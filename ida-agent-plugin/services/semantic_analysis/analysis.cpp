#include "model.hpp"

#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <tuple>

namespace ida_agent::services::semantic
{
using Json = nlohmann::json;

std::string Hex(std::uint64_t value)
{
  std::ostringstream stream;
  stream << "0x" << std::hex << value;
  return stream.str();
}
bool Location::operator==(const Location &other) const
{ return space == other.space && offset == other.offset && bytes == other.bytes; }
bool Location::Overlaps(const Location &other) const
{
  if (space != other.space || !bytes || !other.bytes) return false;
  return offset <= other.offset ? other.offset - offset < bytes : offset - other.offset < other.bytes;
}
std::string Location::Key() const
{ return space + ":" + Hex(offset) + ":" + std::to_string(bytes); }
bool ValidRequest(const Request &r)
{
  return r.argument_index <= 255 && r.max_nodes >= 1 && r.max_nodes <= 1000
      && r.max_work >= 1 && r.max_work <= 100000 && r.max_guards >= 1 && r.max_guards <= 128;
}

namespace
{
struct Stop {};
using Point = std::pair<int, int>;

class Analysis
{
public:
  Analysis(const Snapshot &s, const Request &r) : s(s), r(r), predecessors(s.blocks.size())
  {
    for (int b = 0; b < static_cast<int>(s.blocks.size()); ++b)
      for (int next : s.blocks[b].successors)
      {
        if (next < 0 || next >= static_cast<int>(s.blocks.size()))
          throw std::invalid_argument("invalid CFG edge");
        predecessors[next].push_back(b);
      }
    for (const auto &reason : s.limitations) Limit(reason);
    if (!s.cfg_complete) Limit("unsupported_control_flow");
  }

  Json Run(bool include_guards)
  {
    const Instruction *call = nullptr;
    for (int b = 0; b < static_cast<int>(s.blocks.size()); ++b)
      for (int i = 0; i < static_cast<int>(s.blocks[b].instructions.size()); ++i)
      {
        const auto &candidate = s.blocks[b].instructions[i];
        if (candidate.call && candidate.address == r.call_address)
        {
          if (call) throw std::invalid_argument("ambiguous call address");
          call = &candidate;
          target = {b, i};
        }
      }
    if (!call) throw std::out_of_range("call address was not recovered");
    if (r.argument_index >= call->arguments.size()) throw std::invalid_argument("argument index is out of range");
    Json root = nullptr;
    try
    {
      root = Trace(call->arguments[r.argument_index], target, 0);
      if (include_guards) Guards(root.get<int>());
    }
    catch (const Stop &) { truncated = true; }
    return {
        {"entryAddress", Hex(s.entry_address)}, {"callAddress", Hex(r.call_address)},
        {"argumentIndex", r.argument_index}, {"argumentCount", call->arguments.size()},
        {"argumentType", r.argument_index < call->argument_types.size() ? call->argument_types[r.argument_index] : ""},
        {"model", "microcode_reaching_definitions"}, {"maturity", "MMAT_CALLS"},
        {"scope", "function"}, {"status", limitations.empty() && !truncated ? "complete" : "partial"},
        {"cfgComplete", s.cfg_complete}, {"root", root}, {"nodes", nodes}, {"edges", edges},
        {"guards", guards}, {"limitations", limitations}, {"truncated", truncated}, {"visitedStates", work}};
  }

private:
  const Snapshot &s;
  const Request &r;
  std::vector<std::vector<int>> predecessors;
  Point target{};
  Json nodes = Json::array(), edges = Json::array(), guards = Json::array();
  std::vector<std::string> limitations;
  std::map<std::string, int> interned;
  std::set<std::pair<int, int>> edge_set;
  std::map<int, std::vector<int>> inputs_by_node;
  std::map<std::tuple<int, int, std::string>, int> definitions;
  std::set<std::tuple<int, int, std::string>> active;
  std::uint32_t work = 0;
  bool truncated = false;

  void Limit(const std::string &reason)
  {
    if (std::find(limitations.begin(), limitations.end(), reason) == limitations.end())
      limitations.push_back(reason);
  }
  void Tick()
  {
    if (work >= r.max_work) { Limit("work_budget"); throw Stop{}; }
    ++work;
  }
  std::optional<std::uint64_t> Address(Point p) const
  {
    if (p.first < 0 || p.second < 0 || p.second >= static_cast<int>(s.blocks[p.first].instructions.size()))
      return std::nullopt;
    return s.blocks[p.first].instructions[p.second].address;
  }
  int Node(const std::string &key, const std::string &kind, const std::string &op,
           std::uint32_t bits, Point p, const std::string &literal = "")
  {
    if (auto it = interned.find(key); it != interned.end()) return it->second;
    if (nodes.size() >= r.max_nodes) { Limit("node_budget"); throw Stop{}; }
    int id = static_cast<int>(nodes.size());
    auto address = Address(p);
    nodes.push_back({{"id", id}, {"kind", kind}, {"operation", op}, {"bits", bits},
        {"address", address ? Json(Hex(*address)) : Json(nullptr)}, {"value", literal}});
    interned[key] = id;
    return id;
  }
  void Edge(int from, int to)
  {
    if (from == to) return;
    if (edge_set.count({from, to})) return;
    if (edges.size() >= 2000) { Limit("edge_budget"); throw Stop{}; }
    edge_set.insert({from, to});
    inputs_by_node[from].push_back(to);
    edges.push_back({{"from", from}, {"to", to}});
  }
  int Unknown(const std::string &reason, const Location &location, Point p)
  {
    Limit(reason);
    return Node(reason + ":" + location.Key() + ":" + std::to_string(p.first) + ":" + std::to_string(p.second),
        "unknown", reason, location.bytes * 8, p, location.Key());
  }
  int Trace(const Value &v, Point p, int depth)
  {
    Tick();
    if (depth > 64) { Limit("depth_budget"); throw Stop{}; }
    if (v.kind == "location") return Reaching(v.location, p, depth + 1);
    std::vector<int> inputs;
    for (const auto &input : v.inputs) inputs.push_back(Trace(input, p, depth + 1));
    if (v.operation == "mov" && inputs.size() == 1 && nodes[inputs[0]]["bits"] == v.bits)
      return inputs[0];
    std::string key = v.kind + ":" + v.operation + ":" + std::to_string(v.bits) + ":" + v.literal;
    for (int input : inputs) key += ":" + std::to_string(input);
    if (v.kind == "unknown" || v.kind == "memory_read" || v.kind == "call_return")
    {
      key += ":" + std::to_string(p.first) + ":" + std::to_string(p.second);
      Limit(v.kind == "unknown" ? "unsupported_operation" : v.kind + "_boundary");
    }
    int node = Node(key, v.kind, v.operation, v.bits, v.synthetic ? Point{-1, -1} : p, v.literal);
    for (int input : inputs) Edge(node, input);
    return node;
  }
  int Reaching(const Location &loc, Point p, int depth)
  {
    Tick();
    if (depth > 64) return Unknown("loop_or_depth_boundary", loc, p);
    const auto state = std::make_tuple(p.first, p.second, loc.Key());
    if (active.count(state)) return Unknown("loop_boundary", loc, p);
    if (auto it = definitions.find(state); it != definitions.end()) return it->second;
    active.insert(state);
    const int result = Find(loc, p, depth);
    active.erase(state);
    definitions[state] = result;
    return result;
  }
  int Find(const Location &loc, Point p, int depth)
  {
    for (int i = p.second - 1; i >= 0; --i)
    {
      Tick();
      const auto &ins = s.blocks[p.first].instructions[i];
      Point here{p.first, i};
      if (ins.destination && ins.destination->Overlaps(loc))
      {
        if (!(*ins.destination == loc))
        {
          // Same-start narrower reads select the low bytes on the normalized
          // little-endian locations. Partial overwrites remain unknown.
          if (ins.destination->offset == loc.offset && ins.destination->bytes > loc.bytes && s.little_endian)
          {
            Value low; low.kind = "operation"; low.operation = "low";
            low.synthetic = true;
            low.bits = loc.bytes * 8; low.inputs = {ins.value};
            return Trace(low, here, depth + 1);
          }
          return Unknown("partial_write", loc, here);
        }
        return Trace(ins.value, here, depth + 1);
      }
      for (const auto &clobber : ins.clobbers)
      {
        Tick();
        if (clobber.Overlaps(loc)) return Unknown("call_clobber", loc, here);
      }
      if (loc.space == "register" && ins.register_barrier) return Unknown("unknown_register_effect", loc, here);
      if (loc.space != "register" && ins.memory_barrier) return Unknown("memory_alias_or_call", loc, here);
    }
    if (predecessors[p.first].empty())
    {
      if (p.first != 0) return Unknown("unreachable_definition", loc, p);
      for (std::size_t i = 0; i < s.parameters.size(); ++i)
      {
        const auto &param = s.parameters[i];
        if (param.space != loc.space || param.offset != loc.offset || param.bytes < loc.bytes) continue;
        if (param.bytes != loc.bytes && !s.little_endian) continue;
        int source = Node("parameter:" + param.Key(), "parameter", "", param.bytes * 8, {-1, -1}, std::to_string(i));
        if (param.bytes == loc.bytes) return source;
        const auto bits = loc.bytes * 8;
        int low = Node("operation:low:" + std::to_string(bits) + "::" + std::to_string(source), "operation", "low", bits, {-1, -1});
        Edge(low, source);
        return low;
      }
      if (loc.space == "global") return Unknown("global_memory_boundary", loc, p);
      Limit("unclassified_entry_value");
      return Node("entry:" + loc.Key(), "entry_value", "", loc.bytes * 8, {-1, -1}, loc.Key());
    }
    std::set<int> sources;
    for (int pred : predecessors[p.first])
      sources.insert(Reaching(loc, {pred, static_cast<int>(s.blocks[pred].instructions.size())}, depth + 1));
    if (sources.size() == 1) return *sources.begin();
    std::string key = "merge:" + loc.Key();
    for (int source : sources) key += ":" + std::to_string(source);
    int merge = Node(key, "merge", "reaching_definitions", loc.bytes * 8, p);
    for (int source : sources) Edge(merge, source);
    return merge;
  }
  // Program-point reachability stops at the target call, so conditions after it
  // are not incorrectly treated as protecting that invocation in a loop.
  bool Reach(Point from, Point to, std::pair<int, int> removed = {-1, -1})
  {
    std::vector<Point> pending{from};
    std::set<Point> seen;
    while (!pending.empty())
    {
      Tick();
      auto current = pending.back(); pending.pop_back();
      if (current == to) return true;
      if (current == target || !seen.insert(current).second) continue;
      const auto &block = s.blocks[current.first];
      if (current.second < static_cast<int>(block.instructions.size()))
        pending.emplace_back(current.first, current.second + 1);
      else
        for (int next : block.successors)
          if (removed != std::make_pair(current.first, next)) pending.emplace_back(next, 0);
    }
    return false;
  }
  std::set<int> Dependencies(int root)
  {
    std::set<int> found;
    std::vector<int> pending{root};
    while (!pending.empty())
    {
      Tick();
      int node = pending.back(); pending.pop_back();
      if (!found.insert(node).second) continue;
      for (int input : inputs_by_node[node]) { Tick(); pending.push_back(input); }
    }
    return found;
  }
  std::string Relation(int checked, int root)
  {
    auto a = Dependencies(checked), b = Dependencies(root);
    auto uncertain = [this](const std::set<int> &deps) {
      for (int id : deps)
      {
        const std::string kind = nodes[id]["kind"];
        if (kind == "unknown" || kind == "merge" || kind == "memory_read") return true;
      }
      return false;
    };
    if (checked == root) return uncertain(a) ? "unknown" : "same_value";
    for (int id : a)
      if (b.count(id) && nodes[id]["kind"] != "constant" && nodes[id]["kind"] != "address")
        return uncertain(a) || uncertain(b) ? "unknown" : "derived_value";
    return uncertain(a) || uncertain(b) ? "unknown" : "unrelated";
  }
  void Guards(int root)
  {
    if (!Reach({0, 0}, target)) { Limit("call_unreachable_in_cfg"); return; }
    for (int b = 0; b < static_cast<int>(s.blocks.size()); ++b)
      for (int i = 0; i < static_cast<int>(s.blocks[b].instructions.size()); ++i)
      {
        const auto &ins = s.blocks[b].instructions[i];
        if (!ins.condition || !Reach({0, 0}, {b, i}) || !Reach({b, i + 1}, target)) continue;
        if (guards.size() >= r.max_guards) { Limit("guard_budget"); throw Stop{}; }
        std::vector<int> operands;
        for (const auto &v : ins.condition->inputs) operands.push_back(Trace(v, {b, i}, 0));
        std::string relation = "unrelated";
        for (int operand : operands)
        {
          auto candidate = Relation(operand, root);
          if (candidate == "same_value") { relation = candidate; break; }
          if (candidate == "unknown" || (candidate == "derived_value" && relation == "unrelated")) relation = candidate;
        }
        // Include unrelated conditions too: a comparison may be on an older
        // definition that was overwritten before the call.
        std::string required = "unknown";
        if (s.cfg_complete && ins.true_block >= 0 && ins.false_block >= 0 && ins.true_block != ins.false_block)
        {
          const bool without_true = Reach({0, 0}, target, {b, ins.true_block});
          const bool without_false = Reach({0, 0}, target, {b, ins.false_block});
          required = !without_true ? "true" : !without_false ? "false" : "neither";
        }
        guards.push_back({{"address", ins.address ? Json(Hex(*ins.address)) : Json(nullptr)},
            {"operation", ins.condition->operation}, {"bits", ins.condition->bits},
            {"operands", operands}, {"requiredBranch", required}, {"valueRelation", relation}});
      }
  }
};
}

Json Analyze(const Snapshot &snapshot, const Request &request, bool guards)
{
  if (!ValidRequest(request) || snapshot.blocks.empty()) throw std::invalid_argument("invalid analysis request");
  return Analysis(snapshot, request).Run(guards);
}
}
