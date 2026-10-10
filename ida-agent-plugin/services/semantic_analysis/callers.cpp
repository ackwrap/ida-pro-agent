#include "callers.hpp"
#include "address.hpp"
#include <algorithm>
#include <map>
#include <set>
#include <stdexcept>

namespace ida_agent::services::semantic
{
using Json = nlohmann::json;
bool ValidCallersRequest(const CallersRequest &r)
{
  return r.argument_index <= 255 && r.max_depth <= 5 && r.max_contexts >= 1 && r.max_contexts <= 64
      && r.max_callers >= 1 && r.max_callers <= 32 && r.max_nodes >= 1 && r.max_nodes <= 4000
      && r.max_work >= 1 && r.max_work <= 1000000;
}
CallersRequest ParseCallersRequest(const Json &p)
{
  if (!p.is_object() || !p.contains("callAddress") || !p["callAddress"].is_string() || !p.contains("argumentIndex"))
    throw std::invalid_argument("callAddress and argumentIndex are required");
  CallersRequest r;
  r.call_address = rpc::ParseAddress(p["callAddress"].get<std::string>());
  std::map<std::string, std::uint32_t *> fields{{"argumentIndex", &r.argument_index}, {"maxDepth", &r.max_depth},
      {"maxContexts", &r.max_contexts}, {"maxCallers", &r.max_callers}, {"maxNodes", &r.max_nodes}, {"maxWork", &r.max_work}};
  for (auto it = p.begin(); it != p.end(); ++it)
  {
    if (it.key() == "callAddress") continue;
    auto field = fields.find(it.key());
    if (field == fields.end() || !it->is_number_integer()
        || (!it->is_number_unsigned() && it->get<std::int64_t>() < 0) || it->get<std::uint64_t>() > 1000000)
      throw std::invalid_argument("invalid caller trace parameter");
    *field->second = it->get<std::uint32_t>();
  }
  if (!ValidCallersRequest(r)) throw std::invalid_argument("caller trace bound is out of range");
  return r;
}
namespace
{
struct Stop {};
class Tracer
{
public:
  Tracer(const CallersRequest &r, const CallersProvider &p) : r(r), p(p) {}
  QueryResult Run()
  {
    try { Visit(r.call_address, r.argument_index, 0, {}, -1, -1, 0, ""); }
    catch (const Stop &) { truncated = true; Limit("work_budget"); }
    if (root_error != QueryStatus::Success) return {root_error, {}};
    Json out{{"callAddress", Hex(r.call_address)}, {"argumentIndex", r.argument_index},
        {"model", "microcode_caller_contexts"}, {"scope", "known_direct_callers"},
        {"status", partial || truncated || !limitations.empty() ? "partial" : "complete"},
        {"contexts", contexts}, {"links", links}, {"boundaries", boundaries},
        {"limitations", limitations}, {"truncated", truncated}, {"visitedWork", work}, {"totalNodes", nodes}};
    if (out.dump().size() > 256 * 1024) return {QueryStatus::OutputLimit, {}};
    return {QueryStatus::Success, std::move(out)};
  }
private:
  const CallersRequest &r;
  const CallersProvider &p;
  Json contexts = Json::array(), links = Json::array(), boundaries = Json::array();
  std::vector<std::string> limitations;
  std::uint32_t work = 0, nodes = 0, attempts = 0;
  bool truncated = false, partial = false;
  QueryStatus root_error = QueryStatus::Success;
  void Spend(std::uint32_t count = 1)
  {
    if (count > r.max_work - work) { work = r.max_work; throw Stop{}; }
    work += count;
  }
  void Tick() { if (work == r.max_work) throw Stop{}; Spend(); }
  void Limit(const std::string &reason)
  {
    if (std::find(limitations.begin(), limitations.end(), reason) == limitations.end()) limitations.push_back(reason);
  }
  void Boundary(int context, int parameter, std::optional<std::uint64_t> call, const char *reason, bool budget = false)
  {
    partial = true;
    truncated = truncated || budget;
    if (boundaries.size() >= 512) { truncated = true; Limit("boundary_budget"); return; }
    boundaries.push_back({{"context", context}, {"parameterNode", parameter < 0 ? Json(nullptr) : Json(parameter)},
        {"callAddress", call ? Json(Hex(*call)) : Json(nullptr)}, {"reason", reason}});
  }
  std::vector<int> Parameters(const Json &trace)
  {
    std::vector<int> result;
    if (trace["root"].is_null()) return result;
    std::map<int, std::vector<int>> edges;
    for (const auto &e : trace["edges"]) { Tick(); edges[e["from"].get<int>()].push_back(e["to"].get<int>()); }
    std::vector<int> pending{trace["root"].get<int>()};
    std::set<int> seen;
    while (!pending.empty())
    {
      Tick();
      int id = pending.back(); pending.pop_back();
      if (!seen.insert(id).second) continue;
      if (trace["nodes"][id]["kind"] == "parameter") result.push_back(id);
      for (int next : edges[id]) pending.push_back(next);
    }
    std::sort(result.begin(), result.end());
    return result;
  }
  void Visit(std::uint64_t call, std::uint32_t argument, std::uint32_t depth,
      std::set<std::uint64_t> ancestors, int parent, int parameter, std::uint64_t callee, const std::string &signature)
  {
    Tick();
    if (attempts >= r.max_contexts || nodes >= r.max_nodes)
    {
      Boundary(parent, parameter, call, attempts >= r.max_contexts ? "context_budget" : "node_budget", true);
      return;
    }
    if (work == r.max_work) throw Stop{};
    ++attempts; // Failed or recursive analyses must also consume the SDK-call budget.
    auto loaded = p.load(call, (std::min)(r.max_work - work, std::uint32_t(100000)));
    Spend(loaded.work);
    if (loaded.status != QueryStatus::Success || !loaded.snapshot)
    {
      if (parent < 0) root_error = loaded.status == QueryStatus::Success ? QueryStatus::DecompileFailed : loaded.status;
      else Boundary(parent, parameter, call, loaded.status == QueryStatus::OutputLimit ? "extraction_budget" : "caller_analysis_unavailable", loaded.status == QueryStatus::OutputLimit);
      return;
    }
    const auto &s = *loaded.snapshot;
    if (ancestors.count(s.entry_address)) { Boundary(parent, parameter, call, "recursive_call"); return; }
    if (parent >= 0)
    {
      const Instruction *target = nullptr;
      for (const auto &b : s.blocks) for (const auto &i : b.instructions)
      {
        Tick();
        if (i.call && i.address == call) { if (target) { Boundary(parent, parameter, call, "ambiguous_call"); return; } target = &i; }
      }
      if (!target || target->callee != callee || signature.empty() || target->signature != signature)
      { Boundary(parent, parameter, call, "prototype_mismatch"); return; }
    }
    if (work == r.max_work) throw Stop{};
    Request local;
    local.call_address = call; local.argument_index = argument;
    local.max_nodes = (std::min)(r.max_nodes - nodes, std::uint32_t(1000));
    local.max_work = (std::min)(r.max_work - work, std::uint32_t(100000));
    Json trace;
    try { trace = Analyze(s, local, false); }
    catch (const std::invalid_argument &) { if (parent < 0) root_error = QueryStatus::InvalidArgument; else Boundary(parent, parameter, call, "argument_mapping_unavailable"); return; }
    catch (const std::out_of_range &) { if (parent < 0) root_error = QueryStatus::NotFound; else Boundary(parent, parameter, call, "call_not_recovered"); return; }
    Spend(trace["visitedStates"].get<std::uint32_t>());
    nodes += static_cast<std::uint32_t>(trace["nodes"].size());
    partial = partial || trace["status"] == "partial";
    truncated = truncated || trace["truncated"].get<bool>();
    int id = static_cast<int>(contexts.size());
    contexts.push_back({{"id", id}, {"depth", depth}, {"trace", trace}});
    if (parent >= 0) links.push_back({{"fromContext", parent}, {"parameterNode", parameter}, {"toContext", id}});
    ancestors.insert(s.entry_address);
    auto parameters = Parameters(trace);
    if (parameters.empty()) return;
    Limit("caller_set_not_proven_complete");
    for (int node : parameters)
    {
      Tick();
      if (depth >= r.max_depth) { Boundary(id, node, std::nullopt, "depth_budget", true); continue; }
      if (s.signature.empty()) { Boundary(id, node, std::nullopt, "parameter_abi_unavailable"); continue; }
      if (work == r.max_work) throw Stop{};
      auto callers = p.callers(s.entry_address, r.max_callers, r.max_work - work);
      Spend(callers.work);
      if (callers.truncated) Boundary(id, node, std::nullopt, "caller_budget", true);
      if (callers.unsupported) Boundary(id, node, std::nullopt, "non_call_reference");
      if (callers.addresses.empty()) Boundary(id, node, std::nullopt, "no_known_callers");
      const auto index = static_cast<std::uint32_t>(std::stoul(trace["nodes"][node]["value"].get<std::string>()));
      for (auto address : callers.addresses) Visit(address, index, depth + 1, ancestors, id, node, s.entry_address, s.signature);
    }
  }
};
}
QueryResult TraceCallers(const CallersRequest &r, const CallersProvider &p)
{
  if (!ValidCallersRequest(r)) return {QueryStatus::InvalidArgument, {}};
  return Tracer(r, p).Run();
}
}
