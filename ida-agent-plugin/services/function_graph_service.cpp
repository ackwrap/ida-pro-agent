#include "function_service.hpp"

#include "address.hpp"

#include <ida.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <xref.hpp>

#include <algorithm>
#include <deque>
#include <map>
#include <set>
#include <stdexcept>
#include <tuple>

namespace ida_agent::services
{
namespace
{

constexpr std::size_t MaxCollectedCallers = 10000;
constexpr std::size_t MaxCallSitesPerCaller = 256;
constexpr std::size_t MaxFunctionNameBytes = 1024;

std::string FunctionName(ea_t address)
{
  qstring value;
  if ( get_func_name(&value, address) <= 0 || value.empty() )
    return rpc::FormatAddress(address);
  std::string result(value.c_str(), value.length());
  if ( result.size() > MaxFunctionNameBytes || !is_valid_utf8(result.c_str()) )
    throw std::range_error("function name exceeds the output limit");
  return result;
}

FunctionAnalysisStatus ResolveEntry(std::uint64_t address, ea_t *entry)
{
  const ea_t requested = static_cast<ea_t>(address);
  if ( static_cast<std::uint64_t>(requested) != address
    || requested == BADADDR || !is_mapped(requested) )
  {
    return FunctionAnalysisStatus::InvalidAddress;
  }
  *entry = get_func_start(requested);
  return *entry == BADADDR
      ? FunctionAnalysisStatus::NotFound
      : FunctionAnalysisStatus::Success;
}

void SetContinuation(
    const FunctionPageQuery &query,
    std::size_t returned,
    bool has_more,
    std::optional<std::uint32_t> *next)
{
  if ( has_more )
    *next = query.offset + static_cast<std::uint32_t>(returned);
}

} // namespace

FunctionCallersOutcome FunctionService::Callers(const FunctionPageQuery &query) const
{
  ea_t entry = BADADDR;
  const FunctionAnalysisStatus status = ResolveEntry(query.address, &entry);
  if ( status != FunctionAnalysisStatus::Success )
    return {status, std::nullopt};

  std::map<std::uint64_t, FunctionCaller> collected;
  xrefblk_t xref;
  for ( bool found = xref.first_to(entry, XREF_FAR); found; found = xref.next_to() )
  {
    if ( !xref.iscode || (xref.type != fl_CF && xref.type != fl_CN) )
      continue;
    const ea_t caller_entry = get_func_start(xref.from);
    if ( caller_entry == BADADDR )
      continue;
    std::string caller_name;
    try { caller_name = FunctionName(caller_entry); }
    catch ( const std::range_error & )
    {
      return {FunctionAnalysisStatus::OutputLimit, std::nullopt};
    }
    auto [current, inserted] = collected.emplace(
        caller_entry,
        FunctionCaller{caller_entry, std::move(caller_name), {}});
    if ( inserted && collected.size() > MaxCollectedCallers )
      return {FunctionAnalysisStatus::OutputLimit, std::nullopt};
    auto &sites = current->second.call_sites;
    if ( sites.size() == MaxCallSitesPerCaller )
      return {FunctionAnalysisStatus::OutputLimit, std::nullopt};
    if ( std::find(sites.begin(), sites.end(), xref.from) == sites.end() )
      sites.push_back(xref.from);
  }

  FunctionCallersResult result{entry};
  auto current = collected.begin();
  std::advance(current, (std::min)(static_cast<std::size_t>(query.offset), collected.size()));
  for ( std::uint32_t count = 0;
        count < query.limit && current != collected.end();
        ++count, ++current )
  {
    std::sort(current->second.call_sites.begin(), current->second.call_sites.end());
    result.items.push_back(current->second);
  }
  result.has_more = current != collected.end();
  SetContinuation(query, result.items.size(), result.has_more, &result.next_offset);
  return {FunctionAnalysisStatus::Success, std::move(result)};
}

FunctionCallGraphOutcome FunctionService::CallGraph(const CallGraphQuery &query) const
{
  if ( query.roots.empty() )
    return {FunctionAnalysisStatus::NotFound, std::nullopt};

  struct Pending
  {
    std::uint64_t address;
    std::uint32_t depth;
  };
  std::deque<Pending> pending;
  std::map<std::uint64_t, std::uint32_t> depths;
  for ( const std::uint64_t root : query.roots )
  {
    ea_t entry = BADADDR;
    const FunctionAnalysisStatus status = ResolveEntry(root, &entry);
    if ( status != FunctionAnalysisStatus::Success )
      return {status, std::nullopt};
    if ( depths.emplace(entry, 0).second )
      pending.push_back({entry, 0});
  }

  FunctionCallGraphResult result;
  std::set<std::pair<std::uint64_t, std::uint64_t>> edges;
  while ( !pending.empty() )
  {
    const Pending current = pending.front();
    pending.pop_front();
    if ( result.nodes.size() == query.max_nodes )
    {
      result.truncated = true;
      break;
    }
    std::string node_name;
    try { node_name = FunctionName(current.address); }
    catch ( const std::range_error & )
    {
      return {FunctionAnalysisStatus::OutputLimit, std::nullopt};
    }
    result.nodes.push_back({current.address, std::move(node_name), current.depth});
    if ( current.depth == query.max_depth )
      continue;

    std::vector<std::pair<std::uint64_t, std::uint64_t>> adjacent;
    if ( query.direction != CallGraphDirection::Callers )
    {
      const auto outcome = Callees({current.address, 0, query.per_function});
      if ( outcome.status != FunctionAnalysisStatus::Success || !outcome.result )
        return {outcome.status, std::nullopt};
      result.truncated = result.truncated || outcome.result->has_more;
      for ( const FunctionCallee &callee : outcome.result->items )
      {
        if ( callee.internal )
          adjacent.emplace_back(current.address, callee.address);
      }
    }
    if ( query.direction != CallGraphDirection::Callees )
    {
      const auto outcome = Callers({current.address, 0, query.per_function});
      if ( outcome.status != FunctionAnalysisStatus::Success || !outcome.result )
        return {outcome.status, std::nullopt};
      result.truncated = result.truncated || outcome.result->has_more;
      for ( const FunctionCaller &caller : outcome.result->items )
        adjacent.emplace_back(caller.address, current.address);
    }
    std::sort(adjacent.begin(), adjacent.end());
    adjacent.erase(std::unique(adjacent.begin(), adjacent.end()), adjacent.end());
    for ( const auto &edge : adjacent )
    {
      if ( edges.size() == query.max_edges )
      {
        result.truncated = true;
        break;
      }
      if ( !edges.insert(edge).second )
        continue;
      const std::uint64_t neighbor = edge.first == current.address ? edge.second : edge.first;
      if ( depths.emplace(neighbor, current.depth + 1).second )
        pending.push_back({neighbor, current.depth + 1});
    }
  }
  std::sort(result.nodes.begin(), result.nodes.end(), [](const auto &left, const auto &right)
  {
    return std::tie(left.depth, left.address) < std::tie(right.depth, right.address);
  });
  for ( const auto &edge : edges )
    result.edges.push_back({edge.first, edge.second});
  return {FunctionAnalysisStatus::Success, std::move(result)};
}

nlohmann::json ToJson(const FunctionCallersResult &result)
{
  nlohmann::json items = nlohmann::json::array();
  for ( const FunctionCaller &caller : result.items )
  {
    nlohmann::json sites = nlohmann::json::array();
    for ( std::uint64_t site : caller.call_sites )
      sites.push_back(rpc::FormatAddress(site));
    items.push_back({
        {"address", rpc::FormatAddress(caller.address)},
        {"name", caller.name},
        {"callSites", std::move(sites)},
    });
  }
  return {
      {"entryAddress", rpc::FormatAddress(result.entry_address)},
      {"items", std::move(items)},
      {"nextOffset", result.next_offset ? nlohmann::json(*result.next_offset) : nlohmann::json(nullptr)},
      {"hasMore", result.has_more},
  };
}

nlohmann::json ToJson(const FunctionCallGraphResult &result)
{
  nlohmann::json nodes = nlohmann::json::array();
  for ( const CallGraphNode &node : result.nodes )
  {
    nodes.push_back({
        {"address", rpc::FormatAddress(node.address)},
        {"name", node.name},
        {"depth", node.depth},
    });
  }
  nlohmann::json edges = nlohmann::json::array();
  for ( const CallGraphEdge &edge : result.edges )
  {
    edges.push_back({
        {"from", rpc::FormatAddress(edge.from)},
        {"to", rpc::FormatAddress(edge.to)},
    });
  }
  return {{"nodes", std::move(nodes)}, {"edges", std::move(edges)}, {"truncated", result.truncated}};
}

} // namespace ida_agent::services
