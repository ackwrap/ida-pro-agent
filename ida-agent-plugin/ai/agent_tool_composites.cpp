#include "ai/agent_tool_composites.hpp"

#include "ai/agent_tool_registry_internal.hpp"
#include "bridge/composite_analysis.hpp"
#include "rpc/address.hpp"
#include "services/database_service.hpp"
#include "services/decompiler_service.hpp"
#include "services/function_service.hpp"
#include "services/string_service.hpp"
#include "services/symbol_service.hpp"
#include "services/xref_service.hpp"

#include <algorithm>
#include <deque>
#include <map>
#include <set>
#include <tuple>
#include <utility>

namespace ida_agent::ai::composite
{
namespace
{
using Json = nlohmann::json;

Json Bounded(Json result, const char *message)
{
  if ( result.dump().size() > MaxAgentToolResultBytes )
    throw AgentToolSafeError(message);
  return result;
}

Json Unwrap(bridge::Dispatcher::MethodResult result, const char *message)
{
  if ( auto *value = std::get_if<Json>(&result) ) return std::move(*value);
  throw AgentToolSafeError(message);
}

} // namespace

Json DatabaseSurvey(
    const services::DatabaseService &database,
    const services::FunctionService &functions,
    const services::StringService &strings,
    const services::SymbolService &symbols,
    const AgentDatabaseSurveyArguments &arguments)
{
  const std::uint32_t section = arguments.mode == "minimal"
      ? (std::min)(5U, (std::max)(1U, arguments.budget / 3U))
      : (std::max)(1U, arguments.budget / 3U);
  const auto function_inventory = functions.SearchByName("", section, std::nullopt);
  const auto string_inventory = strings.Search("", 4, section, std::nullopt);
  const auto import_inventory = symbols.Imports("", "", section, std::nullopt);
  if ( !function_inventory.result || !string_inventory.result || !import_inventory.result )
    throw AgentToolSafeError("Database survey inventory is unavailable.");

  std::map<std::string, std::uint32_t> categories;
  for ( const auto &item : import_inventory.result->items ) ++categories[item.module];
  Json category_items = Json::array();
  for ( const auto &[module, count] : categories )
    category_items.push_back({{"module", module}, {"sampledCount", count}});

  Json call_summary{{"roots", 0}, {"nodes", 0}, {"edges", 0}, {"truncated", false}};
  if ( !function_inventory.result->items.empty() )
  {
    std::vector<std::uint64_t> roots;
    const std::size_t root_count = (std::min)(
        function_inventory.result->items.size(),
        static_cast<std::size_t>(arguments.mode == "minimal" ? 2 : 8));
    for ( std::size_t index = 0; index < root_count; ++index )
      roots.push_back(function_inventory.result->items[index].entry_address);
    const auto graph = functions.CallGraph({
        roots, services::CallGraphDirection::Both, 1, section,
        (std::min)(100U, section * 2U), section});
    if ( graph.result )
    {
      call_summary = {
          {"roots", roots.size()}, {"nodes", graph.result->nodes.size()},
          {"edges", graph.result->edges.size()}, {"truncated", graph.result->truncated}};
    }
    else if ( graph.status == services::FunctionAnalysisStatus::OutputLimit )
      call_summary["truncated"] = true;
  }

  const auto metadata = database.Info();
  const bool truncated = function_inventory.result->has_more
      || string_inventory.result->has_more || import_inventory.result->has_more
      || call_summary["truncated"].get<bool>();
  Json result{
      {"mode", arguments.mode}, {"metadata", services::ToJson(metadata)},
      {"statistics", {
          {"sampledFunctions", function_inventory.result->items.size()},
          {"sampledStrings", string_inventory.result->items.size()},
          {"sampledImports", import_inventory.result->items.size()},
          {"functionsTruncated", function_inventory.result->has_more},
          {"stringsTruncated", string_inventory.result->has_more},
          {"importsTruncated", import_inventory.result->has_more}}},
      {"importCategories", std::move(category_items)}, {"callGraph", std::move(call_summary)},
      {"metrics", {
          {"segments", metadata.segments.total},
          {"functions", {{"sampled", function_inventory.result->items.size()},
              {"hasMore", function_inventory.result->has_more}}},
          {"strings", {{"sampled", string_inventory.result->items.size()},
              {"hasMore", string_inventory.result->has_more}}},
          {"imports", {{"sampled", import_inventory.result->items.size()},
              {"hasMore", import_inventory.result->has_more}}}}},
      {"truncated", truncated},
      {"budget", {{"requestedItems", arguments.budget}, {"perSection", section}}}};
  if ( arguments.mode == "full" )
  {
    result["functions"] = services::ToJson(*function_inventory.result);
    result["strings"] = services::ToJson(*string_inventory.result);
    result["functions"].erase("nextCursor");
    result["strings"].erase("nextCursor");
  }
  else
  {
    result["functions"] = {{"sampledCount", function_inventory.result->items.size()},
        {"hasMore", function_inventory.result->has_more}};
    result["strings"] = {{"sampledCount", string_inventory.result->items.size()},
        {"hasMore", string_inventory.result->has_more}};
  }
  return Bounded(std::move(result), "Database survey exceeded the Agent output limit.");
}

Json FunctionProfile(
    const services::FunctionService &functions,
    const AgentFunctionProfileArguments &arguments)
{
  const auto page = functions.SearchByName(arguments.name, arguments.limit, std::nullopt);
  if ( page.status == services::FunctionSearchStatus::OutputLimit )
    throw AgentToolSafeError("Function profile inventory exceeded service limits.");
  if ( !page.result ) throw AgentToolSafeError("Function profile inventory is unavailable.");
  Json items = Json::array();
  std::size_t sampled_instructions = 0;
  for ( const auto &candidate : page.result->items )
  {
    const auto lookup = functions.Get(candidate.entry_address);
    if ( !lookup.info ) continue;
    const auto &info = *lookup.info;
    if ( info.statistics.size_bytes < arguments.minimum_size
        || info.statistics.size_bytes > arguments.maximum_size
        || (arguments.library && info.flags.library != *arguments.library)
        || (arguments.thunk && info.flags.thunk != *arguments.thunk) ) continue;
    Json item{
        {"address", rpc::FormatAddress(info.entry_address)}, {"name", info.name},
        {"metrics", {{"sizeBytes", info.statistics.size_bytes},
            {"instructions", info.statistics.instruction_count},
            {"basicBlocks", info.statistics.basic_block_count},
            {"chunks", info.statistics.chunk_count}}},
        {"flags", {{"library", info.flags.library}, {"thunk", info.flags.thunk}}}};
    if ( arguments.include_prototype )
      item["prototype"] = info.signature ? Json(*info.signature) : Json(nullptr);
    if ( arguments.sample_limit != 0 )
    {
      const auto disassembly = functions.Disassemble(
          {info.entry_address, 0, arguments.sample_limit});
      item["samples"] = disassembly.result
          ? services::ToJson(*disassembly.result)["items"] : Json::array();
      item["samplesTruncated"] = !disassembly.result || disassembly.result->has_more;
      sampled_instructions += item["samples"].size();
    }
    items.push_back(std::move(item));
  }
  const std::size_t matched = items.size();
  return Bounded({
      {"items", std::move(items)}, {"hasMore", page.result->has_more},
      {"metrics", {{"candidates", page.result->items.size()},
          {"matched", matched}, {"sampledInstructions", sampled_instructions}}}},
      "Function profile exceeded the Agent output limit.");
}

Json FunctionExport(
    const services::FunctionService &functions,
    const AgentFunctionExportArguments &arguments)
{
  return Bounded(Unwrap(bridge::composite::ExportFunctions(
      functions, arguments.addresses, arguments.format, arguments.max_bytes),
      "Function export failed."), "Function export exceeded the Agent output limit.");
}

Json FunctionAnalyze(
    const services::FunctionService &functions,
    const services::DecompilerService &decompiler,
    const services::StringService &strings,
    const services::XrefService &xrefs,
    const AgentFunctionAnalyzeArguments &arguments)
{
  const std::set<std::string> sections(arguments.sections.begin(), arguments.sections.end());
  return Bounded(Unwrap(bridge::composite::AnalyzeBatch(
      functions, decompiler, strings, xrefs, arguments.addresses, sections,
      arguments.per_section, arguments.decompile_bytes, MaxAgentToolResultBytes),
      "Function analysis failed."), "Function analysis exceeded the Agent output limit.");
}

Json AnalysisComponent(
    const services::FunctionService &functions,
    const services::StringService &strings,
    const services::SymbolService &symbols,
    const services::XrefService &xrefs,
    const AgentAnalysisComponentArguments &arguments)
{
  const auto graph = functions.CallGraph({
      arguments.roots, services::CallGraphDirection::Both, arguments.max_depth,
      arguments.max_nodes, arguments.max_edges, arguments.per_function});
  if ( graph.status == services::FunctionAnalysisStatus::InvalidAddress )
    throw AgentToolSafeError("Component root address is invalid.");
  if ( graph.status == services::FunctionAnalysisStatus::NotFound )
    throw AgentToolSafeError("Component root function was not found.");
  if ( graph.status == services::FunctionAnalysisStatus::OutputLimit || !graph.result )
    throw AgentToolSafeError("Component graph is unavailable.");
  return Bounded(bridge::composite::BuildComponent(
      functions, strings, symbols, xrefs, *graph.result,
      arguments.per_function, arguments.shared_limit),
      "Component analysis exceeded the Agent output limit.");
}

Json TraceDataFlow(
    const services::FunctionService &functions,
    const services::StringService &strings,
    const services::SymbolService &symbols,
    const services::XrefService &xrefs,
    const AgentTraceDataFlowArguments &arguments)
{
  const auto root_check = xrefs.Query({arguments.address, services::XrefDirection::Incoming,
      services::XrefCategory::All, false, 1, std::nullopt});
  if ( root_check.status == services::XrefQueryStatus::InvalidAddress )
    throw AgentToolSafeError("Trace address is invalid.");
  if ( root_check.status != services::XrefQueryStatus::Success || !root_check.result )
    throw AgentToolSafeError("Trace root validation failed.");

  struct Pending { std::uint64_t address; std::uint32_t depth; };
  std::deque<Pending> pending{{arguments.address, 0}};
  std::set<std::uint64_t> seen{arguments.address};
  std::map<std::tuple<std::uint64_t, std::uint64_t, std::string>, services::XrefInfo>
      collected;
  bool truncated = false;
  while ( !pending.empty() && collected.size() < arguments.max_edges )
  {
    const Pending current = pending.front();
    pending.pop_front();
    if ( current.depth == arguments.max_depth ) continue;
    for ( services::XrefDirection scan : {
              services::XrefDirection::Incoming, services::XrefDirection::Outgoing} )
    {
      if ( collected.size() == arguments.max_edges )
      {
        truncated = true;
        break;
      }
      if ( (arguments.direction == "incoming" && scan != services::XrefDirection::Incoming)
          || (arguments.direction == "outgoing" && scan != services::XrefDirection::Outgoing) )
        continue;
      const std::uint32_t remaining = static_cast<std::uint32_t>((std::min)(
          static_cast<std::size_t>(100), arguments.max_edges - collected.size()));
      const auto outcome = xrefs.Query({current.address, scan,
          services::XrefCategory::All, false, remaining, std::nullopt});
      if ( outcome.status == services::XrefQueryStatus::InvalidAddress )
        throw AgentToolSafeError("Trace encountered an invalid address.");
      if ( outcome.status == services::XrefQueryStatus::OutputLimit )
        throw AgentToolSafeError("Trace cross-reference output exceeded service limits.");
      if ( outcome.status != services::XrefQueryStatus::Success || !outcome.result )
        throw AgentToolSafeError("Trace cross-reference query failed.");
      truncated = truncated || outcome.result->has_more;
      for ( const auto &xref : outcome.result->items )
      {
        if ( collected.size() == arguments.max_edges )
        {
          truncated = true;
          break;
        }
        collected.emplace(std::make_tuple(xref.from, xref.to, xref.type), xref);
        const std::uint64_t next = scan == services::XrefDirection::Incoming
            ? xref.from : xref.to;
        if ( seen.find(next) != seen.end() ) continue;
        if ( seen.size() == arguments.max_nodes )
        {
          truncated = true;
          continue;
        }
        seen.insert(next);
        pending.push_back({next, current.depth + 1});
      }
    }
  }
  truncated = truncated || !pending.empty();
  Json nodes = bridge::composite::BuildTraceNodes(
      functions, strings, symbols, seen,
      (std::min)(100U, arguments.max_nodes), &truncated);
  Json edges = Json::array();
  for ( const auto &[key, xref] : collected )
  {
    static_cast<void>(key);
    edges.push_back({
        {"from", rpc::FormatAddress(xref.from)}, {"to", rpc::FormatAddress(xref.to)},
        {"type", xref.type}, {"code", xref.code}, {"userDefined", xref.user_defined}});
  }
  return Bounded({{"model", "xref_bfs"}, {"nodes", std::move(nodes)},
      {"edges", std::move(edges)}, {"truncated", truncated}},
      "Data-flow trace exceeded the Agent output limit.");
}

} // namespace ida_agent::ai::composite
