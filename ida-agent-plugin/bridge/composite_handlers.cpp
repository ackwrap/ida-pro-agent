#include "composite_handlers.hpp"

#include "composite_analysis.hpp"
#include "ida_executor.hpp"
#include "rpc/address.hpp"
#include "rpc/function_search_cursor.hpp"
#include "rpc/list_cursor.hpp"
#include "services/database_service.hpp"
#include "services/decompiler_service.hpp"
#include "services/function_service.hpp"
#include "services/string_service.hpp"
#include "services/symbol_service.hpp"
#include "services/xref_service.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <deque>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace ida_agent::bridge
{
namespace
{

constexpr std::size_t MaxCompositeResultBytes = 500 * 1024;

Dispatcher::MethodResult Error(
    rpc::ErrorCode code,
    const char *message,
    bool retryable = false)
{
  return rpc::RpcError{code, message, retryable};
}

bool Fields(
    const nlohmann::json &params,
    std::initializer_list<const char *> allowed)
{
  for ( auto field = params.begin(); field != params.end(); ++field )
  {
    bool found = false;
    for ( const char *name : allowed )
      found = found || field.key() == name;
    if ( !found )
      return false;
  }
  return true;
}

std::optional<std::uint32_t> Bound(
    const nlohmann::json &params,
    const char *name,
    std::uint32_t fallback,
    std::uint32_t low,
    std::uint32_t high)
{
  if ( !params.contains(name) )
    return fallback;
  const auto &value = params[name];
  std::uint64_t parsed = 0;
  if ( value.is_number_unsigned() )
  {
    parsed = value.get<std::uint64_t>();
  }
  else if ( value.is_number_integer() )
  {
    const std::int64_t signed_value = value.get<std::int64_t>();
    if ( signed_value < 0 )
      return std::nullopt;
    parsed = static_cast<std::uint64_t>(signed_value);
  }
  else
  {
    return std::nullopt;
  }
  if ( parsed < low || parsed > high )
    return std::nullopt;
  return static_cast<std::uint32_t>(parsed);
}

std::optional<std::vector<std::uint64_t>> Addresses(
    const nlohmann::json &params,
    const char *name,
    std::size_t maximum)
{
  if ( !params.contains(name) || !params[name].is_array()
    || params[name].empty() || params[name].size() > maximum )
  {
    return std::nullopt;
  }
  std::vector<std::uint64_t> result;
  std::set<std::uint64_t> unique;
  for ( const auto &item : params[name] )
  {
    if ( !item.is_string() )
      return std::nullopt;
    try
    {
      const std::uint64_t address = rpc::ParseAddress(item.get<std::string>());
      if ( unique.insert(address).second )
        result.push_back(address);
    }
    catch ( const std::invalid_argument & )
    {
      return std::nullopt;
    }
  }
  return result;
}

std::optional<bool> Boolean(
    const nlohmann::json &params,
    const char *name,
    bool fallback)
{
  if ( !params.contains(name) ) return fallback;
  if ( !params[name].is_boolean() ) return std::nullopt;
  return params[name].get<bool>();
}

std::optional<std::set<std::string>> AnalysisSections(const nlohmann::json &params)
{
  static const std::set<std::string> allowed{
      "overview", "metrics", "prototype", "callers", "callees", "blocks",
      "xrefs", "strings", "constants", "comments", "decompile",
  };
  if ( !params.contains("sections") ) return allowed;
  if ( !params["sections"].is_array() || params["sections"].empty()
    || params["sections"].size() > allowed.size() )
  {
    return std::nullopt;
  }
  std::set<std::string> selected;
  for ( const auto &item : params["sections"] )
  {
    if ( !item.is_string() ) return std::nullopt;
    const std::string section = item.get<std::string>();
    if ( allowed.find(section) == allowed.end() || !selected.insert(section).second )
      return std::nullopt;
  }
  return selected;
}

std::string Lower(std::string value)
{
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character)
  {
    return static_cast<char>(std::tolower(character));
  });
  return value;
}

Dispatcher::MethodResult Budgeted(nlohmann::json result, const char *message)
{
  if ( result.dump().size() > MaxCompositeResultBytes )
    return Error(rpc::ErrorCode::OutputLimit, message);
  return result;
}

template <typename Operation>
Dispatcher::MethodResult Run(
    IdaExecutor &executor,
    const rpc::Request &request,
    Operation operation)
{
  try
  {
    return executor.ReadFor(
        std::chrono::milliseconds(request.timeout_ms),
        std::move(operation));
  }
  catch ( const IdaTimeoutError & )
  {
    return Error(rpc::ErrorCode::Timeout, "IDA request timed out", true);
  }
  catch ( const IdaBusyError & )
  {
    return Error(rpc::ErrorCode::IdaBusy, "IDA is busy", true);
  }
  catch ( const std::exception &error )
  {
    if ( qgetenv("IDA_AGENT_TEST_DIAGNOSTICS", nullptr) )
      msg("[ida-agent-test] composite handler exception: %s\n", error.what());
    throw;
  }
}

} // namespace

Dispatcher::MethodHandlers BuildCompositeHandlers(
    IdaExecutor &executor,
    const services::DatabaseService &database,
    const services::DecompilerService &decompiler,
    const services::FunctionService &functions,
    const services::StringService &strings,
    const services::SymbolService &symbols,
    const services::XrefService &xrefs)
{
  Dispatcher::MethodHandlers handlers;

  handlers.emplace("database.survey", [&executor, &database, &functions, &strings, &symbols](const rpc::Request &request) -> Dispatcher::MethodResult
  {
    if ( !Fields(request.params, {"mode", "budget"}) )
      return Error(rpc::ErrorCode::InvalidArgument, "database.survey contains an unknown parameter");
    std::string mode = "full";
    if ( request.params.contains("mode") )
    {
      if ( !request.params["mode"].is_string() )
        return Error(rpc::ErrorCode::InvalidArgument, "database.survey mode is invalid");
      mode = request.params["mode"].get<std::string>();
    }
    if ( mode != "full" && mode != "minimal" )
      return Error(rpc::ErrorCode::InvalidArgument, "database.survey mode is invalid");
    const auto budget = Bound(request.params, "budget", 60, 3, 100);
    if ( !budget )
      return Error(rpc::ErrorCode::InvalidArgument, "database.survey budget must be from 3 to 100");
    return Run(executor, request, [&database, &functions, &strings, &symbols, mode, budget]() -> Dispatcher::MethodResult
    {
      const std::uint32_t section = mode == "minimal"
          ? (std::min)(5U, (std::max)(1U, *budget / 3U))
          : (std::max)(1U, *budget / 3U);
      const auto function_inventory = functions.SearchByName("", section, std::nullopt);
      const auto string_inventory = strings.Search("", 4, section, std::nullopt);
      const auto import_inventory = symbols.Imports("", "", section, std::nullopt);
      if ( !function_inventory.result || !string_inventory.result || !import_inventory.result )
        return Error(rpc::ErrorCode::OutputLimit, "database.survey inventory is unavailable");

      std::map<std::string, std::uint32_t> categories;
      for ( const auto &item : import_inventory.result->items )
        ++categories[item.module];
      nlohmann::json category_items = nlohmann::json::array();
      for ( const auto &[module, count] : categories )
        category_items.push_back({{"module", module}, {"sampledCount", count}});

      nlohmann::json call_summary{
          {"roots", 0}, {"nodes", 0}, {"edges", 0}, {"truncated", false}};
      if ( !function_inventory.result->items.empty() )
      {
        std::vector<std::uint64_t> roots;
        const std::size_t root_count = (std::min)(
            function_inventory.result->items.size(),
            static_cast<std::size_t>(mode == "minimal" ? 2 : 8));
        for ( std::size_t index = 0; index < root_count; ++index )
          roots.push_back(function_inventory.result->items[index].entry_address);
        const auto graph = functions.CallGraph({
            roots,
            services::CallGraphDirection::Both,
            1,
            section,
            (std::min)(100U, section * 2U),
            section,
        });
        if ( graph.result )
        {
          call_summary = {
              {"roots", roots.size()},
              {"nodes", graph.result->nodes.size()},
              {"edges", graph.result->edges.size()},
              {"truncated", graph.result->truncated},
          };
        }
        else if ( graph.status == services::FunctionAnalysisStatus::OutputLimit )
        {
          call_summary["truncated"] = true;
        }
      }

      const auto metadata = database.Info();
      const bool truncated = function_inventory.result->has_more
          || string_inventory.result->has_more || import_inventory.result->has_more
          || call_summary["truncated"].get<bool>();
      nlohmann::json result{
          {"mode", mode},
          {"metadata", services::ToJson(metadata)},
          {"statistics", {
              {"sampledFunctions", function_inventory.result->items.size()},
              {"sampledStrings", string_inventory.result->items.size()},
              {"sampledImports", import_inventory.result->items.size()},
              {"functionsTruncated", function_inventory.result->has_more},
              {"stringsTruncated", string_inventory.result->has_more},
              {"importsTruncated", import_inventory.result->has_more},
          }},
          {"importCategories", std::move(category_items)},
          {"callGraph", std::move(call_summary)},
          {"metrics", {
              {"segments", metadata.segments.total},
              {"functions", {{"sampled", function_inventory.result->items.size()}, {"hasMore", function_inventory.result->has_more}}},
              {"strings", {{"sampled", string_inventory.result->items.size()}, {"hasMore", string_inventory.result->has_more}}},
              {"imports", {{"sampled", import_inventory.result->items.size()}, {"hasMore", import_inventory.result->has_more}}},
          }},
          {"truncated", truncated},
          {"budget", {{"requestedItems", *budget}, {"perSection", section}}},
      };
      if ( mode == "full" )
      {
        result["functions"] = services::ToJson(*function_inventory.result);
        result["strings"] = services::ToJson(*string_inventory.result);
      }
      else
      {
        result["functions"] = {
            {"sampledCount", function_inventory.result->items.size()},
            {"hasMore", function_inventory.result->has_more},
        };
        result["strings"] = {
            {"sampledCount", string_inventory.result->items.size()},
            {"hasMore", string_inventory.result->has_more},
        };
      }
      return Budgeted(std::move(result), "database.survey exceeds the output budget");
    });
  });

  handlers.emplace("function.profile", [&executor, &functions](const rpc::Request &request) -> Dispatcher::MethodResult
  {
    if ( !Fields(request.params, {"name", "minSize", "maxSize", "library", "thunk", "includePrototype", "sampleLimit", "limit", "cursor"}) )
      return Error(rpc::ErrorCode::InvalidArgument, "function.profile contains an unknown parameter");
    std::string name;
    if ( request.params.contains("name") )
    {
      if ( !request.params["name"].is_string() ) return Error(rpc::ErrorCode::InvalidArgument, "function.profile name is invalid");
      name = request.params["name"].get<std::string>();
    }
    const auto minimum = Bound(request.params, "minSize", 0, 0, 1024 * 1024);
    const auto maximum = Bound(request.params, "maxSize", 1024 * 1024, 1, 1024 * 1024);
    const bool filter_library = request.params.contains("library");
    const bool filter_thunk = request.params.contains("thunk");
    const auto library = Boolean(request.params, "library", false);
    const auto thunk = Boolean(request.params, "thunk", false);
    const auto prototype = Boolean(request.params, "includePrototype", false);
    const auto samples = Bound(request.params, "sampleLimit", 0, 0, 8);
    const auto limit = Bound(request.params, "limit", 20, 1, 50);
    std::optional<std::string> cursor;
    if ( request.params.contains("cursor") )
    {
      if ( !request.params["cursor"].is_string() ) return Error(rpc::ErrorCode::InvalidArgument, "function.profile cursor is invalid");
      cursor = request.params["cursor"].get<std::string>();
    }
    if ( name.size() > 1024 || name.find('\0') != std::string::npos || !minimum || !maximum
      || *minimum > *maximum || !library || !thunk || !prototype || !samples || !limit
      || *samples * *limit > 96 || (cursor && cursor->size() > 128) )
      return Error(rpc::ErrorCode::InvalidArgument, "function.profile params are invalid");

    const std::string normalized_name = Lower(name);
    std::string identity = normalized_name;
    identity.push_back('\0');
    identity += std::to_string(*minimum) + ":" + std::to_string(*maximum) + ":"
        + (filter_library ? (*library ? "1" : "0") : "*") + ":"
        + (filter_thunk ? (*thunk ? "1" : "0") : "*") + ":"
        + (*prototype ? "1" : "0") + ":" + std::to_string(*samples) + ":"
        + std::to_string(*limit);
    std::optional<std::string> search_cursor;
    if ( cursor )
    {
      try
      {
        search_cursor = rpc::EncodeFunctionSearchCursor(
            normalized_name, rpc::DecodeListCursor("fp1", *cursor, identity));
      }
      catch ( const std::invalid_argument & )
      {
        return Error(rpc::ErrorCode::InvalidArgument, "function.profile cursor is invalid");
      }
    }
    return Run(executor, request, [&functions, name, normalized_name, identity, minimum, maximum, filter_library, filter_thunk, library, thunk, prototype, samples, limit, search_cursor]() -> Dispatcher::MethodResult
    {
      const auto page = functions.SearchByName(name, *limit, search_cursor);
      if ( page.status == services::FunctionSearchStatus::InvalidCursor )
        return Error(rpc::ErrorCode::InvalidArgument, "function.profile cursor is invalid");
      if ( !page.result ) return Error(rpc::ErrorCode::InternalError, "function.profile inventory is unavailable");
      nlohmann::json items = nlohmann::json::array();
      std::size_t sampled_instructions = 0;
      for ( const auto &candidate : page.result->items )
      {
        const auto lookup = functions.Get(candidate.entry_address);
        if ( !lookup.info ) continue;
        const auto &info = *lookup.info;
        if ( info.statistics.size_bytes < *minimum || info.statistics.size_bytes > *maximum
          || (filter_library && info.flags.library != *library)
          || (filter_thunk && info.flags.thunk != *thunk) ) continue;
        nlohmann::json item{
            {"address", rpc::FormatAddress(info.entry_address)},
            {"name", info.name},
            {"metrics", {
                {"sizeBytes", info.statistics.size_bytes},
                {"instructions", info.statistics.instruction_count},
                {"basicBlocks", info.statistics.basic_block_count},
                {"chunks", info.statistics.chunk_count},
            }},
            {"flags", {{"library", info.flags.library}, {"thunk", info.flags.thunk}}},
        };
        if ( *prototype ) item["prototype"] = info.signature ? nlohmann::json(*info.signature) : nlohmann::json(nullptr);
        if ( *samples != 0 )
        {
          const auto disassembly = functions.Disassemble({info.entry_address, 0, *samples});
          item["samples"] = disassembly.result ? services::ToJson(*disassembly.result)["items"] : nlohmann::json::array();
          item["samplesTruncated"] = !disassembly.result || disassembly.result->has_more;
          sampled_instructions += item["samples"].size();
        }
        items.push_back(std::move(item));
      }
      nlohmann::json next_cursor = nullptr;
      if ( page.result->next_cursor )
      {
        try
        {
          const std::uint64_t position = rpc::DecodeFunctionSearchCursor(
              *page.result->next_cursor, normalized_name);
          next_cursor = rpc::EncodeListCursor("fp1", identity, position);
        }
        catch ( const std::invalid_argument & )
        {
          return Error(rpc::ErrorCode::InternalError, "function.profile continuation is unavailable");
        }
      }
      const std::size_t matched = items.size();
      return Budgeted({
          {"items", std::move(items)},
          {"nextCursor", std::move(next_cursor)},
          {"hasMore", page.result->has_more},
          {"metrics", {{"candidates", page.result->items.size()}, {"matched", matched}, {"sampledInstructions", sampled_instructions}}},
      }, "function.profile exceeds the output budget");
    });
  });

  handlers.emplace("function.export", [&executor, &functions](const rpc::Request &request) -> Dispatcher::MethodResult
  {
    if ( !Fields(request.params, {"addresses", "format", "maxBytes"})
      || !request.params.contains("format") || !request.params["format"].is_string() )
    {
      return Error(rpc::ErrorCode::InvalidArgument, "function.export params are invalid");
    }
    const auto addresses = Addresses(request.params, "addresses", 100);
    const auto maximum = Bound(request.params, "maxBytes", 32768, 1024, 65536);
    const std::string format = request.params["format"].get<std::string>();
    if ( !addresses || !maximum
      || (format != "json" && format != "c_header" && format != "prototypes") )
    {
      return Error(rpc::ErrorCode::InvalidArgument, "function.export params are invalid");
    }
    return Run(executor, request, [&functions, addresses, format, maximum]()
    {
      return composite::ExportFunctions(functions, *addresses, format, *maximum);
    });
  });

  handlers.emplace("function.analyze", [&executor, &functions, &decompiler, &strings, &xrefs](const rpc::Request &request) -> Dispatcher::MethodResult
  {
    if ( !Fields(request.params, {"addresses", "sections", "perSection", "decompileBytes"}) )
      return Error(rpc::ErrorCode::InvalidArgument, "function.analyze contains an unknown parameter");
    const auto addresses = Addresses(request.params, "addresses", 8);
    const auto per_section = Bound(request.params, "perSection", 50, 1, 100);
    const auto decompile_bytes = Bound(request.params, "decompileBytes", 16384, 1024, 65536);
    const auto sections = AnalysisSections(request.params);
    if ( !addresses || !sections || !per_section || !decompile_bytes
      || addresses->size() * static_cast<std::size_t>(*decompile_bytes) > MaxCompositeResultBytes )
      return Error(rpc::ErrorCode::InvalidArgument, "function.analyze params are invalid");
    return Run(executor, request, [&functions, &decompiler, &strings, &xrefs, addresses, sections, per_section, decompile_bytes]() -> Dispatcher::MethodResult
    {
      return composite::AnalyzeBatch(
          functions, decompiler, strings, xrefs, *addresses, *sections,
          *per_section, *decompile_bytes, MaxCompositeResultBytes);
    });
  });
  handlers.emplace("function.analyze_batch", handlers.at("function.analyze"));

  handlers.emplace("analysis.component", [&executor, &functions, &strings, &symbols, &xrefs](const rpc::Request &request) -> Dispatcher::MethodResult
  {
    if ( !Fields(request.params, {"roots", "maxDepth", "maxNodes", "maxEdges", "perFunction", "sharedLimit"}) )
      return Error(rpc::ErrorCode::InvalidArgument, "analysis.component contains an unknown parameter");
    const auto roots = Addresses(request.params, "roots", 16);
    const auto depth = Bound(request.params, "maxDepth", 2, 0, 5);
    const auto nodes = Bound(request.params, "maxNodes", 100, 1, 200);
    const auto edges = Bound(request.params, "maxEdges", 200, 1, 1000);
    const auto per_function = Bound(request.params, "perFunction", 50, 1, 100);
    const auto shared_limit = Bound(request.params, "sharedLimit", 100, 1, 100);
    if ( !roots || !depth || !nodes || !edges || !per_function || !shared_limit )
      return Error(rpc::ErrorCode::InvalidArgument, "analysis.component params are invalid");
    return Run(executor, request, [&functions, &strings, &symbols, &xrefs, roots, depth, nodes, edges, per_function, shared_limit]() -> Dispatcher::MethodResult
    {
      const auto graph = functions.CallGraph({
          *roots,
          services::CallGraphDirection::Both,
          *depth,
          *nodes,
          *edges,
          *per_function,
      });
      if ( graph.status == services::FunctionAnalysisStatus::InvalidAddress )
        return Error(rpc::ErrorCode::InvalidAddress, "component root address is not mapped");
      if ( graph.status == services::FunctionAnalysisStatus::NotFound )
        return Error(rpc::ErrorCode::NotFound, "component root function was not found");
      if ( graph.status == services::FunctionAnalysisStatus::OutputLimit || !graph.result )
        return Error(rpc::ErrorCode::OutputLimit, "component graph is unavailable");
      return Budgeted(
          composite::BuildComponent(
              functions, strings, symbols, xrefs, *graph.result, *per_function, *shared_limit),
          "component analysis exceeds the output budget");
    });
  });

  handlers.emplace("analysis.trace_data_flow", [&executor, &functions, &strings, &symbols, &xrefs](const rpc::Request &request) -> Dispatcher::MethodResult
  {
    if ( !Fields(request.params, {"address", "direction", "maxDepth", "maxNodes", "maxEdges"})
      || !request.params.contains("address") || !request.params["address"].is_string() )
    {
      return Error(rpc::ErrorCode::InvalidArgument, "analysis.trace_data_flow params are invalid");
    }
    std::uint64_t root = 0;
    try
    {
      root = rpc::ParseAddress(request.params["address"].get<std::string>());
    }
    catch ( const std::invalid_argument & )
    {
      return Error(rpc::ErrorCode::InvalidAddress, "trace address is invalid");
    }
    std::string direction = "both";
    if ( request.params.contains("direction") )
    {
      if ( !request.params["direction"].is_string() )
        return Error(rpc::ErrorCode::InvalidArgument, "trace direction is invalid");
      direction = request.params["direction"].get<std::string>();
    }
    if ( direction != "incoming" && direction != "outgoing" && direction != "both" )
      return Error(rpc::ErrorCode::InvalidArgument, "trace direction is invalid");
    const auto depth = Bound(request.params, "maxDepth", 3, 0, 8);
    const auto nodes = Bound(request.params, "maxNodes", 200, 1, 1000);
    const auto edges = Bound(request.params, "maxEdges", 500, 1, 2000);
    if ( !depth || !nodes || !edges )
      return Error(rpc::ErrorCode::InvalidArgument, "trace bounds are invalid");

    return Run(executor, request, [&functions, &strings, &symbols, &xrefs, root, direction, depth, nodes, edges]() -> Dispatcher::MethodResult
    {
      const auto root_check = xrefs.Query({root, services::XrefDirection::Incoming, services::XrefCategory::All, false, 1, std::nullopt});
      if ( root_check.status == services::XrefQueryStatus::InvalidAddress ) return Error(rpc::ErrorCode::InvalidAddress, "trace address is not mapped");
      if ( root_check.status != services::XrefQueryStatus::Success || !root_check.result ) return Error(rpc::ErrorCode::InternalError, "trace root validation failed");
      struct Pending { std::uint64_t address; std::uint32_t depth; };
      std::deque<Pending> pending{{root, 0}};
      std::set<std::uint64_t> seen{root};
      std::map<std::tuple<std::uint64_t, std::uint64_t, std::string>, services::XrefInfo>
          collected;
      bool truncated = false;
      while ( !pending.empty() && collected.size() < *edges )
      {
        const Pending current = pending.front();
        pending.pop_front();
        if ( current.depth == *depth )
          continue;
        const services::XrefDirection scans[] = {
            services::XrefDirection::Incoming,
            services::XrefDirection::Outgoing,
        };
        for ( services::XrefDirection scan : scans )
        {
          if ( collected.size() == *edges )
          {
            truncated = true;
            break;
          }
          if ( (direction == "incoming" && scan != services::XrefDirection::Incoming)
            || (direction == "outgoing" && scan != services::XrefDirection::Outgoing) )
          {
            continue;
          }
          const std::uint32_t remaining = static_cast<std::uint32_t>(
              (std::min)(static_cast<std::size_t>(100), *edges - collected.size()));
          const auto outcome = xrefs.Query({
              current.address,
              scan,
              services::XrefCategory::All,
              false,
              remaining,
              std::nullopt,
          });
          if ( outcome.status == services::XrefQueryStatus::InvalidAddress ) return Error(rpc::ErrorCode::InvalidAddress, "trace encountered an invalid address");
          if ( outcome.status == services::XrefQueryStatus::OutputLimit ) return Error(rpc::ErrorCode::OutputLimit, "trace xref output limit exceeded");
          if ( outcome.status != services::XrefQueryStatus::Success || !outcome.result ) return Error(rpc::ErrorCode::InternalError, "trace xref query failed");
          truncated = truncated || outcome.result->has_more;
          for ( const auto &xref : outcome.result->items )
          {
            if ( collected.size() == *edges )
            {
              truncated = true;
              break;
            }
            collected.emplace(std::make_tuple(xref.from, xref.to, xref.type), xref);
            const std::uint64_t next = scan == services::XrefDirection::Incoming
                ? xref.from
                : xref.to;
            if ( seen.find(next) != seen.end() )
              continue;
            if ( seen.size() == *nodes )
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
      nlohmann::json node_items = composite::BuildTraceNodes(
          functions, strings, symbols, seen, (std::min)(100U, *nodes), &truncated);
      nlohmann::json edge_items = nlohmann::json::array();
      for ( const auto &[key, xref] : collected )
      {
        static_cast<void>(key);
        edge_items.push_back({
            {"from", rpc::FormatAddress(xref.from)},
            {"to", rpc::FormatAddress(xref.to)},
            {"type", xref.type},
            {"code", xref.code},
            {"userDefined", xref.user_defined},
        });
      }
      return Budgeted({
          {"model", "xref_bfs"},
          {"nodes", std::move(node_items)},
          {"edges", std::move(edge_items)},
          {"truncated", truncated},
      }, "data flow trace exceeds the output budget");
    });
  });
  return handlers;
}

} // namespace ida_agent::bridge
