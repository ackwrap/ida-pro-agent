#include "composite_analysis.hpp"

#include "rpc/address.hpp"
#include "services/decompiler_service.hpp"
#include "services/function_service.hpp"
#include "services/string_service.hpp"
#include "services/symbol_service.hpp"
#include "services/xref_service.hpp"

#include <algorithm>
#include <cctype>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <utility>

namespace ida_agent::bridge::composite
{
namespace
{

Dispatcher::MethodResult Error(rpc::ErrorCode code, const char *message)
{
  return rpc::RpcError{code, message, false};
}

nlohmann::json EmptySection(bool truncated = false)
{
  return {{"items", nlohmann::json::array()}, {"truncated", truncated}};
}

std::string TruncateUtf8(std::string_view value, std::size_t maximum)
{
  if ( value.size() <= maximum )
    return std::string(value);
  std::size_t end = maximum;
  while ( end > 0 && end < value.size()
    && (static_cast<unsigned char>(value[end]) & 0xC0) == 0x80 )
  {
    --end;
  }
  return std::string(value.substr(0, end));
}

nlohmann::json StringItem(const services::StringInfo &item)
{
  return {
      {"address", rpc::FormatAddress(item.address)},
      {"length", item.length},
      {"encoding", item.encoding},
      {"value", item.value},
      {"truncated", item.truncated},
      {"originalSize", item.original_size},
  };
}

bool NumericToken(std::string_view token)
{
  while ( !token.empty()
    && (token.front() == '#' || token.front() == '$' || token.front() == '='
        || token.front() == '+' || token.front() == '-') )
  {
    token.remove_prefix(1);
  }
  if ( token.empty() )
    return false;
  if ( token.size() > 2 && token[0] == '0'
    && (token[1] == 'x' || token[1] == 'X') )
  {
    token.remove_prefix(2);
    return !token.empty() && std::all_of(token.begin(), token.end(), [](unsigned char value)
    {
      return std::isxdigit(value) != 0;
    });
  }
  if ( token.size() > 1 && (token.back() == 'h' || token.back() == 'H') )
  {
    token.remove_suffix(1);
    return std::all_of(token.begin(), token.end(), [](unsigned char value)
    {
      return std::isxdigit(value) != 0;
    });
  }
  return std::all_of(token.begin(), token.end(), [](unsigned char value)
  {
    return std::isdigit(value) != 0;
  });
}

std::set<std::string> ConstantsIn(std::string_view text)
{
  std::set<std::string> result;
  std::size_t start = 0;
  while ( start < text.size() )
  {
    while ( start < text.size()
      && !(std::isalnum(static_cast<unsigned char>(text[start]))
           || text[start] == '#' || text[start] == '$' || text[start] == '='
           || text[start] == '+' || text[start] == '-') )
    {
      ++start;
    }
    std::size_t end = start;
    while ( end < text.size()
      && (std::isalnum(static_cast<unsigned char>(text[end]))
          || text[end] == '#' || text[end] == '$' || text[end] == '='
          || text[end] == '+' || text[end] == '-') )
    {
      ++end;
    }
    if ( end > start )
    {
      const std::string token(text.substr(start, end - start));
      if ( NumericToken(token) )
        result.insert(token);
    }
    start = end + (end == start ? 1 : 0);
  }
  return result;
}

struct FunctionEvidence
{
  nlohmann::json xrefs = EmptySection();
  nlohmann::json strings = EmptySection();
  nlohmann::json constants = EmptySection();
  nlohmann::json comments = EmptySection();
  std::set<std::uint64_t> referenced_data;
};

FunctionEvidence CollectEvidence(
    const services::FunctionService &functions,
    const services::StringService &strings,
    const services::XrefService &xrefs,
    std::uint64_t address,
    std::uint32_t limit)
{
  FunctionEvidence result;
  const auto disassembly = functions.Disassemble({address, 0, limit});
  if ( !disassembly.result )
  {
    result.xrefs["truncated"] = true;
    result.strings["truncated"] = true;
    result.constants["truncated"] = true;
    result.comments["truncated"] = true;
    return result;
  }

  std::map<std::tuple<std::uint64_t, std::uint64_t, std::string>, services::XrefInfo>
      collected_xrefs;
  std::set<std::pair<std::uint64_t, std::string>> constants;
  nlohmann::json comments = nlohmann::json::array();
  bool xrefs_truncated = disassembly.result->has_more;
  for ( const auto &line : disassembly.result->items )
  {
    for ( const std::string &constant : ConstantsIn(line.text) )
    {
      if ( constants.size() < limit )
        constants.emplace(line.address, constant);
      else
        result.constants["truncated"] = true;
    }

    const std::size_t semicolon = line.text.find(';');
    const std::size_t slashes = line.text.find("//");
    const std::size_t marker = (std::min)(
        semicolon == std::string::npos ? line.text.size() : semicolon,
        slashes == std::string::npos ? line.text.size() : slashes);
    if ( marker < line.text.size() )
    {
      if ( comments.size() < limit )
      {
        comments.push_back({
            {"address", rpc::FormatAddress(line.address)},
            {"text", line.text.substr(marker)},
        });
      }
      else
      {
        result.comments["truncated"] = true;
      }
    }

    if ( collected_xrefs.size() == limit )
    {
      xrefs_truncated = true;
      continue;
    }
    const std::uint32_t remaining =
        limit - static_cast<std::uint32_t>(collected_xrefs.size());
    const auto outcome = xrefs.Query({
        line.address,
        services::XrefDirection::Outgoing,
        services::XrefCategory::All,
        false,
        remaining,
        std::nullopt,
    });
    if ( !outcome.result )
      continue;
    xrefs_truncated = xrefs_truncated || outcome.result->has_more;
    for ( const auto &xref : outcome.result->items )
    {
      collected_xrefs.emplace(
          std::make_tuple(xref.from, xref.to, xref.type),
          xref);
      if ( !xref.code )
        result.referenced_data.insert(xref.to);
    }
  }

  nlohmann::json xref_items = nlohmann::json::array();
  for ( const auto &[key, xref] : collected_xrefs )
  {
    static_cast<void>(key);
    xref_items.push_back({
        {"from", rpc::FormatAddress(xref.from)},
        {"to", rpc::FormatAddress(xref.to)},
        {"type", xref.type},
        {"code", xref.code},
        {"userDefined", xref.user_defined},
    });
  }
  result.xrefs = {{"items", std::move(xref_items)}, {"truncated", xrefs_truncated}};

  nlohmann::json constant_items = nlohmann::json::array();
  for ( const auto &[item_address, value] : constants )
  {
    constant_items.push_back({
        {"address", rpc::FormatAddress(item_address)},
        {"value", value},
    });
  }
  result.constants["items"] = std::move(constant_items);
  result.constants["truncated"] =
      result.constants["truncated"].get<bool>() || disassembly.result->has_more;
  result.comments["items"] = std::move(comments);
  result.comments["truncated"] =
      result.comments["truncated"].get<bool>() || disassembly.result->has_more;

  const auto inventory = strings.Search("", 1, (std::min)(100U, limit * 4U), std::nullopt);
  nlohmann::json string_items = nlohmann::json::array();
  if ( inventory.result )
  {
    for ( const auto &item : inventory.result->items )
    {
      if ( result.referenced_data.find(item.address) != result.referenced_data.end() )
        string_items.push_back(StringItem(item));
    }
    result.strings["truncated"] = inventory.result->has_more;
  }
  else
  {
    result.strings["truncated"] = true;
  }
  result.strings["items"] = std::move(string_items);
  return result;
}

std::string PrototypeLine(const services::FunctionInfo &info)
{
  if ( !info.signature )
  {
    return "/* prototype unavailable at " + rpc::FormatAddress(info.entry_address) + " */";
  }
  std::string line = *info.signature;
  while ( !line.empty() && std::isspace(static_cast<unsigned char>(line.back())) )
    line.pop_back();
  if ( line.empty() || line.back() != ';' )
    line.push_back(';');
  return line;
}

struct ComponentReferences
{
  std::map<std::uint64_t, std::set<std::uint64_t>> users;
  bool truncated = false;
};

ComponentReferences ComponentDataReferences(
    const services::FunctionService &functions,
    const services::XrefService &xrefs,
    const std::set<std::uint64_t> &members,
    std::uint32_t per_function,
    std::uint32_t maximum_targets)
{
  ComponentReferences result;
  for ( std::uint64_t member : members )
  {
    const auto disassembly = functions.Disassemble({member, 0, per_function});
    if ( !disassembly.result )
    {
      result.truncated = true;
      continue;
    }
    result.truncated = result.truncated || disassembly.result->has_more;
    for ( const auto &line : disassembly.result->items )
    {
      const auto outcome = xrefs.Query({
          line.address,
          services::XrefDirection::Outgoing,
          services::XrefCategory::Data,
          false,
          100,
          std::nullopt,
      });
      if ( !outcome.result )
        continue;
      result.truncated = result.truncated || outcome.result->has_more;
      for ( const auto &xref : outcome.result->items )
      {
        if ( result.users.size() == maximum_targets
          && result.users.find(xref.to) == result.users.end() )
        {
          result.truncated = true;
          continue;
        }
        result.users[xref.to].insert(member);
      }
    }
  }
  return result;
}

nlohmann::json ReferencedBy(const std::set<std::uint64_t> &addresses)
{
  nlohmann::json result = nlohmann::json::array();
  for ( std::uint64_t address : addresses )
    result.push_back(rpc::FormatAddress(address));
  return result;
}

nlohmann::json TraceNode(
    const services::FunctionService &functions,
    const std::map<std::uint64_t, services::StringInfo> &strings,
    const std::map<std::uint64_t, services::SymbolInfo> &symbols,
    std::uint64_t address)
{
  nlohmann::json result{{"address", rpc::FormatAddress(address)}, {"kind", "address"}};
  const auto function = functions.Get(address);
  if ( function.info )
  {
    result["kind"] = address == function.info->entry_address ? "function" : "code";
    result["function"] = {
        {"entryAddress", rpc::FormatAddress(function.info->entry_address)},
        {"name", function.info->name},
        {"prototype", function.info->signature
            ? nlohmann::json(*function.info->signature)
            : nlohmann::json(nullptr)},
    };
  }
  const auto string = strings.find(address);
  if ( string != strings.end() )
  {
    result["kind"] = "string";
    result["string"] = StringItem(string->second);
  }
  const auto symbol = symbols.find(address);
  if ( symbol != symbols.end() )
  {
    result["name"] = symbol->second.name;
    result["symbolKind"] = symbol->second.kind;
    if ( result["kind"] == "address" )
      result["kind"] = "symbol";
  }
  return result;
}

} // namespace

nlohmann::json AnalyzeOne(
    const services::FunctionService &functions,
    const services::DecompilerService &decompiler,
    const services::StringService &strings,
    const services::XrefService &xrefs,
    std::uint64_t address,
    const std::set<std::string> &sections,
    std::uint32_t per_section,
    std::uint32_t decompile_bytes)
{
  const auto info = functions.Get(address);
  if ( info.status != services::FunctionLookupStatus::Found || !info.info )
    return {{"address", rpc::FormatAddress(address)}, {"error", "function_not_found"}};

  const auto selected = [&sections](const char *name)
  {
    return sections.find(name) != sections.end();
  };
  nlohmann::json result{
      {"address", rpc::FormatAddress(info.info->entry_address)},
      {"name", info.info->name},
  };
  if ( selected("overview") )
  {
    result["range"] = {
        {"start", rpc::FormatAddress(info.info->range_start)},
        {"end", rpc::FormatAddress(info.info->range_end)},
    };
    result["flags"] = services::ToJson(*info.info)["flags"];
  }
  if ( selected("prototype") )
  {
    result["prototype"] = info.info->signature
        ? nlohmann::json(*info.info->signature)
        : nlohmann::json(nullptr);
  }
  if ( selected("metrics") )
  {
    result["metrics"] = {
        {"sizeBytes", info.info->statistics.size_bytes},
        {"instructions", info.info->statistics.instruction_count},
        {"basicBlocks", info.info->statistics.basic_block_count},
        {"chunks", info.info->statistics.chunk_count},
    };
  }
  if ( selected("callees") )
  {
    const auto outcome = functions.Callees({address, 0, per_section});
    result["callees"] = outcome.result ? services::ToJson(*outcome.result) : EmptySection(true);
    if ( outcome.result ) result["callees"]["truncated"] = outcome.result->has_more;
  }
  if ( selected("callers") )
  {
    const auto outcome = functions.Callers({address, 0, per_section});
    result["callers"] = outcome.result ? services::ToJson(*outcome.result) : EmptySection(true);
    if ( outcome.result ) result["callers"]["truncated"] = outcome.result->has_more;
  }
  if ( selected("blocks") )
  {
    const auto outcome = functions.BasicBlocks({address, 0, per_section});
    result["blocks"] = outcome.result ? services::ToJson(*outcome.result) : EmptySection(true);
    if ( outcome.result ) result["blocks"]["truncated"] = outcome.result->has_more;
  }

  const bool needs_evidence = selected("xrefs") || selected("strings")
      || selected("constants") || selected("comments");
  if ( needs_evidence )
  {
    FunctionEvidence evidence = CollectEvidence(functions, strings, xrefs, address, per_section);
    if ( selected("xrefs") ) result["xrefs"] = std::move(evidence.xrefs);
    if ( selected("strings") ) result["strings"] = std::move(evidence.strings);
    if ( selected("constants") ) result["constants"] = std::move(evidence.constants);
    if ( selected("comments") ) result["comments"] = std::move(evidence.comments);
  }
  if ( selected("decompile") )
  {
    const auto code = decompiler.Decompile({address, 0, decompile_bytes});
    result["decompile"] = code.status == services::DecompileStatus::Success && code.result
        ? services::ToJson(*code.result)
        : nlohmann::json(nullptr);
  }
  return result;
}

Dispatcher::MethodResult AnalyzeBatch(
    const services::FunctionService &functions,
    const services::DecompilerService &decompiler,
    const services::StringService &strings,
    const services::XrefService &xrefs,
    const std::vector<std::uint64_t> &addresses,
    const std::set<std::string> &sections,
    std::uint32_t per_section,
    std::uint32_t decompile_bytes,
    std::size_t maximum_bytes)
{
  nlohmann::json items = nlohmann::json::array();
  for ( std::uint64_t address : addresses )
  {
    items.push_back(AnalyzeOne(
        functions, decompiler, strings, xrefs, address, sections,
        per_section, decompile_bytes));
    if ( items.dump().size() > maximum_bytes )
      return Error(rpc::ErrorCode::OutputLimit, "function analysis exceeds the output budget");
  }
  nlohmann::json selected = nlohmann::json::array();
  for ( const std::string &section : sections ) selected.push_back(section);
  nlohmann::json result{{"sections", std::move(selected)}, {"items", std::move(items)}};
  if ( result.dump().size() > maximum_bytes )
    return Error(rpc::ErrorCode::OutputLimit, "function analysis exceeds the output budget");
  return result;
}

Dispatcher::MethodResult ExportFunctions(
    const services::FunctionService &functions,
    const std::vector<std::uint64_t> &addresses,
    std::string_view format,
    std::uint32_t maximum_bytes)
{
  std::vector<services::FunctionInfo> collected;
  collected.reserve(addresses.size());
  for ( std::uint64_t address : addresses )
  {
    const auto lookup = functions.Get(address);
    if ( lookup.status == services::FunctionLookupStatus::InvalidAddress )
      return Error(rpc::ErrorCode::InvalidAddress, "function.export address is not mapped");
    if ( lookup.status == services::FunctionLookupStatus::NotFound )
      return Error(rpc::ErrorCode::NotFound, "function.export function was not found");
    if ( lookup.status == services::FunctionLookupStatus::OutputLimit || !lookup.info )
      return Error(rpc::ErrorCode::OutputLimit, "function.export item exceeds the output limit");
    collected.push_back(*lookup.info);
  }

  std::string content;
  if ( format == "json" )
  {
    nlohmann::json items = nlohmann::json::array();
    for ( const auto &info : collected ) items.push_back(services::ToJson(info));
    content = items.dump(2);
  }
  else
  {
    if ( format == "c_header" )
      content = "#ifndef IDA_AGENT_FUNCTION_EXPORT_H\n#define IDA_AGENT_FUNCTION_EXPORT_H\n\n";
    for ( const auto &info : collected ) content += PrototypeLine(info) + "\n";
    if ( format == "c_header" )
      content += "\n#endif /* IDA_AGENT_FUNCTION_EXPORT_H */\n";
  }
  const std::size_t original_size = content.size();
  return nlohmann::json{
      {"format", format},
      {"content", TruncateUtf8(content, maximum_bytes)},
      {"truncated", original_size > maximum_bytes},
      {"originalSize", original_size},
  };
}

nlohmann::json BuildComponent(
    const services::FunctionService &functions,
    const services::StringService &strings,
    const services::SymbolService &symbols,
    const services::XrefService &xrefs,
    const services::FunctionCallGraphResult &graph,
    std::uint32_t per_function,
    std::uint32_t shared_limit)
{
  std::set<std::uint64_t> members;
  nlohmann::json member_items = nlohmann::json::array();
  for ( const auto &node : graph.nodes )
  {
    members.insert(node.address);
    const auto info = functions.Get(node.address);
    if ( info.info ) member_items.push_back(services::ToJson(*info.info));
  }

  std::uint64_t incoming = 0;
  std::uint64_t outgoing = 0;
  bool interface_truncated = false;
  for ( std::uint64_t member : members )
  {
    const auto callers = functions.Callers({member, 0, per_function});
    if ( callers.result )
    {
      interface_truncated = interface_truncated || callers.result->has_more;
      for ( const auto &caller : callers.result->items )
        incoming += members.find(caller.address) == members.end() ? 1 : 0;
    }
    const auto callees = functions.Callees({member, 0, per_function});
    if ( callees.result )
    {
      interface_truncated = interface_truncated || callees.result->has_more;
      for ( const auto &callee : callees.result->items )
      {
        if ( !callee.internal || members.find(callee.address) == members.end() ) ++outgoing;
      }
    }
  }

  ComponentReferences references = ComponentDataReferences(
      functions, xrefs, members, per_function, shared_limit * 4U);
  std::map<std::uint64_t, services::StringInfo> known_strings;
  const auto string_inventory = strings.Search("", 1, shared_limit, std::nullopt);
  if ( string_inventory.result )
  {
    for ( const auto &item : string_inventory.result->items )
      known_strings.emplace(item.address, item);
  }
  std::map<std::uint64_t, services::SymbolInfo> known_symbols;
  const auto symbol_inventory = symbols.Search("", "", shared_limit, std::nullopt);
  if ( symbol_inventory.result )
  {
    for ( const auto &item : symbol_inventory.result->items )
      known_symbols.emplace(item.address, item);
  }

  nlohmann::json shared_strings = nlohmann::json::array();
  nlohmann::json shared_globals = nlohmann::json::array();
  for ( const auto &[target, users] : references.users )
  {
    if ( users.size() < 2 ) continue;
    const auto string = known_strings.find(target);
    if ( string != known_strings.end() )
    {
      nlohmann::json item = StringItem(string->second);
      item["referencedBy"] = ReferencedBy(users);
      shared_strings.push_back(std::move(item));
      continue;
    }
    const auto symbol = known_symbols.find(target);
    if ( symbol != known_symbols.end() )
    {
      shared_globals.push_back({
          {"address", rpc::FormatAddress(target)},
          {"name", symbol->second.name},
          {"kind", symbol->second.kind},
          {"referencedBy", ReferencedBy(users)},
      });
    }
  }

  return {
      {"graph", services::ToJson(graph)},
      {"members", std::move(member_items)},
      {"sharedGlobals", std::move(shared_globals)},
      {"sharedStrings", std::move(shared_strings)},
      {"statistics", {
          {"internal", {{"functions", members.size()}, {"calls", graph.edges.size()}}},
          {"interface", {{"incomingCalls", incoming}, {"outgoingCalls", outgoing}}},
      }},
      {"truncated", graph.truncated || references.truncated || interface_truncated
          || (string_inventory.result && string_inventory.result->has_more)
          || (symbol_inventory.result && symbol_inventory.result->has_more)},
  };
}

nlohmann::json BuildTraceNodes(
    const services::FunctionService &functions,
    const services::StringService &strings,
    const services::SymbolService &symbols,
    const std::set<std::uint64_t> &addresses,
    std::uint32_t inventory_limit,
    bool *truncated)
{
  std::map<std::uint64_t, services::StringInfo> known_strings;
  const auto string_inventory = strings.Search("", 1, inventory_limit, std::nullopt);
  if ( string_inventory.result )
  {
    for ( const auto &item : string_inventory.result->items )
      known_strings.emplace(item.address, item);
    *truncated = *truncated || string_inventory.result->has_more;
  }
  std::map<std::uint64_t, services::SymbolInfo> known_symbols;
  const auto symbol_inventory = symbols.Search("", "", inventory_limit, std::nullopt);
  if ( symbol_inventory.result )
  {
    for ( const auto &item : symbol_inventory.result->items )
      known_symbols.emplace(item.address, item);
    *truncated = *truncated || symbol_inventory.result->has_more;
  }
  nlohmann::json result = nlohmann::json::array();
  for ( std::uint64_t address : addresses )
    result.push_back(TraceNode(functions, known_strings, known_symbols, address));
  return result;
}

} // namespace ida_agent::bridge::composite
