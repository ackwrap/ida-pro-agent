#include "ai/agent_tool_registry.hpp"

#include "ai/agent_tool_registry_additional.hpp"
#include "ai/agent_file_service.hpp"
#include "ai/agent_tool_registry_internal.hpp"
#include "services/semantic_analysis/request.hpp"

#include <algorithm>
#include <cctype>
#include <limits>
#include <optional>
#include <set>
#include <string_view>
#include <utility>

namespace ida_agent::ai
{
namespace
{
using Json = nlohmann::json;

bool Fields(const Json &value, std::initializer_list<const char *> names)
{
  if ( !value.is_object() || value.size() != names.size() ) return false;
  return std::all_of(names.begin(), names.end(), [&](const char *name) {
    return value.contains(name);
  });
}

std::optional<std::uint32_t> Unsigned(
    const Json &value,
    const char *name,
    std::uint32_t minimum,
    std::uint32_t maximum)
{
  const auto found = value.find(name);
  if ( found == value.end()
      || (!found->is_number_integer() && !found->is_number_unsigned()) )
    return std::nullopt;
  std::uint64_t parsed = 0;
  if ( found->is_number_unsigned() )
    parsed = found->get<std::uint64_t>();
  else
  {
    const std::int64_t signed_value = found->get<std::int64_t>();
    if ( signed_value < 0 ) return std::nullopt;
    parsed = static_cast<std::uint64_t>(signed_value);
  }
  if ( parsed < minimum || parsed > maximum ) return std::nullopt;
  return static_cast<std::uint32_t>(parsed);
}

std::optional<std::uint64_t> Unsigned64(
    const Json &value,
    const char *name)
{
  const auto found = value.find(name);
  if ( found == value.end()
      || (!found->is_number_integer() && !found->is_number_unsigned()) )
    return std::nullopt;
  if ( found->is_number_unsigned() ) return found->get<std::uint64_t>();
  const std::int64_t parsed = found->get<std::int64_t>();
  return parsed < 0 ? std::nullopt
                    : std::optional<std::uint64_t>(static_cast<std::uint64_t>(parsed));
}

std::optional<std::uint64_t> Address(const Json &value)
{
  if ( !value.is_string() ) return std::nullopt;
  const std::string text = value.get<std::string>();
  if ( text.size() < 3 || text.size() > 18 || text[0] != '0' || text[1] != 'x' )
    return std::nullopt;
  std::uint64_t result = 0;
  for ( std::size_t index = 2; index < text.size(); ++index )
  {
    const unsigned char character = static_cast<unsigned char>(text[index]);
    unsigned digit = 0;
    if ( character >= '0' && character <= '9' ) digit = character - '0';
    else if ( character >= 'a' && character <= 'f' ) digit = character - 'a' + 10;
    else if ( character >= 'A' && character <= 'F' ) digit = character - 'A' + 10;
    else return std::nullopt;
    if ( result > ((std::numeric_limits<std::uint64_t>::max)() - digit) / 16 )
      return std::nullopt;
    result = result * 16 + digit;
  }
  return result;
}

bool ValidText(std::string_view value, std::size_t maximum, bool allow_empty = true)
{
  if ( value.size() > maximum || (!allow_empty && value.empty()) ) return false;
  std::size_t offset = 0;
  while ( offset < value.size() )
  {
    const auto first = static_cast<unsigned char>(value[offset]);
    std::uint32_t point = 0;
    std::size_t width = 0;
    if ( first < 0x80 ) { point = first; width = 1; }
    else if ( first >= 0xC2 && first <= 0xDF ) { point = first & 0x1F; width = 2; }
    else if ( first >= 0xE0 && first <= 0xEF ) { point = first & 0x0F; width = 3; }
    else if ( first >= 0xF0 && first <= 0xF4 ) { point = first & 7; width = 4; }
    else return false;
    if ( offset + width > value.size() ) return false;
    for ( std::size_t index = 1; index < width; ++index )
    {
      const auto continuation = static_cast<unsigned char>(value[offset + index]);
      if ( (continuation & 0xC0) != 0x80 ) return false;
      point = (point << 6) | (continuation & 0x3F);
    }
    if ( (width == 2 && point < 0x80) || (width == 3 && point < 0x800)
      || (width == 4 && point < 0x10000) || (point >= 0xD800 && point <= 0xDFFF)
      || point > 0x10FFFF || point < 0x20 || (point >= 0x7F && point <= 0x9F) )
      return false;
    offset += width;
  }
  return true;
}

std::optional<std::string> Text(
    const Json &value,
    const char *name,
    std::size_t maximum,
    bool allow_empty = true)
{
  const auto found = value.find(name);
  if ( found == value.end() || !found->is_string() ) return std::nullopt;
  std::string parsed = found->get<std::string>();
  return ValidText(parsed, maximum, allow_empty)
      ? std::optional<std::string>(std::move(parsed)) : std::nullopt;
}

std::optional<std::string> Enum(
    const Json &value,
    const char *name,
    std::initializer_list<std::string_view> allowed)
{
  const auto parsed = Text(value, name, 64);
  if ( !parsed ) return std::nullopt;
  for ( std::string_view candidate : allowed )
    if ( *parsed == candidate ) return parsed;
  return std::nullopt;
}

std::optional<bool> NullableBoolean(const Json &value, const char *name)
{
  const auto found = value.find(name);
  if ( found == value.end() ) return std::nullopt;
  if ( found->is_null() ) return false;
  if ( !found->is_boolean() ) return std::nullopt;
  return found->get<bool>();
}

std::optional<std::vector<std::uint64_t>> Addresses(
    const Json &value,
    const char *name,
    std::size_t maximum)
{
  const auto found = value.find(name);
  if ( found == value.end() || !found->is_array()
      || found->empty() || found->size() > maximum )
    return std::nullopt;
  std::vector<std::uint64_t> result;
  std::set<std::uint64_t> unique;
  for ( const Json &item : *found )
  {
    const auto address = Address(item);
    if ( !address ) return std::nullopt;
    if ( unique.insert(*address).second ) result.push_back(*address);
  }
  return result;
}

std::optional<std::vector<std::string>> Sections(const Json &value)
{
  static const std::set<std::string> allowed{
      "overview", "metrics", "prototype", "callers", "callees", "blocks",
      "xrefs", "strings", "constants", "comments", "decompile"};
  const auto found = value.find("sections");
  if ( found == value.end() || !found->is_array()
      || found->empty() || found->size() > allowed.size() )
    return std::nullopt;
  std::vector<std::string> result;
  std::set<std::string> unique;
  for ( const Json &item : *found )
  {
    if ( !item.is_string() ) return std::nullopt;
    const std::string section = item.get<std::string>();
    if ( allowed.find(section) == allowed.end() || !unique.insert(section).second )
      return std::nullopt;
    result.push_back(section);
  }
  return result;
}

std::optional<services::ChangeKind> ChangeKind(std::string_view name)
{
  using K = services::ChangeKind;
  static const std::pair<std::string_view, K> values[]{
      {"rename",K::Rename},{"comment.set",K::CommentSet},{"comment.append",K::CommentAppend},
      {"comment.pseudocode",K::PseudocodeComment},{"bookmark.add",K::Bookmark},{"type.apply",K::TypeApply},
      {"patch.bytes",K::PatchBytes},{"patch.integer",K::PatchInteger},{"define.function",K::DefineFunction},
      {"define.code",K::DefineCode},{"undefine",K::Undefine},{"decompiler.invalidate",K::ForceRecompile},
      {"define.data",K::MakeData},{"operand.hex",K::OperandHex},{"operand.decimal",K::OperandDec},
      {"operand.character",K::OperandChar},{"operand.binary",K::OperandBinary},{"operand.octal",K::OperandOctal},
      {"operand.offset",K::OperandOffset},{"operand.struct_offset",K::OperandStructOffset},
      {"operand.stack_variable",K::OperandStackVariable},{"type.declare",K::DeclareType},{"enum.upsert",K::EnumUpsert},
      {"decompiler.invalidate_all",K::InvalidateAllDecompilations},{"stack.declare",K::StackDeclare},
      {"stack.delete",K::StackDelete},{"local.rename",K::LocalRename},{"local.type",K::LocalType},
      {"segment.rename",K::SegmentRename},{"segment.permissions",K::SegmentPermissions},
      {"xref.code.add",K::XrefCodeAdd},{"xref.code.delete",K::XrefCodeDelete},{"xref.data.add",K::XrefDataAdd},
      {"xref.data.delete",K::XrefDataDelete},{"function.flags",K::FunctionFlags},{"function.end",K::FunctionEnd},
      {"function.chunk.add",K::FunctionChunkAdd},{"function.chunk.delete",K::FunctionChunkDelete}};
  for ( const auto &value : values ) if ( value.first == name ) return value.second;
  return std::nullopt;
}

bool IntegerType(std::string_view value)
{
  if ( value.size() < 2 || (value.front() != 'u' && value.front() != 'i') ) return false;
  value.remove_prefix(1);
  if ( value.size() > 2
      && (value.substr(value.size() - 2) == "le" || value.substr(value.size() - 2) == "be") )
    value.remove_suffix(2);
  return value == "8" || value == "16" || value == "32" || value == "64";
}

bool OperandKind(services::ChangeKind kind)
{
  using K = services::ChangeKind;
  return kind == K::OperandHex || kind == K::OperandDec || kind == K::OperandChar
      || kind == K::OperandBinary || kind == K::OperandOctal || kind == K::OperandOffset
      || kind == K::OperandStructOffset || kind == K::OperandStackVariable;
}

bool OptionalFieldsMatch(const services::ChangeOperation &operation)
{
  using K = services::ChangeKind;
  const bool repeatable = operation.repeatable;
  const bool offset = operation.offset.has_value();
  const bool size = operation.size.has_value();
  const bool subject = operation.subject.has_value();
  switch ( operation.kind )
  {
    case K::CommentSet: case K::CommentAppend: return !offset && !size && !subject;
    case K::PatchInteger: return !repeatable && !offset && !size && subject;
    case K::OperandOffset: return !repeatable && !offset && !size;
    case K::OperandStructOffset: return !repeatable && !size && subject;
    case K::StackDeclare: return !repeatable && offset && !size && !subject;
    case K::StackDelete: return !repeatable && offset && size && !subject;
    case K::LocalRename: case K::LocalType: case K::XrefCodeAdd: case K::XrefCodeDelete:
    case K::XrefDataAdd: case K::XrefDataDelete: case K::FunctionChunkAdd: case K::FunctionChunkDelete:
      return !repeatable && !offset && !size && subject;
    default: return !repeatable && !offset && !size && !subject;
  }
}

std::optional<std::vector<services::ChangeOperation>> Operations(const Json &arguments)
{
  if ( !Fields(arguments, {"operations"}) || !arguments["operations"].is_array()
      || arguments["operations"].empty() || arguments["operations"].size() > 100 )
    return std::nullopt;
  std::vector<services::ChangeOperation> result;
  for ( const Json &item : arguments["operations"] )
  {
    if ( !Fields(item, {"kind","address","value","expected","repeatable","offset","size","subject"})
        || !item["kind"].is_string() || !item["value"].is_string()
        || !item["repeatable"].is_boolean() ) return std::nullopt;
    const auto kind = ChangeKind(item["kind"].get<std::string>());
    const std::string value = item["value"].get<std::string>();
    if ( !kind || value.size() > 65536 ) return std::nullopt;
    services::ChangeOperation operation{
        *kind, 0, value, std::nullopt, item["repeatable"].get<bool>(),
        std::nullopt, std::nullopt, std::nullopt};
    const bool addressless = *kind == services::ChangeKind::DeclareType
        || *kind == services::ChangeKind::EnumUpsert
        || *kind == services::ChangeKind::InvalidateAllDecompilations;
    if ( item["address"].is_null() )
    {
      if ( !addressless ) return std::nullopt;
    }
    else
    {
      const auto address = Address(item["address"]);
      if ( addressless || !address ) return std::nullopt;
      operation.address = *address;
    }
    if ( !item["expected"].is_null() )
    {
      if ( !item["expected"].is_string() ) return std::nullopt;
      operation.expected = item["expected"].get<std::string>();
      if ( operation.expected->size() > 65536 ) return std::nullopt;
    }
    if ( !item["offset"].is_null() )
    {
      if ( item["offset"].is_number_unsigned() )
      {
        const auto number = item["offset"].get<std::uint64_t>();
        if ( number > static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()) )
          return std::nullopt;
        operation.offset = static_cast<std::int64_t>(number);
      }
      else if ( item["offset"].is_number_integer() )
        operation.offset = item["offset"].get<std::int64_t>();
      else return std::nullopt;
    }
    if ( !item["size"].is_null() )
    {
      if ( !item["size"].is_number_unsigned() ) return std::nullopt;
      const auto number = item["size"].get<std::uint64_t>();
      if ( number == 0 || number > (std::numeric_limits<std::uint32_t>::max)() )
        return std::nullopt;
      operation.size = static_cast<std::uint32_t>(number);
    }
    if ( !item["subject"].is_null() )
    {
      if ( !item["subject"].is_string() ) return std::nullopt;
      operation.subject = item["subject"].get<std::string>();
      if ( operation.subject->empty() || operation.subject->size() > 1024 )
        return std::nullopt;
    }
    if ( !OptionalFieldsMatch(operation) ) return std::nullopt;
    if ( *kind == services::ChangeKind::Bookmark && (value.empty() || value.size() > 1024) )
      return std::nullopt;
    if ( OperandKind(*kind) && (value.size() != 1 || value[0] < '0' || value[0] > '7') )
      return std::nullopt;
    if ( *kind == services::ChangeKind::PatchBytes
        && (value.empty() || value.size() > 131072 || value.size() % 2 != 0
            || !std::all_of(value.begin(), value.end(), [](unsigned char character) {
                 return std::isxdigit(character) != 0;
               })) ) return std::nullopt;
    if ( *kind == services::ChangeKind::PatchInteger && !IntegerType(*operation.subject) )
      return std::nullopt;
    if ( *kind == services::ChangeKind::InvalidateAllDecompilations && !value.empty() )
      return std::nullopt;
    if ( *kind == services::ChangeKind::SegmentRename && (value.empty() || value.size() > 255) )
      return std::nullopt;
    if ( *kind == services::ChangeKind::SegmentPermissions
        && (value.size() != 3 || (value[0] != 'r' && value[0] != '-')
            || (value[1] != 'w' && value[1] != '-')
            || (value[2] != 'x' && value[2] != '-')) ) return std::nullopt;
    const bool xref_code = *kind == services::ChangeKind::XrefCodeAdd
        || *kind == services::ChangeKind::XrefCodeDelete;
    const bool xref_data = *kind == services::ChangeKind::XrefDataAdd
        || *kind == services::ChangeKind::XrefDataDelete;
    if ( xref_code || xref_data )
    {
      if ( !Address(Json(value)) ) return std::nullopt;
      const auto &type = *operation.subject;
      if ( xref_code
          ? type != "call_far" && type != "call_near" && type != "jump_far" && type != "jump_near"
          : type != "offset" && type != "write" && type != "read"
              && type != "text" && type != "informational" ) return std::nullopt;
    }
    if ( *kind == services::ChangeKind::FunctionEnd && !Address(Json(value)) )
      return std::nullopt;
    if ( *kind == services::ChangeKind::FunctionFlags )
    {
      std::string_view remaining(value);
      while ( !remaining.empty() )
      {
        const std::size_t separator = remaining.find(',');
        const std::string_view flag = remaining.substr(0, separator);
        if ( flag != "noreturn" && flag != "library" && flag != "static"
            && flag != "hidden" && flag != "thunk" ) return std::nullopt;
        if ( separator == std::string_view::npos ) break;
        remaining.remove_prefix(separator + 1);
        if ( remaining.empty() ) return std::nullopt;
      }
    }
    if ( *kind == services::ChangeKind::FunctionChunkAdd
        || *kind == services::ChangeKind::FunctionChunkDelete )
    {
      const auto start = Address(Json(value));
      const auto end = Address(Json(*operation.subject));
      if ( !start || !end || *start >= *end || *end - *start > 16ULL * 1024 * 1024 )
        return std::nullopt;
    }
    if ( *kind == services::ChangeKind::OperandOffset
        && operation.subject && !Address(Json(*operation.subject)) ) return std::nullopt;
    if ( (*kind == services::ChangeKind::StackDeclare || *kind == services::ChangeKind::StackDelete)
        && (!operation.offset || *operation.offset < 0) ) return std::nullopt;
    result.push_back(std::move(operation));
  }
  if ( result.size() != 1
      && std::any_of(result.begin(), result.end(), [](const auto &operation) {
           return operation.kind == services::ChangeKind::InvalidateAllDecompilations;
         }) ) return std::nullopt;
  return result;
}

template <typename Callback, typename Argument>
Json Invoke(
    const std::shared_ptr<AgentToolInvokers> &invokers,
    const Callback &callback,
    Argument &&argument)
{
  if ( !invokers || !callback ) throw std::runtime_error("fixed tool invoker is unavailable");
  return callback(std::forward<Argument>(argument));
}

template <typename Callback>
Json Invoke(
    const std::shared_ptr<AgentToolInvokers> &invokers,
    const Callback &callback)
{
  if ( !invokers || !callback ) throw std::runtime_error("fixed tool invoker is unavailable");
  return callback();
}
} // namespace

AdditionalAgentToolStatus InvokeAdditionalAgentTool(
    AgentToolName tool,
    const Json &arguments,
    const std::shared_ptr<AgentToolInvokers> &invokers,
    Json &response,
    bool &page)
{
  switch ( tool )
  {
    case AgentToolName::DebuggerThreads:
    case AgentToolName::DebuggerModules:
    {
      if ( !Fields(arguments, {"limit"}) ) return AdditionalAgentToolStatus::Invalid;
      const auto limit = Unsigned(arguments, "limit", 1, 100);
      if ( !limit ) return AdditionalAgentToolStatus::Invalid;
      response = tool == AgentToolName::DebuggerThreads
          ? Invoke(invokers, invokers ? invokers->debugger_threads : decltype(invokers->debugger_threads){}, *limit)
          : Invoke(invokers, invokers ? invokers->debugger_modules : decltype(invokers->debugger_modules){}, *limit);
      page = true;
      return AdditionalAgentToolStatus::Success;
    }
    case AgentToolName::ChangeSetPreview:
    {
      const auto operations = Operations(arguments);
      if ( !operations ) return AdditionalAgentToolStatus::Invalid;
      response = Invoke(invokers, invokers ? invokers->changeset_preview : decltype(invokers->changeset_preview){},
          AgentChangeSetPreviewArguments{*operations});
      return AdditionalAgentToolStatus::Success;
    }
    case AgentToolName::DatabaseSurvey:
    {
      if ( !Fields(arguments, {"mode", "budget"}) ) return AdditionalAgentToolStatus::Invalid;
      const auto mode = Enum(arguments, "mode", {"full", "minimal"});
      const auto budget = Unsigned(arguments, "budget", 3, 100);
      if ( !mode || !budget ) return AdditionalAgentToolStatus::Invalid;
      response = Invoke(invokers, invokers ? invokers->database_survey : decltype(invokers->database_survey){},
          AgentDatabaseSurveyArguments{*mode, *budget});
      return AdditionalAgentToolStatus::Success;
    }
    case AgentToolName::FunctionProfile:
    {
      if ( !Fields(arguments, {"name", "minSize", "maxSize", "library", "thunk",
              "includePrototype", "sampleLimit", "limit"}) )
        return AdditionalAgentToolStatus::Invalid;
      const auto name = Text(arguments, "name", 1024);
      const auto minimum = Unsigned(arguments, "minSize", 0, 1024 * 1024);
      const auto maximum = Unsigned(arguments, "maxSize", 1, 1024 * 1024);
      const auto library = NullableBoolean(arguments, "library");
      const auto thunk = NullableBoolean(arguments, "thunk");
      const auto samples = Unsigned(arguments, "sampleLimit", 0, 8);
      const auto limit = Unsigned(arguments, "limit", 1, 50);
      const auto prototype = arguments.find("includePrototype");
      if ( !name || !minimum || !maximum || *minimum > *maximum || !library || !thunk
          || !samples || !limit || *samples * *limit > 96
          || prototype == arguments.end() || !prototype->is_boolean() )
        return AdditionalAgentToolStatus::Invalid;
      AgentFunctionProfileArguments parsed{
          *name, *minimum, *maximum, std::nullopt, std::nullopt,
          prototype->get<bool>(), *samples, *limit};
      if ( !arguments["library"].is_null() ) parsed.library = *library;
      if ( !arguments["thunk"].is_null() ) parsed.thunk = *thunk;
      response = Invoke(invokers, invokers ? invokers->function_profile : decltype(invokers->function_profile){}, parsed);
      return AdditionalAgentToolStatus::Success;
    }
    case AgentToolName::FunctionExport:
    {
      if ( !Fields(arguments, {"addresses", "format", "maxBytes"}) )
        return AdditionalAgentToolStatus::Invalid;
      const auto addresses = Addresses(arguments, "addresses", 100);
      const auto format = Enum(arguments, "format", {"json", "c_header", "prototypes"});
      const auto maximum = Unsigned(arguments, "maxBytes", 1024, 65536);
      if ( !addresses || !format || !maximum ) return AdditionalAgentToolStatus::Invalid;
      response = Invoke(invokers, invokers ? invokers->function_export : decltype(invokers->function_export){},
          AgentFunctionExportArguments{*addresses, *format, *maximum});
      return AdditionalAgentToolStatus::Success;
    }
    case AgentToolName::FunctionAnalyze:
    {
      if ( !Fields(arguments, {"addresses", "sections", "perSection", "decompileBytes"}) )
        return AdditionalAgentToolStatus::Invalid;
      const auto addresses = Addresses(arguments, "addresses", 8);
      const auto sections = Sections(arguments);
      const auto per_section = Unsigned(arguments, "perSection", 1, 100);
      const auto decompile_bytes = Unsigned(arguments, "decompileBytes", 1024, 65536);
      if ( !addresses || !sections || !per_section || !decompile_bytes
          || addresses->size() * static_cast<std::size_t>(*decompile_bytes) > MaxAgentToolResultBytes )
        return AdditionalAgentToolStatus::Invalid;
      response = Invoke(invokers, invokers ? invokers->function_analyze : decltype(invokers->function_analyze){},
          AgentFunctionAnalyzeArguments{*addresses, *sections, *per_section, *decompile_bytes});
      return AdditionalAgentToolStatus::Success;
    }
    case AgentToolName::AnalysisComponent:
    {
      if ( !Fields(arguments, {"roots", "maxDepth", "maxNodes", "maxEdges", "perFunction", "sharedLimit"}) )
        return AdditionalAgentToolStatus::Invalid;
      const auto roots = Addresses(arguments, "roots", 16);
      const auto depth = Unsigned(arguments, "maxDepth", 0, 5);
      const auto nodes = Unsigned(arguments, "maxNodes", 1, 200);
      const auto edges = Unsigned(arguments, "maxEdges", 1, 1000);
      const auto per_function = Unsigned(arguments, "perFunction", 1, 100);
      const auto shared = Unsigned(arguments, "sharedLimit", 1, 100);
      if ( !roots || !depth || !nodes || !edges || !per_function || !shared )
        return AdditionalAgentToolStatus::Invalid;
      response = Invoke(invokers, invokers ? invokers->analysis_component : decltype(invokers->analysis_component){},
          AgentAnalysisComponentArguments{*roots, *depth, *nodes, *edges, *per_function, *shared});
      return AdditionalAgentToolStatus::Success;
    }
    case AgentToolName::AnalysisTraceDataFlow:
    {
      if ( !Fields(arguments, {"address", "direction", "maxDepth", "maxNodes", "maxEdges"}) )
        return AdditionalAgentToolStatus::Invalid;
      const auto address = Address(arguments["address"]);
      const auto direction = Enum(arguments, "direction", {"incoming", "outgoing", "both"});
      const auto depth = Unsigned(arguments, "maxDepth", 0, 8);
      const auto nodes = Unsigned(arguments, "maxNodes", 1, 1000);
      const auto edges = Unsigned(arguments, "maxEdges", 1, 2000);
      if ( !address || !direction || !depth || !nodes || !edges )
        return AdditionalAgentToolStatus::Invalid;
      response = Invoke(invokers,
          invokers ? invokers->analysis_trace_data_flow : decltype(invokers->analysis_trace_data_flow){},
          AgentTraceDataFlowArguments{*address, *direction, *depth, *nodes, *edges});
      return AdditionalAgentToolStatus::Success;
    }
    case AgentToolName::TraceArgumentCallers:
    {
      services::semantic::CallersRequest request;
      try { request = services::semantic::ParseCallersRequest(arguments); }
      catch (const std::invalid_argument &) { return AdditionalAgentToolStatus::Invalid; }
      if (!invokers || !invokers->argument_callers) throw std::runtime_error("caller trace invoker is unavailable");
      response = invokers->argument_callers(request);
      return AdditionalAgentToolStatus::Success;
    }
    case AgentToolName::TraceArgument:
    case AgentToolName::GuardEvidence:
    {
      services::semantic::Request request;
      try { request = services::semantic::ParseRequest(arguments); }
      catch (const std::invalid_argument &) { return AdditionalAgentToolStatus::Invalid; }
      if (!invokers || !invokers->argument_analysis)
        throw std::runtime_error("argument analysis invoker is unavailable");
      response = invokers->argument_analysis(request, tool == AgentToolName::GuardEvidence);
      return AdditionalAgentToolStatus::Success;
    }
    case AgentToolName::FileList:
    {
      if ( !Fields(arguments, {"path", "limit"}) ) return AdditionalAgentToolStatus::Invalid;
      const auto path = Text(arguments, "path", MaxAgentFilePathBytes);
      const auto limit = Unsigned(arguments, "limit", 1, 100);
      if ( !path || !limit ) return AdditionalAgentToolStatus::Invalid;
      response = Invoke(invokers,
          invokers ? invokers->file_list : decltype(invokers->file_list){},
          AgentFileListArguments{*path, *limit});
      page = true;
      return AdditionalAgentToolStatus::Success;
    }
    case AgentToolName::FileStat:
    {
      if ( !Fields(arguments, {"path"}) ) return AdditionalAgentToolStatus::Invalid;
      const auto path = Text(arguments, "path", MaxAgentFilePathBytes, false);
      if ( !path ) return AdditionalAgentToolStatus::Invalid;
      response = Invoke(invokers,
          invokers ? invokers->file_stat : decltype(invokers->file_stat){}, *path);
      return AdditionalAgentToolStatus::Success;
    }
    case AgentToolName::FileRead:
    {
      if ( !Fields(arguments, {"path", "offset", "maxBytes"}) )
        return AdditionalAgentToolStatus::Invalid;
      const auto path = Text(arguments, "path", MaxAgentFilePathBytes, false);
      const auto offset = Unsigned64(arguments, "offset");
      const auto maximum = Unsigned(arguments, "maxBytes", 1,
          static_cast<std::uint32_t>(MaxAgentFileContentBytes));
      if ( !path || !offset || !maximum ) return AdditionalAgentToolStatus::Invalid;
      response = Invoke(invokers,
          invokers ? invokers->file_read : decltype(invokers->file_read){},
          AgentFileReadArguments{*path, *offset, *maximum});
      return AdditionalAgentToolStatus::Success;
    }
    case AgentToolName::UiCursor:
    case AgentToolName::UiSelection:
    case AgentToolName::UiHighlight:
    case AgentToolName::UiView:
    {
      if ( !Fields(arguments, {}) ) return AdditionalAgentToolStatus::Invalid;
      if ( tool == AgentToolName::UiCursor )
        response = Invoke(invokers,
            invokers ? invokers->ui_cursor : decltype(invokers->ui_cursor){});
      else if ( tool == AgentToolName::UiSelection )
        response = Invoke(invokers,
            invokers ? invokers->ui_selection : decltype(invokers->ui_selection){});
      else if ( tool == AgentToolName::UiHighlight )
        response = Invoke(invokers,
            invokers ? invokers->ui_highlight : decltype(invokers->ui_highlight){});
      else
        response = Invoke(invokers,
            invokers ? invokers->ui_view : decltype(invokers->ui_view){});
      return AdditionalAgentToolStatus::Success;
    }
    case AgentToolName::AddressBoundaries:
    {
      if ( !Fields(arguments, {"address"}) ) return AdditionalAgentToolStatus::Invalid;
      const auto address = Address(arguments["address"]);
      if ( !address ) return AdditionalAgentToolStatus::Invalid;
      response = Invoke(invokers,
          invokers ? invokers->address_boundaries : decltype(invokers->address_boundaries){},
          *address);
      return AdditionalAgentToolStatus::Success;
    }
    default:
      return AdditionalAgentToolStatus::NotHandled;
  }
}

} // namespace ida_agent::ai
