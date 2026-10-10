#include "ai/agent_tool_registry.hpp"

#include "ai/agent_tool_registry_additional.hpp"
#include "ai/agent_tool_registry_internal.hpp"

#include <algorithm>
#include <limits>
#include <optional>
#include <stdexcept>
#include <utility>

namespace ida_agent::ai
{
namespace
{
using Json = nlohmann::json;
constexpr std::string_view InvalidCallMessage = "Tool call is invalid.";
constexpr std::string_view UnavailableMessage = "Tool registry is unavailable.";
constexpr std::string_view ExecutionErrorMessage = "Tool execution failed.";
constexpr std::string_view OutputLimitMessage = "Tool result exceeded the output limit.";

bool ValidText(
    std::string_view value,
    std::size_t max_bytes,
    std::size_t max_code_points,
    bool allow_empty = true)
{
  if ( value.size() > max_bytes || (!allow_empty && value.empty()) ) return false;
  std::size_t offset = 0, count = 0;
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
    if ( ++count > max_code_points ) return false;
  }
  return true;
}

bool Fields(const Json &object, std::initializer_list<const char *> names)
{
  if ( !object.is_object() || object.size() != names.size() ) return false;
  for ( const char *name : names ) if ( !object.contains(name) ) return false;
  return true;
}

std::optional<std::uint32_t> Unsigned(
    const Json &object,
    const char *name,
    std::uint32_t minimum,
    std::uint32_t maximum)
{
  const auto found = object.find(name);
  if ( found == object.end() || (!found->is_number_integer() && !found->is_number_unsigned()) )
    return std::nullopt;
  std::uint64_t value = 0;
  if ( found->is_number_unsigned() ) value = found->get<std::uint64_t>();
  else
  {
    const auto signed_value = found->get<std::int64_t>();
    if ( signed_value < 0 ) return std::nullopt;
    value = static_cast<std::uint64_t>(signed_value);
  }
  if ( value < minimum || value > maximum ) return std::nullopt;
  return static_cast<std::uint32_t>(value);
}

std::optional<std::int64_t> NonnegativeInt64(const Json &object, const char *name)
{
  const auto found = object.find(name);
  if ( found == object.end() || (!found->is_number_integer() && !found->is_number_unsigned()) )
    return std::nullopt;
  if ( found->is_number_unsigned() )
  {
    const auto value = found->get<std::uint64_t>();
    if ( value > static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()) )
      return std::nullopt;
    return static_cast<std::int64_t>(value);
  }
  const auto value = found->get<std::int64_t>();
  return value >= 0 ? std::optional<std::int64_t>(value) : std::nullopt;
}

std::optional<std::string> Text(
    const Json &object,
    const char *name,
    std::size_t max_bytes,
    std::size_t max_points,
    bool allow_empty = true)
{
  const auto found = object.find(name);
  if ( found == object.end() || !found->is_string() ) return std::nullopt;
  std::string value = found->get<std::string>();
  return ValidText(value, max_bytes, max_points, allow_empty)
      ? std::optional<std::string>(std::move(value)) : std::nullopt;
}

std::optional<std::string> Enum(
    const Json &object,
    const char *name,
    std::initializer_list<std::string_view> allowed)
{
  const auto value = Text(object, name, 64, 64);
  if ( !value ) return std::nullopt;
  for ( std::string_view candidate : allowed ) if ( *value == candidate ) return value;
  return std::nullopt;
}

std::optional<std::uint64_t> ParseAddress(std::string_view value)
{
  if ( value.size() < 3 || value.size() > 18 || value[0] != '0' || value[1] != 'x' )
    return std::nullopt;
  std::uint64_t address = 0;
  for ( std::size_t index = 2; index < value.size(); ++index )
  {
    const char character = value[index];
    std::uint8_t digit = 0;
    if ( character >= '0' && character <= '9' ) digit = character - '0';
    else if ( character >= 'a' && character <= 'f' ) digit = character - 'a' + 10;
    else if ( character >= 'A' && character <= 'F' ) digit = character - 'A' + 10;
    else return std::nullopt;
    if ( address > ((std::numeric_limits<std::uint64_t>::max)() - digit) / 16 )
      return std::nullopt;
    address = address * 16 + digit;
  }
  return address;
}

std::optional<std::uint64_t> Address(const Json &object, const char *name)
{
  const auto value = Text(object, name, 18, 18, false);
  return value ? ParseAddress(*value) : std::nullopt;
}

std::optional<std::uint64_t> SentinelAddress(
    const Json &object,
    const char *name,
    bool must_be_empty)
{
  const auto value = Text(object, name, 18, 18);
  if ( !value || (must_be_empty && !value->empty()) || (!must_be_empty && value->empty()) )
    return std::nullopt;
  return value->empty() ? std::optional<std::uint64_t>(0) : ParseAddress(*value);
}

std::optional<AgentToolName> ToolName(std::string_view name)
{
#define IDA_AGENT_TOOL(encoded, value) if ( name == encoded ) return AgentToolName::value
  IDA_AGENT_TOOL("ida_symbol_exports", SymbolExports);
  IDA_AGENT_TOOL("ida_string_search", StringSearch);
  IDA_AGENT_TOOL("ida_function_get", FunctionGet);
  IDA_AGENT_TOOL("ida_decompile", Decompile);
  IDA_AGENT_TOOL("ida_xref_query", XrefQuery);
  IDA_AGENT_TOOL("ida_memory_read", MemoryRead);
  IDA_AGENT_TOOL("ida_database_info", DatabaseInfo);
  IDA_AGENT_TOOL("ida_database_segments", DatabaseSegments);
  IDA_AGENT_TOOL("ida_database_entry_points", DatabaseEntryPoints);
  IDA_AGENT_TOOL("ida_function_search", FunctionSearch);
  IDA_AGENT_TOOL("ida_function_disassemble", FunctionDisassemble);
  IDA_AGENT_TOOL("ida_function_basic_blocks", FunctionBasicBlocks);
  IDA_AGENT_TOOL("ida_function_callers", FunctionCallers);
  IDA_AGENT_TOOL("ida_function_callees", FunctionCallees);
  IDA_AGENT_TOOL("ida_function_chunks", FunctionChunks);
  IDA_AGENT_TOOL("ida_function_call_graph", FunctionCallGraph);
  IDA_AGENT_TOOL("ida_instruction_get", InstructionGet);
  IDA_AGENT_TOOL("ida_fixup_get", FixupGet);
  IDA_AGENT_TOOL("ida_switch_get", SwitchGet);
  IDA_AGENT_TOOL("ida_symbol_imports", SymbolImports);
  IDA_AGENT_TOOL("ida_symbol_search", SymbolSearch);
  IDA_AGENT_TOOL("ida_string_search_regex", StringSearchRegex);
  IDA_AGENT_TOOL("ida_memory_search_bytes", MemorySearchBytes);
  IDA_AGENT_TOOL("ida_instruction_search", InstructionSearch);
  IDA_AGENT_TOOL("ida_signature_make", SignatureMake);
  IDA_AGENT_TOOL("ida_patch_assemble", PatchAssemble);
  IDA_AGENT_TOOL("ida_type_search", TypeSearch);
  IDA_AGENT_TOOL("ida_type_get", TypeGet);
  IDA_AGENT_TOOL("ida_type_infer", TypeInfer);
  IDA_AGENT_TOOL("ida_type_read_value", TypeReadValue);
  IDA_AGENT_TOOL("ida_type_read_struct", TypeReadStruct);
  IDA_AGENT_TOOL("ida_global_value", GlobalValue);
  IDA_AGENT_TOOL("ida_xref_struct_field", XrefStructField);
  IDA_AGENT_TOOL("ida_fixup_list", FixupList);
  IDA_AGENT_TOOL("ida_exception_try_blocks", ExceptionTryBlocks);
  IDA_AGENT_TOOL("ida_analysis_status", AnalysisStatus);
  IDA_AGENT_TOOL("ida_analysis_problems", AnalysisProblems);
  IDA_AGENT_TOOL("ida_listing_search", ListingSearch);
  IDA_AGENT_TOOL("ida_listing_search_text", ListingSearchText);
  IDA_AGENT_TOOL("ida_signature_xrefs", SignatureXrefs);
  IDA_AGENT_TOOL("ida_function_stack_frame", FunctionStackFrame);
  IDA_AGENT_TOOL("ida_source_files", SourceFiles);
  IDA_AGENT_TOOL("ida_source_lines", SourceLines);
  IDA_AGENT_TOOL("ida_name_demangle", NameDemangle);
  IDA_AGENT_TOOL("ida_comment_get", CommentGet);
  IDA_AGENT_TOOL("ida_bookmark_list", BookmarkList);
  IDA_AGENT_TOOL("ida_type_xrefs", TypeXrefs);
  IDA_AGENT_TOOL("ida_decompiler_locals", DecompilerLocals);
  IDA_AGENT_TOOL("ida_decompiler_ctree", DecompilerCtree);
  IDA_AGENT_TOOL("ida_decompiler_local_xrefs", DecompilerLocalXrefs);
  IDA_AGENT_TOOL("ida_debugger_backends", DebuggerBackends);
  IDA_AGENT_TOOL("ida_debugger_configuration", DebuggerConfiguration);
  IDA_AGENT_TOOL("ida_debugger_processes", DebuggerProcesses);
  IDA_AGENT_TOOL("ida_debugger_info", DebuggerInfo);
  IDA_AGENT_TOOL("ida_debugger_breakpoint_list", DebuggerBreakpointList);
  IDA_AGENT_TOOL("ida_debugger_registers", DebuggerRegisters);
  IDA_AGENT_TOOL("ida_debugger_stacktrace", DebuggerStacktrace);
  IDA_AGENT_TOOL("ida_debugger_memory_read", DebuggerMemoryRead);
  IDA_AGENT_TOOL("ida_changeset_audit", ChangeSetAudit);
  IDA_AGENT_TOOL("ida_debugger_threads", DebuggerThreads);
  IDA_AGENT_TOOL("ida_debugger_modules", DebuggerModules);
  IDA_AGENT_TOOL("ida_changeset_preview", ChangeSetPreview);
  IDA_AGENT_TOOL("ida_database_survey", DatabaseSurvey);
  IDA_AGENT_TOOL("ida_function_profile", FunctionProfile);
  IDA_AGENT_TOOL("ida_function_export", FunctionExport);
  IDA_AGENT_TOOL("ida_function_analyze", FunctionAnalyze);
  IDA_AGENT_TOOL("ida_analysis_component", AnalysisComponent);
  IDA_AGENT_TOOL("ida_analysis_trace_data_flow", AnalysisTraceDataFlow);
  IDA_AGENT_TOOL("ida_analysis_trace_argument", TraceArgument);
  IDA_AGENT_TOOL("ida_analysis_trace_argument_callers", TraceArgumentCallers);
  IDA_AGENT_TOOL("ida_analysis_guard_evidence", GuardEvidence);
  IDA_AGENT_TOOL("ida_file_list", FileList);
  IDA_AGENT_TOOL("ida_file_stat", FileStat);
  IDA_AGENT_TOOL("ida_file_read", FileRead);
  IDA_AGENT_TOOL("ida_ui_cursor", UiCursor);
  IDA_AGENT_TOOL("ida_ui_selection", UiSelection);
  IDA_AGENT_TOOL("ida_ui_highlight", UiHighlight);
  IDA_AGENT_TOOL("ida_ui_view", UiView);
  IDA_AGENT_TOOL("ida_address_boundaries", AddressBoundaries);
#undef IDA_AGENT_TOOL
  return std::nullopt;
}

AgentToolResult Failure(const AgentToolCall &call, std::string_view message) noexcept
{
  AgentToolResult result;
  if ( ValidText(call.id, MaxAgentToolCallIdBytes, MaxAgentToolCallIdBytes) ) result.call_id = call.id;
  if ( ValidText(call.name, MaxAgentToolNameBytes, MaxAgentToolNameBytes) ) result.name = call.name;
  result.safe_message = message;
  return result;
}

std::optional<std::string> Encode(Json result, bool page, std::size_t maximum)
{
  if ( !result.is_object() ) return std::nullopt;
  if ( page )
  {
    if ( !result.contains("items") || !result["items"].is_array()
      || !result.contains("hasMore") || !result["hasMore"].is_boolean() )
      return std::nullopt;
    result = Json{{"items", std::move(result["items"])}, {"hasMore", result["hasMore"]}};
  }
  std::string encoded = result.dump();
  return encoded.size() <= maximum
      ? std::optional<std::string>(std::move(encoded)) : std::nullopt;
}

template <typename Callback, typename... Arguments>
Json Fixed(const std::shared_ptr<AgentToolInvokers> &invokers, Callback callback, Arguments &&...arguments)
{
  if ( !invokers || !callback ) throw std::runtime_error("fixed tool invoker is unavailable");
  return callback(std::forward<Arguments>(arguments)...);
}
} // namespace

#ifdef IDA_AGENT_AGENT_TOOL_REGISTRY_TESTING
AgentToolRegistry AgentToolRegistry::ForTesting(
    std::function<Json(std::string_view, std::uint32_t)> exports,
    std::function<Json(std::string_view, std::uint32_t, std::uint32_t, bool)> strings)
{
  const auto unavailable = [](auto &&...) -> Json { throw std::runtime_error("test invoker is unavailable"); };
  return AgentToolRegistry(std::move(exports), std::move(strings), unavailable, unavailable, unavailable, unavailable, 0);
}

AgentToolRegistry AgentToolRegistry::ForTesting(
    std::function<Json(std::string_view, std::uint32_t)> exports,
    std::function<Json(std::string_view, std::uint32_t, std::uint32_t, bool)> strings,
    std::function<Json(std::uint64_t)> function_get,
    std::function<Json(std::uint64_t, std::uint32_t, std::uint32_t)> decompile,
    std::function<Json(std::uint64_t, std::string_view, std::string_view, bool, std::uint32_t)> xrefs,
    std::function<Json(std::uint64_t, std::string_view, std::uint32_t, std::uint32_t)> memory)
{
  return AgentToolRegistry(std::move(exports), std::move(strings), std::move(function_get),
      std::move(decompile), std::move(xrefs), std::move(memory), 0);
}

AgentToolRegistry AgentToolRegistry::ForTesting(AgentToolInvokers invokers)
{
  return AgentToolRegistry(std::move(invokers), 0, 0);
}
#endif

AgentToolRegistry::AgentToolRegistry(AgentToolInvokers invokers, int, int)
    : AgentToolRegistry(
          [](std::string_view, std::uint32_t) -> Json { throw std::runtime_error("test invoker is unavailable"); },
          [](std::string_view, std::uint32_t, std::uint32_t, bool) -> Json { throw std::runtime_error("test invoker is unavailable"); },
          [](std::uint64_t) -> Json { throw std::runtime_error("test invoker is unavailable"); },
          [](std::uint64_t, std::uint32_t, std::uint32_t) -> Json { throw std::runtime_error("test invoker is unavailable"); },
          [](std::uint64_t, std::string_view, std::string_view, bool, std::uint32_t) -> Json { throw std::runtime_error("test invoker is unavailable"); },
          [](std::uint64_t, std::string_view, std::uint32_t, std::uint32_t) -> Json { throw std::runtime_error("test invoker is unavailable"); },
          0)
{
  fixed_invokers_ = std::make_shared<AgentToolInvokers>(std::move(invokers));
}

const std::vector<AgentToolDefinition> &AgentToolRegistry::Definitions() const noexcept
{
  return AgentToolDefinitions();
}

AgentToolResult AgentToolRegistry::Invoke(const AgentToolCall &call) const noexcept
{
  if ( !Available() ) return Failure(call, UnavailableMessage);
  if ( !ValidText(call.id, MaxAgentToolCallIdBytes, MaxAgentToolCallIdBytes, false)
    || !ValidText(call.name, MaxAgentToolNameBytes, MaxAgentToolNameBytes, false)
    || call.arguments_json.size() > MaxAgentToolArgumentsBytes )
    return Failure(call, InvalidCallMessage);

  try
  {
    const auto tool = ToolName(call.name);
    if ( !tool ) return Failure(call, InvalidCallMessage);
    const Json arguments = Json::parse(call.arguments_json.begin(), call.arguments_json.end(), nullptr, true, false);
    Json response;
    bool page = false;

#define INVALID() return Failure(call, InvalidCallMessage)
#define REQUIRE_CALLBACK(member) if ( !fixed_invokers_ || !fixed_invokers_->member ) throw std::runtime_error("fixed tool invoker is unavailable")
    switch ( *tool )
    {
      case AgentToolName::SymbolExports:
      {
        if ( !Fields(arguments, {"name", "limit"}) ) INVALID();
        const auto name = Text(arguments, "name", 4096, 1024);
        const auto limit = Unsigned(arguments, "limit", 1, 100);
        if ( !name || !limit ) INVALID();
        response = exports_(*name, *limit); page = true; break;
      }
      case AgentToolName::StringSearch:
      {
        if ( !Fields(arguments, {"query", "minimumLength", "limit"})
          && !Fields(arguments, {"query", "minimumLength", "limit", "refresh"}) ) INVALID();
        const auto query = Text(arguments, "query", 4096, 1024, false);
        const auto minimum = Unsigned(arguments, "minimumLength", 1, 1024);
        const auto limit = Unsigned(arguments, "limit", 1, 100);
        if ( !query || !minimum || !limit ) INVALID();
        if ( arguments.contains("refresh") && !arguments["refresh"].is_boolean() ) INVALID();
        response = strings_(*query, *minimum, *limit, arguments.value("refresh", false)); page = true; break;
      }
      case AgentToolName::FunctionGet:
      case AgentToolName::InstructionGet:
      case AgentToolName::FixupGet:
      case AgentToolName::SwitchGet:
      case AgentToolName::TypeInfer:
      {
        if ( !Fields(arguments, {"address"}) ) INVALID();
        const auto address = Address(arguments, "address"); if ( !address ) INVALID();
        if ( *tool == AgentToolName::FunctionGet ) response = function_get_(*address);
        else if ( *tool == AgentToolName::InstructionGet ) { REQUIRE_CALLBACK(instruction_get); response = fixed_invokers_->instruction_get(*address); }
        else if ( *tool == AgentToolName::FixupGet ) { REQUIRE_CALLBACK(fixup_get); response = fixed_invokers_->fixup_get(*address); }
        else if ( *tool == AgentToolName::SwitchGet ) { REQUIRE_CALLBACK(switch_get); response = fixed_invokers_->switch_get(*address); }
        else { REQUIRE_CALLBACK(type_infer); response = fixed_invokers_->type_infer(*address); }
        break;
      }
      case AgentToolName::Decompile:
      {
        if ( !Fields(arguments, {"address", "offset", "maxBytes"}) ) INVALID();
        const auto address = Address(arguments, "address");
        const auto offset = Unsigned(arguments, "offset", 0, 16777216);
        const auto bytes = Unsigned(arguments, "maxBytes", 4, 65536);
        if ( !address || !offset || !bytes ) INVALID();
        response = decompile_(*address, *offset, *bytes); break;
      }
      case AgentToolName::XrefQuery:
      {
        if ( !Fields(arguments, {"address", "direction", "category", "includeFlow", "limit"}) ) INVALID();
        const auto address = Address(arguments, "address");
        const auto direction = Enum(arguments, "direction", {"incoming", "outgoing"});
        const auto category = Enum(arguments, "category", {"all", "code", "data"});
        const auto flow = arguments.find("includeFlow");
        const auto limit = Unsigned(arguments, "limit", 1, 100);
        if ( !address || !direction || !category || flow == arguments.end() || !flow->is_boolean() || !limit ) INVALID();
        response = xrefs_(*address, *direction, *category, flow->get<bool>(), *limit); page = true; break;
      }
      case AgentToolName::MemoryRead:
      {
        if ( !Fields(arguments, {"address", "format", "length", "widthBits"}) ) INVALID();
        const auto address = Address(arguments, "address");
        const auto format = Enum(arguments, "format", {"bytes", "string", "integer", "pointer"});
        const auto length = Unsigned(arguments, "length", 0, 4096);
        const auto width = Unsigned(arguments, "widthBits", 0, 64);
        if ( !address || !format || !length || !width ) INVALID();
        const bool sequence = *format == "bytes" || *format == "string";
        if ( (sequence && (*length == 0 || *width != 0))
          || (*format == "integer" && (*length != 0 || (*width != 8 && *width != 16 && *width != 32 && *width != 64)))
          || (*format == "pointer" && (*length != 0 || *width != 0)) ) INVALID();
        response = memory_(*address, *format, *length, *width); break;
      }
      case AgentToolName::DatabaseInfo:
        if ( !Fields(arguments, {}) ) INVALID(); REQUIRE_CALLBACK(database_info); response = fixed_invokers_->database_info(); break;
      case AgentToolName::DatabaseSegments:
      case AgentToolName::DatabaseEntryPoints:
      case AgentToolName::SymbolImports:
      case AgentToolName::SymbolSearch:
      case AgentToolName::StringSearchRegex:
      case AgentToolName::XrefStructField:
      {
        AgentListArguments parsed;
        if ( *tool == AgentToolName::DatabaseSegments )
        {
          if ( !Fields(arguments, {"name", "limit"}) ) INVALID();
          const auto first = Text(arguments, "name", 1024, 256); const auto limit = Unsigned(arguments, "limit", 1, 100);
          if ( !first || !limit ) INVALID(); parsed = {*first, {}, *limit}; REQUIRE_CALLBACK(database_segments); response = fixed_invokers_->database_segments(parsed);
        }
        else if ( *tool == AgentToolName::DatabaseEntryPoints )
        {
          if ( !Fields(arguments, {"name", "type", "limit"}) ) INVALID();
          const auto first = Text(arguments, "name", 1024, 256); const auto second = Enum(arguments, "type", {"", "entry", "export"}); const auto limit = Unsigned(arguments, "limit", 1, 100);
          if ( !first || !second || !limit ) INVALID(); parsed = {*first, *second, *limit}; REQUIRE_CALLBACK(database_entry_points); response = fixed_invokers_->database_entry_points(parsed);
        }
        else if ( *tool == AgentToolName::SymbolImports )
        {
          if ( !Fields(arguments, {"module", "name", "limit"}) ) INVALID();
          const auto first = Text(arguments, "module", 1024, 256); const auto second = Text(arguments, "name", 1024, 256); const auto limit = Unsigned(arguments, "limit", 1, 100);
          if ( !first || !second || !limit ) INVALID(); parsed = {*first, *second, *limit}; REQUIRE_CALLBACK(symbol_imports); response = fixed_invokers_->symbol_imports(parsed);
        }
        else if ( *tool == AgentToolName::SymbolSearch )
        {
          if ( !Fields(arguments, {"name", "kind", "limit"}) ) INVALID();
          const auto first = Text(arguments, "name", 1024, 256); const auto second = Enum(arguments, "kind", {"", "global", "data", "label"}); const auto limit = Unsigned(arguments, "limit", 1, 100);
          if ( !first || !second || !limit ) INVALID(); parsed = {*first, *second, *limit}; REQUIRE_CALLBACK(symbol_search); response = fixed_invokers_->symbol_search(parsed);
        }
        else if ( *tool == AgentToolName::StringSearchRegex )
        {
          if ( !Fields(arguments, {"pattern", "minimumLength", "limit"})
          && !Fields(arguments, {"pattern", "minimumLength", "limit", "refresh"}) ) INVALID();
          const auto first = Text(arguments, "pattern", 1024, 256, false); const auto minimum = Unsigned(arguments, "minimumLength", 1, 4096); const auto limit = Unsigned(arguments, "limit", 1, 100);
          if ( arguments.contains("refresh") && !arguments["refresh"].is_boolean() ) INVALID();
          if ( !first || !minimum || !limit ) INVALID(); AgentRegexArguments regex{*first, *minimum, *limit, arguments.value("refresh", false)}; REQUIRE_CALLBACK(string_search_regex); response = fixed_invokers_->string_search_regex(regex);
        }
        else
        {
          if ( !Fields(arguments, {"type", "field", "limit"}) ) INVALID();
          const auto first = Text(arguments, "type", 1024, 1024, false); const auto second = Text(arguments, "field", 1024, 1024, false); const auto limit = Unsigned(arguments, "limit", 1, 1000);
          if ( !first || !second || !limit ) INVALID(); parsed = {*first, *second, *limit}; REQUIRE_CALLBACK(xref_struct_field); response = fixed_invokers_->xref_struct_field(parsed);
        }
        page = *tool != AgentToolName::XrefStructField; break;
      }
      case AgentToolName::FunctionSearch:
      {
        if ( !Fields(arguments, {"mode", "name", "address", "limit"}) ) INVALID();
        const auto mode = Enum(arguments, "mode", {"name", "address"}); const auto name = Text(arguments, "name", 1024, 256);
        const auto limit = Unsigned(arguments, "limit", 1, 100); if ( !mode || !name || !limit ) INVALID();
        const bool by_name = *mode == "name"; const auto address = SentinelAddress(arguments, "address", by_name);
        if ( !address || (!by_name && !name->empty()) ) INVALID();
        AgentFunctionSearchArguments parsed{*mode, *name, *address, *limit}; REQUIRE_CALLBACK(function_search); response = fixed_invokers_->function_search(parsed); page = true; break;
      }
      case AgentToolName::FunctionDisassemble:
      case AgentToolName::FunctionBasicBlocks:
      case AgentToolName::FunctionCallers:
      case AgentToolName::FunctionCallees:
      case AgentToolName::FunctionChunks:
      {
        if ( !Fields(arguments, {"address", "offset", "limit"}) ) INVALID();
        const auto address = Address(arguments, "address"); const auto offset = Unsigned(arguments, "offset", 0, 1000000); const auto limit = Unsigned(arguments, "limit", 1, 100);
        if ( !address || !offset || !limit ) INVALID(); AgentPageArguments parsed{*address, *offset, *limit};
        if ( *tool == AgentToolName::FunctionDisassemble ) { REQUIRE_CALLBACK(function_disassemble); response = fixed_invokers_->function_disassemble(parsed); }
        else if ( *tool == AgentToolName::FunctionBasicBlocks ) { REQUIRE_CALLBACK(function_basic_blocks); response = fixed_invokers_->function_basic_blocks(parsed); }
        else if ( *tool == AgentToolName::FunctionCallers ) { REQUIRE_CALLBACK(function_callers); response = fixed_invokers_->function_callers(parsed); }
        else if ( *tool == AgentToolName::FunctionCallees ) { REQUIRE_CALLBACK(function_callees); response = fixed_invokers_->function_callees(parsed); }
        else { REQUIRE_CALLBACK(function_chunks); response = fixed_invokers_->function_chunks(parsed); }
        break;
      }
      case AgentToolName::FunctionCallGraph:
      {
        if ( !Fields(arguments, {"roots", "direction", "maxDepth", "maxNodes", "maxEdges", "perFunction"})
          || !arguments["roots"].is_array() || arguments["roots"].empty() || arguments["roots"].size() > 16 ) INVALID();
        AgentCallGraphArguments parsed; for ( const Json &root : arguments["roots"] )
        {
          if ( !root.is_string() ) INVALID(); const auto address = ParseAddress(root.get_ref<const std::string &>()); if ( !address ) INVALID(); parsed.roots.push_back(*address);
        }
        const auto direction = Enum(arguments, "direction", {"callers", "callees", "both"}); const auto depth = Unsigned(arguments, "maxDepth", 0, 5);
        const auto nodes = Unsigned(arguments, "maxNodes", 1, 500); const auto edges = Unsigned(arguments, "maxEdges", 1, 1000); const auto per = Unsigned(arguments, "perFunction", 1, 100);
        if ( !direction || !depth || !nodes || !edges || !per ) INVALID(); parsed.direction = *direction; parsed.max_depth = *depth; parsed.max_nodes = *nodes; parsed.max_edges = *edges; parsed.per_function = *per;
        REQUIRE_CALLBACK(function_call_graph); response = fixed_invokers_->function_call_graph(parsed); break;
      }
      case AgentToolName::MemorySearchBytes:
      {
        if ( !Fields(arguments, {"pattern", "start", "end", "limit"}) ) INVALID();
        const auto pattern = Text(arguments, "pattern", 1024, 1024, false); const auto start = Address(arguments, "start"); const auto end = Address(arguments, "end"); const auto limit = Unsigned(arguments, "limit", 1, 100);
        if ( !pattern || !start || !end || !limit ) INVALID(); AgentByteSearchArguments parsed{*pattern, *start, *end, *limit}; REQUIRE_CALLBACK(memory_search_bytes); response = fixed_invokers_->memory_search_bytes(parsed); page = true; break;
      }
      case AgentToolName::InstructionSearch:
      {
        if ( !Fields(arguments, {"start", "end", "mnemonic", "operand", "limit"}) ) INVALID();
        const auto start = Address(arguments, "start"); const auto end = Address(arguments, "end"); const auto mnemonic = Text(arguments, "mnemonic", 256, 256); const auto operand = Text(arguments, "operand", 256, 256); const auto limit = Unsigned(arguments, "limit", 1, 100);
        if ( !start || !end || !mnemonic || !operand || !limit ) INVALID(); AgentInstructionSearchArguments parsed{*start, *end, *mnemonic, *operand, *limit}; REQUIRE_CALLBACK(instruction_search); response = fixed_invokers_->instruction_search(parsed); page = true; break;
      }
      case AgentToolName::SignatureMake:
      {
        if ( !Fields(arguments, {"mode", "address", "start", "end", "format", "wildcardOperands", "maxLength"}) ) INVALID();
        const auto mode = Enum(arguments, "mode", {"address", "function", "range"}); const auto format = Enum(arguments, "format", {"ida", "x64dbg", "mask", "bitmask"});
        const auto wildcard = arguments.find("wildcardOperands"); const auto length = Unsigned(arguments, "maxLength", 1, 1000); if ( !mode || !format || wildcard == arguments.end() || !wildcard->is_boolean() || !length ) INVALID();
        const bool range = *mode == "range"; const auto address = SentinelAddress(arguments, "address", range); const auto start = SentinelAddress(arguments, "start", !range); const auto end = SentinelAddress(arguments, "end", !range);
        if ( !address || !start || !end ) INVALID(); AgentSignatureArguments parsed{*mode, *address, *start, *end, *format, wildcard->get<bool>(), *length}; REQUIRE_CALLBACK(signature_make); response = fixed_invokers_->signature_make(parsed); break;
      }
      case AgentToolName::PatchAssemble:
      {
        if ( !Fields(arguments, {"address", "instruction"}) ) INVALID(); const auto address = Address(arguments, "address"); const auto instruction = Text(arguments, "instruction", 4096, 4096, false);
        if ( !address || !instruction ) INVALID(); AgentAssemblyArguments parsed{*address, *instruction}; REQUIRE_CALLBACK(patch_assemble); response = fixed_invokers_->patch_assemble(parsed); break;
      }
      case AgentToolName::TypeSearch:
      {
        if ( !Fields(arguments, {"name", "kind", "ordinal", "limit"}) ) INVALID(); const auto name = Text(arguments, "name", 1024, 256); const auto kind = Enum(arguments, "kind", {"", "any", "typedef", "enum", "function", "pointer", "array", "udt", "struct", "union", "other"});
        const auto ordinal = Unsigned(arguments, "ordinal", 1, 1000000); const auto limit = Unsigned(arguments, "limit", 1, 100); if ( !name || !kind || !ordinal || !limit ) INVALID(); AgentTypeSearchArguments parsed{*name, *kind, *ordinal, *limit}; REQUIRE_CALLBACK(type_search); response = fixed_invokers_->type_search(parsed); break;
      }
      case AgentToolName::TypeGet:
      {
        if ( !Fields(arguments, {"name"}) ) INVALID(); const auto name = Text(arguments, "name", 1024, 256, false); if ( !name ) INVALID(); REQUIRE_CALLBACK(type_get); response = fixed_invokers_->type_get(*name); break;
      }
      case AgentToolName::TypeReadValue:
      case AgentToolName::TypeReadStruct:
      {
        if ( !Fields(arguments, {"address", "name", "maxBytes"}) ) INVALID(); const auto address = Address(arguments, "address"); const auto name = Text(arguments, "name", 1024, 256, *tool == AgentToolName::TypeReadStruct); const auto bytes = Unsigned(arguments, "maxBytes", 1, 65536);
        if ( !address || !name || !bytes ) INVALID(); AgentTypedReadArguments parsed{*address, *name, *bytes};
        if ( *tool == AgentToolName::TypeReadValue ) { REQUIRE_CALLBACK(type_read_value); response = fixed_invokers_->type_read_value(parsed); }
        else { REQUIRE_CALLBACK(type_read_struct); response = fixed_invokers_->type_read_struct(parsed); } break;
      }
      case AgentToolName::GlobalValue:
      {
        if ( !Fields(arguments, {"selector", "address", "name", "maxBytes"}) ) INVALID(); const auto selector = Enum(arguments, "selector", {"address", "name"}); const auto name = Text(arguments, "name", 1024, 256); const auto bytes = Unsigned(arguments, "maxBytes", 1, 65536); if ( !selector || !name || !bytes ) INVALID();
        const bool by_address = *selector == "address"; const auto address = SentinelAddress(arguments, "address", !by_address); if ( !address || (by_address && !name->empty()) || (!by_address && name->empty()) ) INVALID(); AgentGlobalValueArguments parsed{*selector, *address, *name, *bytes}; REQUIRE_CALLBACK(global_value); response = fixed_invokers_->global_value(parsed); break;
      }
      case AgentToolName::FixupList:
      {
        if ( !Fields(arguments, {"start", "end", "limit"}) ) INVALID();
        const auto start_text = Text(arguments, "start", 18, 18), end_text = Text(arguments, "end", 18, 18);
        const auto limit = Unsigned(arguments, "limit", 1, 100);
        if ( !start_text || !end_text || !limit || start_text->empty() != end_text->empty() ) INVALID();
        AgentOptionalRangeArguments parsed; parsed.limit = *limit; parsed.has_range = !start_text->empty();
        if ( parsed.has_range )
        {
          const auto start = ParseAddress(*start_text), end = ParseAddress(*end_text);
          if ( !start || !end || *start >= *end ) INVALID(); parsed.start = *start; parsed.end = *end;
        }
        REQUIRE_CALLBACK(fixup_list); response = fixed_invokers_->fixup_list(parsed); page = true; break;
      }
      case AgentToolName::ExceptionTryBlocks:
      {
        if ( !Fields(arguments, {"address", "limit"}) ) INVALID(); const auto address = Address(arguments, "address"); const auto limit = Unsigned(arguments, "limit", 1, 100);
        if ( !address || !limit ) INVALID(); REQUIRE_CALLBACK(exception_try_blocks); response = fixed_invokers_->exception_try_blocks({*address, *limit}); break;
      }
      case AgentToolName::DebuggerBackends:
      case AgentToolName::DebuggerConfiguration:
      {
        if ( !Fields(arguments, {}) ) INVALID();
        if ( *tool == AgentToolName::DebuggerBackends ) { REQUIRE_CALLBACK(debugger_backends); response = fixed_invokers_->debugger_backends(); }
        else { REQUIRE_CALLBACK(debugger_configuration); response = fixed_invokers_->debugger_configuration(); }
        break;
      }
      case AgentToolName::DebuggerProcesses:
      {
        if ( !Fields(arguments, {"limit"}) ) INVALID();
        const auto limit = Unsigned(arguments, "limit", 1, 1000);
        if ( !limit ) INVALID();
        REQUIRE_CALLBACK(debugger_processes); response = fixed_invokers_->debugger_processes(*limit); break;
      }
      case AgentToolName::AnalysisStatus:
      case AgentToolName::DebuggerInfo:
      case AgentToolName::DebuggerBreakpointList:
      {
        if ( !Fields(arguments, {}) ) INVALID();
        if ( *tool == AgentToolName::AnalysisStatus ) { REQUIRE_CALLBACK(analysis_status); response = fixed_invokers_->analysis_status(); }
        else if ( *tool == AgentToolName::DebuggerInfo ) { REQUIRE_CALLBACK(debugger_info); response = fixed_invokers_->debugger_info(); }
        else { REQUIRE_CALLBACK(debugger_breakpoint_list); response = fixed_invokers_->debugger_breakpoint_list(); } break;
      }
      case AgentToolName::AnalysisProblems:
      {
        if ( !Fields(arguments, {"type", "start", "limit"}) ) INVALID();
        const auto type = Enum(arguments, "type", {"no_base", "no_name", "no_forced_operand", "no_comment", "no_xrefs", "jump_table", "disassembly", "head", "illegal_address", "many_lines", "bad_stack", "attention", "final_decision", "rolled_back", "flair_collision", "flair_indecision"});
        const auto start_text = Text(arguments, "start", 18, 18); const auto limit = Unsigned(arguments, "limit", 1, 100);
        if ( !type || !start_text || !limit ) INVALID(); AgentAnalysisProblemsArguments parsed{*type, !start_text->empty(), 0, *limit};
        if ( parsed.has_start ) { const auto start = ParseAddress(*start_text); if ( !start ) INVALID(); parsed.start = *start; }
        REQUIRE_CALLBACK(analysis_problems); response = fixed_invokers_->analysis_problems(parsed); page = true; break;
      }
      case AgentToolName::ListingSearch:
      case AgentToolName::ListingSearchText:
      {
        AgentListingArguments parsed;
        if ( *tool == AgentToolName::ListingSearch )
        {
          if ( !Fields(arguments, {"start", "end", "query", "limit"}) ) INVALID();
          const auto start = Address(arguments, "start"), end = Address(arguments, "end"); const auto query = Text(arguments, "query", 1024, 1024, false); const auto limit = Unsigned(arguments, "limit", 1, 100);
          if ( !start || !end || *start >= *end || !query || !limit ) INVALID(); parsed = {*start, *end, "query", *query, true, false, *limit}; REQUIRE_CALLBACK(listing_search); response = fixed_invokers_->listing_search(parsed);
        }
        else
        {
          if ( !Fields(arguments, {"start", "end", "mode", "pattern", "includeDisassembly", "includeComments", "limit"}) ) INVALID();
          const auto start = Address(arguments, "start"), end = Address(arguments, "end"); const auto mode = Enum(arguments, "mode", {"query", "regex"}); const auto pattern = Text(arguments, "pattern", 1024, 1024, false); const auto limit = Unsigned(arguments, "limit", 1, 100);
          const auto disassembly = arguments.find("includeDisassembly"), comments = arguments.find("includeComments");
          if ( !start || !end || *start >= *end || !mode || !pattern || (*mode == "regex" && pattern->size() > 256) || !limit || disassembly == arguments.end() || !disassembly->is_boolean() || comments == arguments.end() || !comments->is_boolean() || (!disassembly->get<bool>() && !comments->get<bool>()) ) INVALID();
          parsed = {*start, *end, *mode, *pattern, disassembly->get<bool>(), comments->get<bool>(), *limit}; REQUIRE_CALLBACK(listing_search_text); response = fixed_invokers_->listing_search_text(parsed);
        }
        page = true; break;
      }
      case AgentToolName::SignatureXrefs:
      {
        if ( !Fields(arguments, {"address", "format", "wildcardOperands", "maxLength", "top"}) ) INVALID();
        const auto address = Address(arguments, "address"); const auto format = Enum(arguments, "format", {"ida", "x64dbg", "mask", "bitmask"}); const auto wildcard = arguments.find("wildcardOperands"); const auto length = Unsigned(arguments, "maxLength", 1, 1000); const auto top = Unsigned(arguments, "top", 1, 32);
        if ( !address || !format || wildcard == arguments.end() || !wildcard->is_boolean() || !length || !top ) INVALID(); REQUIRE_CALLBACK(signature_xrefs); response = fixed_invokers_->signature_xrefs({*address, *format, wildcard->get<bool>(), *length, *top}); break;
      }
      case AgentToolName::FunctionStackFrame:
      {
        if ( !Fields(arguments, {"address"}) ) INVALID(); const auto address = Address(arguments, "address"); if ( !address ) INVALID(); REQUIRE_CALLBACK(function_stack_frame); response = fixed_invokers_->function_stack_frame(*address); break;
      }
      case AgentToolName::SourceFiles:
      case AgentToolName::BookmarkList:
      {
        if ( !Fields(arguments, {"limit"}) ) INVALID(); const auto limit = Unsigned(arguments, "limit", 1, 100); if ( !limit ) INVALID();
        if ( *tool == AgentToolName::SourceFiles ) { REQUIRE_CALLBACK(source_files); response = fixed_invokers_->source_files(*limit); }
        else { REQUIRE_CALLBACK(bookmark_list); response = fixed_invokers_->bookmark_list(*limit); } page = true; break;
      }
      case AgentToolName::SourceLines:
      {
        if ( !Fields(arguments, {"start", "end", "limit"}) ) INVALID(); const auto start = Address(arguments, "start"), end = Address(arguments, "end"); const auto limit = Unsigned(arguments, "limit", 1, 100);
        if ( !start || !end || *start >= *end || !limit ) INVALID(); AgentRangeArguments parsed{*start, *end, *limit}; REQUIRE_CALLBACK(source_lines); response = fixed_invokers_->source_lines(parsed); page = true; break;
      }
      case AgentToolName::NameDemangle:
      {
        if ( !Fields(arguments, {"selector", "address", "name"}) ) INVALID(); const auto selector = Enum(arguments, "selector", {"address", "name"}); const auto name = Text(arguments, "name", 4096, 4096); if ( !selector || !name ) INVALID();
        const bool by_address = *selector == "address"; const auto address = SentinelAddress(arguments, "address", !by_address); if ( !address || (by_address && !name->empty()) || (!by_address && name->empty()) ) INVALID(); REQUIRE_CALLBACK(name_demangle); response = fixed_invokers_->name_demangle({*selector, *address, *name}); break;
      }
      case AgentToolName::CommentGet:
      {
        if ( !Fields(arguments, {"address", "scope", "repeatable"}) ) INVALID(); const auto address = Address(arguments, "address"); const auto scope = Enum(arguments, "scope", {"item", "function"}); const auto repeatable = arguments.find("repeatable");
        if ( !address || !scope || repeatable == arguments.end() || !repeatable->is_boolean() ) INVALID(); REQUIRE_CALLBACK(comment_get); response = fixed_invokers_->comment_get({*address, *scope, repeatable->get<bool>()}); break;
      }
      case AgentToolName::TypeXrefs:
      {
        if ( !Fields(arguments, {"name", "limit"}) ) INVALID(); const auto name = Text(arguments, "name", 4096, 4096, false); const auto limit = Unsigned(arguments, "limit", 1, 100); if ( !name || !limit ) INVALID(); REQUIRE_CALLBACK(type_xrefs); response = fixed_invokers_->type_xrefs({*name, {}, *limit}); page = true; break;
      }
      case AgentToolName::DecompilerLocals:
      case AgentToolName::DebuggerMemoryRead:
      {
        const char *count_name = *tool == AgentToolName::DecompilerLocals ? "maxItems" : "length"; const std::uint32_t maximum = *tool == AgentToolName::DecompilerLocals ? 512 : 65536;
        if ( !Fields(arguments, {"address", count_name}) ) INVALID(); const auto address = Address(arguments, "address"); const auto count = Unsigned(arguments, count_name, 1, maximum); if ( !address || !count ) INVALID();
        if ( *tool == AgentToolName::DecompilerLocals ) { REQUIRE_CALLBACK(decompiler_locals); response = fixed_invokers_->decompiler_locals({*address, *count}); }
        else { REQUIRE_CALLBACK(debugger_memory_read); response = fixed_invokers_->debugger_memory_read({*address, *count}); } break;
      }
      case AgentToolName::DecompilerCtree:
      {
        if ( !Fields(arguments, {"address", "maxDepth", "maxNodes"}) ) INVALID(); const auto address = Address(arguments, "address"); const auto depth = Unsigned(arguments, "maxDepth", 1, 32); const auto nodes = Unsigned(arguments, "maxNodes", 1, 1000); if ( !address || !depth || !nodes ) INVALID(); REQUIRE_CALLBACK(decompiler_ctree); response = fixed_invokers_->decompiler_ctree({*address, *depth, *nodes}); break;
      }
      case AgentToolName::DecompilerLocalXrefs:
      {
        if ( !Fields(arguments, {"address", "localIndex", "maxDepth", "maxNodes", "maxItems"}) ) INVALID(); const auto address = Address(arguments, "address"); const auto index = Unsigned(arguments, "localIndex", 0, 1000000); const auto depth = Unsigned(arguments, "maxDepth", 1, 32); const auto nodes = Unsigned(arguments, "maxNodes", 1, 5000); const auto items = Unsigned(arguments, "maxItems", 1, 512);
        if ( !address || !index || !depth || !nodes || !items ) INVALID(); REQUIRE_CALLBACK(decompiler_local_xrefs); response = fixed_invokers_->decompiler_local_xrefs({*address, *index, *depth, *nodes, *items}); break;
      }
      case AgentToolName::DebuggerRegisters:
      {
        if ( !Fields(arguments, {"threadMode", "threadIds", "registerMode", "names"}) ) INVALID(); const auto thread_mode = Enum(arguments, "threadMode", {"current", "specified", "all"}); const auto register_mode = Enum(arguments, "registerMode", {"all", "named", "general-purpose"});
        if ( !thread_mode || !register_mode || !arguments["threadIds"].is_array() || arguments["threadIds"].size() > 256 || !arguments["names"].is_array() || arguments["names"].size() > 256 ) INVALID(); AgentDebuggerRegistersArguments parsed{*thread_mode, {}, *register_mode, {}};
        for ( const Json &value : arguments["threadIds"] ) { Json wrapper{{"value", value}}; const auto id = NonnegativeInt64(wrapper, "value"); if ( !id || *id == 0 || std::find(parsed.thread_ids.begin(), parsed.thread_ids.end(), *id) != parsed.thread_ids.end() ) INVALID(); parsed.thread_ids.push_back(*id); }
        for ( const Json &value : arguments["names"] ) { if ( !value.is_string() ) INVALID(); const std::string name = value.get<std::string>(); if ( !ValidText(name, 128, 128, false) || std::find(parsed.names.begin(), parsed.names.end(), name) != parsed.names.end() ) INVALID(); parsed.names.push_back(name); }
        if ( (*thread_mode == "specified") != !parsed.thread_ids.empty() || (*register_mode == "named") != !parsed.names.empty() ) INVALID(); REQUIRE_CALLBACK(debugger_registers); response = fixed_invokers_->debugger_registers(parsed); break;
      }
      case AgentToolName::DebuggerStacktrace:
      {
        if ( !Fields(arguments, {"threadId", "limit"}) ) INVALID(); const auto thread = NonnegativeInt64(arguments, "threadId"); const auto limit = Unsigned(arguments, "limit", 1, 1000); if ( !thread || !limit ) INVALID(); REQUIRE_CALLBACK(debugger_stacktrace); response = fixed_invokers_->debugger_stacktrace({*thread, *limit}); break;
      }
      case AgentToolName::ChangeSetAudit:
      {
        if ( !Fields(arguments, {"offset", "limit"}) ) INVALID(); const auto offset = Unsigned(arguments, "offset", 0, (std::numeric_limits<std::uint32_t>::max)()); const auto limit = Unsigned(arguments, "limit", 1, 1000); if ( !offset || !limit ) INVALID(); REQUIRE_CALLBACK(changeset_audit); response = fixed_invokers_->changeset_audit({*offset, *limit}); break;
      }
      case AgentToolName::DebuggerThreads:
      case AgentToolName::DebuggerModules:
      case AgentToolName::ChangeSetPreview:
      case AgentToolName::DatabaseSurvey:
      case AgentToolName::FunctionProfile:
      case AgentToolName::FunctionExport:
      case AgentToolName::FunctionAnalyze:
      case AgentToolName::AnalysisComponent:
      case AgentToolName::AnalysisTraceDataFlow:
      case AgentToolName::TraceArgumentCallers:
      case AgentToolName::TraceArgument:
      case AgentToolName::GuardEvidence:
      case AgentToolName::FileList:
      case AgentToolName::FileStat:
      case AgentToolName::FileRead:
      case AgentToolName::UiCursor:
      case AgentToolName::UiSelection:
      case AgentToolName::UiHighlight:
      case AgentToolName::UiView:
      case AgentToolName::AddressBoundaries:
      {
        const AdditionalAgentToolStatus status = InvokeAdditionalAgentTool(
            *tool, arguments, fixed_invokers_, response, page);
        if ( status != AdditionalAgentToolStatus::Success ) INVALID();
        break;
      }
    }
#undef REQUIRE_CALLBACK
#undef INVALID
    const std::size_t result_limit = *tool == AgentToolName::FileRead
        ? MaxAgentFileToolResultBytes : MaxAgentToolResultBytes;
    auto output = Encode(std::move(response), page, result_limit);
    if ( !output ) return Failure(call, OutputLimitMessage);
    return AgentToolResult{call.id, call.name, true, std::move(*output), {}};
  }
  catch ( const AgentToolSafeError &error ) { return Failure(call, error.what()); }
  catch ( const std::exception & ) { return Failure(call, ExecutionErrorMessage); }
  catch ( ... ) { return Failure(call, ExecutionErrorMessage); }
}

void AgentToolRegistry::SetAvailable(bool available) noexcept
{
  available_.store(available, std::memory_order_release);
}

bool AgentToolRegistry::Available() const noexcept
{
  return available_.load(std::memory_order_acquire);
}

} // namespace ida_agent::ai
