#include "ai/agent_tool_registry.hpp"

#include <limits>
#include <utility>

namespace ida_agent::ai
{
namespace
{
using Json = nlohmann::json;

Json Text(std::size_t maximum, std::string value = {}, std::size_t minimum = 0)
{
  Json schema{{"type", "string"}, {"maxLength", maximum}, {"default", std::move(value)}};
  if ( minimum != 0 ) schema["minLength"] = minimum;
  return schema;
}

Json Address(bool sentinel = false)
{
  return {
      {"type", "string"},
      {"pattern", sentinel ? "^(|0x[0-9A-Fa-f]{1,16})$" : "^0x[0-9A-Fa-f]{1,16}$"},
      {"default", sentinel ? "" : "0x0"},
  };
}

Json Integer(std::uint64_t minimum, std::uint64_t maximum, std::uint64_t value)
{
  return {{"type", "integer"}, {"minimum", minimum}, {"maximum", maximum}, {"default", value}};
}

Json Boolean(bool value)
{
  return {{"type", "boolean"}, {"default", value}};
}

Json Enum(std::initializer_list<const char *> values, const char *value)
{
  Json items = Json::array();
  for ( const char *item : values ) items.push_back(item);
  return {{"type", "string"}, {"enum", std::move(items)}, {"default", value}};
}

Json Array(Json items, std::size_t maximum)
{
  return {{"type", "array"}, {"items", std::move(items)}, {"maxItems", maximum}, {"default", Json::array()}};
}

Json Array(
    Json items,
    std::size_t minimum,
    std::size_t maximum,
    Json value)
{
  return {{"type", "array"}, {"items", std::move(items)},
      {"minItems", minimum}, {"maxItems", maximum}, {"default", std::move(value)}};
}

Json Nullable(const char *type, Json extra = Json::object())
{
  extra["type"] = Json::array({type, "null"});
  extra["default"] = nullptr;
  return extra;
}

Json Strict(std::initializer_list<std::pair<const char *, Json>> fields)
{
  Json properties = Json::object(), required = Json::array();
  for ( const auto &field : fields )
  {
    properties[field.first] = field.second;
    required.push_back(field.first);
  }
  return {{"type", "object"}, {"additionalProperties", false},
      {"properties", std::move(properties)}, {"required", std::move(required)}};
}

AgentToolDefinition Tool(
    const char *name,
    const char *description,
    std::initializer_list<std::pair<const char *, Json>> fields)
{
  return {name, description, Strict(fields)};
}
} // namespace

const std::vector<AgentToolDefinition> &ExtendedAgentToolDefinitions()
{
  static const Json change_kinds = Json::array({
      "rename", "comment.set", "comment.append", "comment.pseudocode", "bookmark.add",
      "type.apply", "patch.bytes", "patch.integer", "define.function", "define.code",
      "undefine", "decompiler.invalidate", "define.data", "operand.hex", "operand.decimal",
      "operand.character", "operand.binary", "operand.octal", "operand.offset",
      "operand.struct_offset", "operand.stack_variable", "type.declare", "enum.upsert",
      "decompiler.invalidate_all", "stack.declare", "stack.delete", "local.rename",
      "local.type", "segment.rename", "segment.permissions", "xref.code.add",
      "xref.code.delete", "xref.data.add", "xref.data.delete", "function.flags",
      "function.end", "function.chunk.add", "function.chunk.delete"});
  static const Json change_operation = Strict({
      {"kind", {{"type", "string"}, {"enum", change_kinds}, {"default", "rename"}}},
      {"address", Nullable("string", {{"pattern", "^0x[0-9A-Fa-f]{1,16}$"}})},
      {"value", Text(65536)},
      {"expected", Nullable("string", {{"maxLength", 65536}})},
      {"repeatable", Boolean(false)},
      {"offset", Nullable("integer", {
          {"minimum", (std::numeric_limits<std::int64_t>::min)()},
          {"maximum", (std::numeric_limits<std::int64_t>::max)()}})},
      {"size", Nullable("integer", {
          {"minimum", 1}, {"maximum", (std::numeric_limits<std::uint32_t>::max)()}})},
      {"subject", Nullable("string", {{"minLength", 1}, {"maxLength", 1024}})},
  });
  static const Json analysis_sections = Json::array({
      "overview", "metrics", "prototype", "callers", "callees", "blocks",
      "xrefs", "strings", "constants", "comments", "decompile"});
  static const std::vector<AgentToolDefinition> definitions{
      Tool("ida_fixup_list", "List a bounded first page of fixups without exposing continuation state.", {
          {"start", Address(true)}, {"end", Address(true)}, {"limit", Integer(1, 100, 20)}}),
      Tool("ida_exception_try_blocks", "List bounded exception try blocks for one function.", {
          {"address", Address()}, {"limit", Integer(1, 100, 20)}}),
      Tool("ida_analysis_status", "Get the current IDA auto-analysis status.", {}),
      Tool("ida_analysis_problems", "List a bounded first page of one analysis-problem category.", {
          {"type", Enum({"no_base", "no_name", "no_forced_operand", "no_comment", "no_xrefs",
              "jump_table", "disassembly", "head", "illegal_address", "many_lines", "bad_stack",
              "attention", "final_decision", "rolled_back", "flair_collision", "flair_indecision"}, "attention")},
          {"start", Address(true)}, {"limit", Integer(1, 100, 20)}}),
      Tool("ida_listing_search", "Search a bounded listing range for disassembly text.", {
          {"start", Address()}, {"end", Address()}, {"query", Text(1024, "", 1)},
          {"limit", Integer(1, 100, 20)}}),
      Tool("ida_listing_search_text", "Search bounded listing text by fixed query or regex mode.", {
          {"start", Address()}, {"end", Address()}, {"mode", Enum({"query", "regex"}, "query")},
          {"pattern", Text(1024, "", 1)}, {"includeDisassembly", Boolean(true)},
          {"includeComments", Boolean(true)}, {"limit", Integer(1, 100, 20)}}),
      Tool("ida_signature_xrefs", "Create bounded signatures for incoming code references.", {
          {"address", Address()}, {"format", Enum({"ida", "x64dbg", "mask", "bitmask"}, "ida")},
          {"wildcardOperands", Boolean(true)}, {"maxLength", Integer(1, 1000, 250)},
          {"top", Integer(1, 32, 5)}}),
      Tool("ida_function_stack_frame", "Get bounded stack-frame metadata for one function.", {
          {"address", Address()}}),
      Tool("ida_source_files", "List a bounded first page of source files without exposing a cursor.", {
          {"limit", Integer(1, 100, 20)}}),
      Tool("ida_source_lines", "List a bounded first page of source lines in an address range.", {
          {"start", Address()}, {"end", Address()}, {"limit", Integer(1, 100, 20)}}),
      Tool("ida_name_demangle", "Demangle exactly one address-derived or explicit name.", {
          {"selector", Enum({"address", "name"}, "address")}, {"address", Address(true)},
          {"name", Text(4096)}}),
      Tool("ida_comment_get", "Get one item or function comment.", {
          {"address", Address()}, {"scope", Enum({"item", "function"}, "item")},
          {"repeatable", Boolean(false)}}),
      Tool("ida_bookmark_list", "List a bounded first page of bookmarks without exposing a cursor.", {
          {"limit", Integer(1, 100, 20)}}),
      Tool("ida_type_xrefs", "List a bounded first page of references to a named type.", {
          {"name", Text(4096, "", 1)}, {"limit", Integer(1, 100, 20)}}),
      Tool("ida_decompiler_locals", "List bounded decompiler locals for one function.", {
          {"address", Address()}, {"maxItems", Integer(1, 512, 100)}}),
      Tool("ida_decompiler_ctree", "Get a bounded decompiler ctree for one function.", {
          {"address", Address()}, {"maxDepth", Integer(1, 32, 8)},
          {"maxNodes", Integer(1, 1000, 200)}}),
      Tool("ida_decompiler_local_xrefs", "Find bounded ctree references to one decompiler local.", {
          {"address", Address()}, {"localIndex", Integer(0, 1000000, 0)},
          {"maxDepth", Integer(1, 32, 16)}, {"maxNodes", Integer(1, 5000, 1000)},
          {"maxItems", Integer(1, 512, 100)}}),
      Tool("ida_debugger_backends", "List installed debugger names and local/remote modes while idle; works before selection.", {}),
      Tool("ida_debugger_configuration", "Read launch and remote options; returns hasPassword, never the password.", {}),
      Tool("ida_debugger_processes", "List attach candidates from the selected local or remote debugger while idle. Returns total and truncated; enumeration itself may take time.", {{"limit", Integer(1, 1000, 100)}}),
      Tool("ida_debugger_info", "Get the current debugger state without changing it.", {}),
      Tool("ida_debugger_breakpoint_list", "List debugger breakpoints without changing them.", {}),
      Tool("ida_debugger_registers", "Read bounded debugger registers with fixed thread and register selectors.", {
          {"threadMode", Enum({"current", "specified", "all"}, "current")},
          {"threadIds", Array(Integer(1, (std::numeric_limits<std::int64_t>::max)(), 1), 256)},
          {"registerMode", Enum({"all", "named", "general-purpose"}, "all")},
          {"names", Array(Text(128, "", 1), 256)}}),
      Tool("ida_debugger_stacktrace", "Read a bounded debugger stack trace; threadId zero selects the current thread.", {
          {"threadId", Integer(0, (std::numeric_limits<std::int64_t>::max)(), 0)},
          {"limit", Integer(1, 1000, 100)}}),
      Tool("ida_debugger_memory_read", "Read a bounded range from debugger process memory.", {
          {"address", Address()}, {"length", Integer(1, 65536, 256)}}),
      Tool("ida_changeset_audit", "Read a bounded ChangeSet audit page without modifying audit state.", {
          {"offset", Integer(0, (std::numeric_limits<std::uint32_t>::max)(), 0)},
          {"limit", Integer(1, 1000, 100)}}),
      Tool("ida_debugger_threads", "List a bounded first page of debugger threads without changing debugger state or exposing a cursor.", {
          {"limit", Integer(1, 100, 20)}}),
      Tool("ida_debugger_modules", "List a bounded first page of debugger modules without changing debugger state or exposing a cursor.", {
          {"limit", Integer(1, 100, 20)}}),
      Tool("ida_changeset_preview", "Preview fixed ChangeSet operations without applying or recording any change.", {
          {"operations", Array(change_operation, 1, 100, Json::array({Json{
              {"kind", "rename"}, {"address", "0x0"}, {"value", ""},
              {"expected", nullptr}, {"repeatable", false}, {"offset", nullptr},
              {"size", nullptr}, {"subject", nullptr}}}))}}),
      Tool("ida_database_survey", "Build a bounded read-only survey from database metadata and sampled inventories.", {
          {"mode", Enum({"full", "minimal"}, "full")},
          {"budget", Integer(3, 100, 60)}}),
      Tool("ida_function_profile", "Profile a bounded first page of functions without exposing continuation state.", {
          {"name", Text(1024)}, {"minSize", Integer(0, 1024 * 1024, 0)},
          {"maxSize", Integer(1, 1024 * 1024, 1024 * 1024)},
          {"library", Nullable("boolean")}, {"thunk", Nullable("boolean")},
          {"includePrototype", Boolean(false)}, {"sampleLimit", Integer(0, 8, 0)},
          {"limit", Integer(1, 50, 20)}}),
      Tool("ida_function_export", "Export bounded function metadata or prototypes without writing a file.", {
          {"addresses", Array(Address(), 1, 100, Json::array({"0x0"}))},
          {"format", Enum({"json", "c_header", "prototypes"}, "json")},
          {"maxBytes", Integer(1024, 65536, 32768)}}),
      Tool("ida_function_analyze", "Analyze bounded functions using fixed read-only evidence sections.", {
          {"addresses", Array(Address(), 1, 8, Json::array({"0x0"}))},
          {"sections", Array({{"type", "string"}, {"enum", analysis_sections}},
              1, 11, analysis_sections)},
          {"perSection", Integer(1, 100, 50)},
          {"decompileBytes", Integer(1024, 65536, 16384)}}),
      Tool("ida_analysis_component", "Build a bounded read-only component analysis from fixed call-graph roots.", {
          {"roots", Array(Address(), 1, 16, Json::array({"0x0"}))},
          {"maxDepth", Integer(0, 5, 2)}, {"maxNodes", Integer(1, 200, 100)},
          {"maxEdges", Integer(1, 1000, 200)}, {"perFunction", Integer(1, 100, 50)},
          {"sharedLimit", Integer(1, 100, 100)}}),
      Tool("ida_analysis_trace_data_flow", "Trace a bounded read-only cross-reference data-flow graph.", {
          {"address", Address()}, {"direction", Enum({"incoming", "outgoing", "both"}, "both")},
          {"maxDepth", Integer(0, 8, 3)}, {"maxNodes", Integer(1, 1000, 200)},
          {"maxEdges", Integer(1, 2000, 500)}}),
      Tool("ida_file_list", "List one stable, bounded directory level under the current IDB directory without following reparse points or exposing the absolute root.", {
          {"path", Text(1024)}, {"limit", Integer(1, 100, 50)}}),
      Tool("ida_file_stat", "Get bounded metadata for a relative path under the current IDB directory without following reparse points.", {
          {"path", Text(1024, "", 1)}}),
      Tool("ida_file_read", "Read one bounded page from an ordinary UTF-8 text file under the current IDB directory; file access is restricted to this tool's safety policy.", {
          {"path", Text(1024, "", 1)},
          {"offset", Integer(0, (std::numeric_limits<std::uint64_t>::max)(), 0)},
          {"maxBytes", Integer(1, 128 * 1024, 64 * 1024)}}),
      Tool("ida_ui_cursor", "Read the cursor address and operand of the current IDA view without changing it.", {}),
      Tool("ida_ui_selection", "Read the linear address range selected in the last active IDA address view without changing it.", {}),
      Tool("ida_ui_highlight", "Read the identifier currently highlighted in the active IDA view without changing it.", {}),
      Tool("ida_ui_view", "Identify the active IDA widget kind and title without changing it.", {}),
      Tool("ida_address_boundaries", "Get bounded boundaries enclosing an address: decoded item, containing segment, function, function chunk, and basic block.", {
          {"address", Address()}}),
      Tool("ida_analysis_trace_argument_callers", "Trace argument parameters upward through known direct callers with separate contexts and explicit ABI/recursion boundaries.", {
          {"callAddress", Address()}, {"argumentIndex", Integer(0, 255, 0)},
          {"maxDepth", Integer(0, 5, 2)}, {"maxContexts", Integer(1, 64, 16)},
          {"maxCallers", Integer(1, 32, 8)}, {"maxNodes", Integer(1, 4000, 1000)},
          {"maxWork", Integer(1, 1000000, 100000)}}),
      Tool("ida_analysis_trace_argument", "Trace a zero-based call argument through function-local microcode; report unknown sources and truncation.", {
          {"callAddress", Address()}, {"argumentIndex", Integer(0, 255, 0)},
          {"maxNodes", Integer(1, 1000, 200)}, {"maxWork", Integer(1, 100000, 20000)},
          {"maxGuards", Integer(1, 128, 32)}}),
      Tool("ida_analysis_guard_evidence", "Read argument dependencies and required CFG branches; these are evidence, not proof of safety or feasible paths.", {
          {"callAddress", Address()}, {"argumentIndex", Integer(0, 255, 0)},
          {"maxNodes", Integer(1, 1000, 200)}, {"maxWork", Integer(1, 100000, 20000)},
          {"maxGuards", Integer(1, 128, 32)}}),
  };
  return definitions;
}

} // namespace ida_agent::ai
