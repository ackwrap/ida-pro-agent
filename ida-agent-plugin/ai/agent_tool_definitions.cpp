#include "ai/agent_tool_registry.hpp"

namespace ida_agent::ai
{
namespace
{
using Json = nlohmann::json;

Json Text(std::size_t maximum, std::string default_value = {}, std::size_t minimum = 0)
{
  Json schema{{"type", "string"}, {"maxLength", maximum}, {"default", std::move(default_value)}};
  if ( minimum != 0 ) schema["minLength"] = minimum;
  return schema;
}

Json Address(bool sentinel = false, const char *sentinel_default = "")
{
  return {
      {"type", "string"},
      {"pattern", sentinel ? "^(|0x[0-9A-Fa-f]{1,16})$" : "^0x[0-9A-Fa-f]{1,16}$"},
      {"default", sentinel ? sentinel_default : "0x0"},
  };
}

Json Integer(std::uint32_t minimum, std::uint32_t maximum, std::uint32_t value)
{
  return {{"type", "integer"}, {"minimum", minimum}, {"maximum", maximum}, {"default", value}};
}

Json Enum(std::initializer_list<const char *> values, const char *value)
{
  Json items = Json::array();
  for ( const char *item : values ) items.push_back(item);
  return {{"type", "string"}, {"enum", std::move(items)}, {"default", value}};
}

Json Strict(std::initializer_list<std::pair<const char *, Json>> fields)
{
  Json properties = Json::object();
  Json required = Json::array();
  for ( const auto &field : fields )
  {
    properties[field.first] = field.second;
    required.push_back(field.first);
  }
  return {
      {"type", "object"},
      {"additionalProperties", false},
      {"properties", std::move(properties)},
      {"required", std::move(required)},
  };
}

AgentToolDefinition Tool(
    const char *name,
    const char *description,
    std::initializer_list<std::pair<const char *, Json>> fields)
{
  return {name, description, Strict(fields)};
}

Json PageFields()
{
  return Strict({
      {"address", Address()},
      {"offset", Integer(0, 1000000, 0)},
      {"limit", Integer(1, 100, 20)},
  });
}

AgentToolDefinition PageTool(const char *name, const char *description)
{
  return {name, description, PageFields()};
}
} // namespace

const std::vector<AgentToolDefinition> &AgentToolDefinitions()
{
  static const std::vector<AgentToolDefinition> definitions = []
  {
    std::vector<AgentToolDefinition> result{
      Tool("ida_symbol_exports", "List exported symbols from the current IDA database.", {
          {"name", Text(1024)}, {"limit", Integer(1, 100, 50)}}),
      Tool("ida_string_search", "Search strings in the existing IDA string list. Set refresh=true only when a fresh list is needed; rebuilding may be slow.", {
          {"query", Text(1024, "", 1)}, {"minimumLength", Integer(1, 1024, 4)},
          {"refresh", {{"type", "boolean"}, {"default", false}}},
          {"limit", Integer(1, 100, 50)}}),
      Tool("ida_function_get", "Get bounded metadata for the function containing an address.", {
          {"address", Address()}}),
      Tool("ida_decompile", "Decompile one bounded page of the function containing an address.", {
          {"address", Address()}, {"offset", Integer(0, 16777216, 0)},
          {"maxBytes", Integer(4, 65536, 16384)}}),
      Tool("ida_xref_query", "Query a bounded set of incoming or outgoing cross-references.", {
          {"address", Address()}, {"direction", Enum({"incoming", "outgoing"}, "incoming")},
          {"category", Enum({"all", "code", "data"}, "all")},
          {"includeFlow", {{"type", "boolean"}, {"default", false}}},
          {"limit", Integer(1, 100, 50)}}),
      Tool("ida_memory_read", "Read bounded database memory as bytes, string, integer, or pointer.", {
          {"address", Address()}, {"format", Enum({"bytes", "string", "integer", "pointer"}, "bytes")},
          {"length", Integer(0, 4096, 0)},
          {"widthBits", {{"type", "integer"}, {"enum", Json::array({0, 8, 16, 32, 64})}, {"default", 0}}}}),

      Tool("ida_database_info", "Get architecture, address range, and segment summary for the current database.", {}),
      Tool("ida_database_segments", "List a bounded first page of database segments without exposing a cursor.", {
          {"name", Text(256)}, {"limit", Integer(1, 100, 20)}}),
      Tool("ida_database_entry_points", "List a bounded first page of entry points without exposing a cursor.", {
          {"name", Text(256)}, {"type", Enum({"", "entry", "export"}, "")},
          {"limit", Integer(1, 100, 20)}}),
      Tool("ida_function_search", "Find functions by exactly one fixed selector; name searches return only the first page.", {
          {"mode", Enum({"name", "address"}, "name")}, {"name", Text(256)},
          {"address", Address(true)}, {"limit", Integer(1, 100, 20)}}),
      PageTool("ida_function_disassemble", "Disassemble a bounded page of a function."),
      PageTool("ida_function_basic_blocks", "List a bounded page of function basic blocks."),
      PageTool("ida_function_callers", "List a bounded page of callers for a function."),
      PageTool("ida_function_callees", "List a bounded page of callees for a function."),
      PageTool("ida_function_chunks", "List a bounded page of function chunks."),
      Tool("ida_function_call_graph", "Build a bounded read-only call graph from fixed roots.", {
          {"roots", {{"type", "array"}, {"items", Address()}, {"minItems", 1}, {"maxItems", 16}}},
          {"direction", Enum({"callers", "callees", "both"}, "callees")},
          {"maxDepth", Integer(0, 5, 2)}, {"maxNodes", Integer(1, 500, 100)},
          {"maxEdges", Integer(1, 1000, 200)}, {"perFunction", Integer(1, 100, 100)}}),
      Tool("ida_instruction_get", "Decode one instruction at an address.", {{"address", Address()}}),
      Tool("ida_fixup_get", "Get the fixup whose source is at an address.", {{"address", Address()}}),
      Tool("ida_switch_get", "Get switch metadata at an address.", {{"address", Address()}}),
      Tool("ida_symbol_imports", "List a bounded first page of imports without exposing a cursor.", {
          {"module", Text(256)}, {"name", Text(256)}, {"limit", Integer(1, 100, 20)}}),
      Tool("ida_symbol_search", "Search a bounded first page of symbols without exposing a cursor.", {
          {"name", Text(256)}, {"kind", Enum({"", "global", "data", "label"}, "")},
          {"limit", Integer(1, 100, 20)}}),
      Tool("ida_string_search_regex", "Search strings with a bounded regular expression, returning only the first page. Reuse the existing list unless refresh=true; rebuilding may be slow.", {
          {"pattern", Text(256, "", 1)}, {"minimumLength", Integer(1, 4096, 4)},
          {"refresh", {{"type", "boolean"}, {"default", false}}},
          {"limit", Integer(1, 100, 20)}}),
      Tool("ida_memory_search_bytes", "Search a bounded address range for an IDA byte pattern.", {
          {"pattern", Text(1024, "", 1)}, {"start", Address()}, {"end", Address()},
          {"limit", Integer(1, 100, 20)}}),
      Tool("ida_instruction_search", "Search a bounded address range by mnemonic and operand filters.", {
          {"start", Address()}, {"end", Address()}, {"mnemonic", Text(256)},
          {"operand", Text(256)}, {"limit", Integer(1, 100, 20)}}),
      Tool("ida_signature_make", "Create a bounded read-only byte signature; empty address fields are sentinels for the unused mode.", {
          {"mode", Enum({"address", "function", "range"}, "address")}, {"address", Address(true, "0x0")},
          {"start", Address(true)}, {"end", Address(true)},
          {"format", Enum({"ida", "x64dbg", "mask", "bitmask"}, "ida")},
          {"wildcardOperands", {{"type", "boolean"}, {"default", true}}},
          {"maxLength", Integer(1, 1000, 1000)}}),
      Tool("ida_patch_assemble", "Assemble an instruction and return bytes only; this tool never patches the database.", {
          {"address", Address()}, {"instruction", Text(4096, "", 1)}}),
      Tool("ida_type_search", "Search a bounded page of local types from an ordinal.", {
          {"name", Text(256)},
          {"kind", Enum({"", "any", "typedef", "enum", "function", "pointer", "array", "udt", "struct", "union", "other"}, "")},
          {"ordinal", Integer(1, 1000000, 1)}, {"limit", Integer(1, 100, 20)}}),
      Tool("ida_type_get", "Get bounded details for a named local type.", {{"name", Text(256, "", 1)}}),
      Tool("ida_type_infer", "Infer the type at an address.", {{"address", Address()}}),
      Tool("ida_type_read_value", "Read a bounded value using a required named type.", {
          {"address", Address()}, {"name", Text(256, "", 1)}, {"maxBytes", Integer(1, 65536, 4096)}}),
      Tool("ida_type_read_struct", "Read a bounded structure; an empty name requests the type at the address.", {
          {"address", Address()}, {"name", Text(256)}, {"maxBytes", Integer(1, 65536, 4096)}}),
      Tool("ida_global_value", "Read one bounded global selected by address or name; the unused selector is an empty sentinel.", {
          {"selector", Enum({"address", "name"}, "address")}, {"address", Address(true, "0x0")},
          {"name", Text(256)}, {"maxBytes", Integer(1, 65536, 4096)}}),
      Tool("ida_xref_struct_field", "Find bounded references to a named structure field.", {
          {"type", Text(1024, "", 1)}, {"field", Text(1024, "", 1)},
          {"limit", Integer(1, 1000, 100)}}),
    };
    const auto &extended = ExtendedAgentToolDefinitions();
    result.insert(result.end(), extended.begin(), extended.end());
    return result;
  }();
  return definitions;
}

} // namespace ida_agent::ai
