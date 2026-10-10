#include "ai/agent_tool_registry.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <optional>
#include <stdexcept>
#include <chrono>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

void RunAgentPromptTests();
void RunAgentFileRegistryTests();

namespace
{

using ida_agent::ai::AgentToolCall;
using ida_agent::ai::AgentToolRegistry;
using Json = nlohmann::json;

void Require(bool condition, const char *message)
{
  if ( !condition )
    throw std::runtime_error(message);
}

AgentToolCall Call(std::string name, std::string arguments)
{
  return {"call-1", std::move(name), std::move(arguments)};
}

Json ChangeOperation(
    std::string kind = "rename",
    Json address = "0x401000",
    std::string value = "renamed")
{
  return {{"kind", std::move(kind)}, {"address", std::move(address)},
      {"value", std::move(value)}, {"expected", nullptr}, {"repeatable", false},
      {"offset", nullptr}, {"size", nullptr}, {"subject", nullptr}};
}

void RequireInvalid(AgentToolRegistry &registry, AgentToolCall call)
{
  const auto result = registry.Invoke(call);
  Require(!result.success, "invalid call succeeded");
  Require(result.output.empty(), "invalid call exposed output");
  Require(!result.safe_message.empty(), "invalid call omitted safe message");
}

void TestDefinitions()
{
  const auto &definitions = ida_agent::ai::AgentToolDefinitions();
  Require(definitions.size() == 79, "tool count mismatch");
  Require(definitions[0].name == "ida_symbol_exports", "export order mismatch");
  Require(definitions[1].name == "ida_string_search", "string order mismatch");
  Require(definitions[2].name == "ida_function_get", "function order mismatch");
  Require(definitions[3].name == "ida_decompile", "decompile order mismatch");
  Require(definitions[4].name == "ida_xref_query", "xref order mismatch");
  Require(definitions[5].name == "ida_memory_read", "memory order mismatch");
  const std::vector<std::string> added{
      "ida_database_info", "ida_database_segments", "ida_database_entry_points",
      "ida_function_search", "ida_function_disassemble", "ida_function_basic_blocks",
      "ida_function_callers", "ida_function_callees", "ida_function_chunks",
      "ida_function_call_graph", "ida_instruction_get", "ida_fixup_get", "ida_switch_get",
      "ida_symbol_imports", "ida_symbol_search", "ida_string_search_regex",
      "ida_memory_search_bytes", "ida_instruction_search", "ida_signature_make",
      "ida_patch_assemble", "ida_type_search", "ida_type_get", "ida_type_infer",
      "ida_type_read_value", "ida_type_read_struct", "ida_global_value",
      "ida_xref_struct_field",
      "ida_fixup_list", "ida_exception_try_blocks", "ida_analysis_status",
      "ida_analysis_problems", "ida_listing_search", "ida_listing_search_text",
      "ida_signature_xrefs", "ida_function_stack_frame", "ida_source_files",
      "ida_source_lines", "ida_name_demangle", "ida_comment_get",
      "ida_bookmark_list", "ida_type_xrefs", "ida_decompiler_locals",
      "ida_decompiler_ctree", "ida_decompiler_local_xrefs", "ida_debugger_backends", "ida_debugger_configuration", "ida_debugger_processes", "ida_debugger_info",
      "ida_debugger_breakpoint_list", "ida_debugger_registers",
      "ida_debugger_stacktrace", "ida_debugger_memory_read", "ida_changeset_audit",
      "ida_debugger_threads", "ida_debugger_modules", "ida_changeset_preview",
      "ida_database_survey", "ida_function_profile", "ida_function_export",
      "ida_function_analyze", "ida_analysis_component",
      "ida_analysis_trace_data_flow", "ida_file_list", "ida_file_stat", "ida_file_read",
      "ida_ui_cursor", "ida_ui_selection", "ida_ui_highlight", "ida_ui_view",
      "ida_address_boundaries",
  };
  for ( std::size_t index = 0; index < added.size(); ++index )
    Require(definitions[index + 6].name == added[index], "fixed tool order mismatch");
  for ( const auto &definition : definitions )
  {
    Require(definition.parameters.at("type") == "object", "schema type mismatch");
    Require(!definition.parameters.at("additionalProperties").get<bool>(), "schema is not strict");
    const Json &properties = definition.parameters.at("properties");
    const Json &required = definition.parameters.at("required");
    Require(required.size() == properties.size(), "strict schema omitted required fields");
    for ( const auto &property : properties.items() )
      Require(std::find(required.begin(), required.end(), property.key()) != required.end(),
              "strict schema property is optional");
  }
  const Json &exports = definitions[0].parameters.at("properties");
  Require(exports.at("name").at("maxLength") == 1024, "export name limit mismatch");
  Require(exports.at("limit").at("minimum") == 1, "export limit minimum mismatch");
  Require(exports.at("limit").at("maximum") == 100, "export limit maximum mismatch");
  Require(exports.at("limit").at("default") == 50, "export limit default mismatch");
  const Json &strings = definitions[1].parameters;
  Require(strings.at("required") == Json::array({"query", "minimumLength", "refresh", "limit"}),
          "string strict requirements mismatch");
  Require(strings.at("properties").at("query").at("minLength") == 1, "query minimum mismatch");
  Require(strings.at("properties").at("query").at("maxLength") == 1024, "query maximum mismatch");
  Require(strings.at("properties").at("minimumLength").at("default") == 4, "string default mismatch");
  Require(definitions[2].parameters.at("required") == Json::array({"address"}),
          "function requirements mismatch");
  Require(definitions[3].parameters.at("properties").at("maxBytes").at("maximum") == 65536,
          "decompile byte limit mismatch");
  Require(definitions[4].parameters.at("properties").at("limit").at("maximum") == 100,
          "xref limit mismatch");
  Require(definitions[5].parameters.at("properties").at("length").at("maximum") == 4096,
          "memory length mismatch");
  Require(definitions[6].parameters.at("required").empty(), "database info schema mismatch");
  Require(definitions[15].parameters.at("properties").at("roots").at("maxItems") == 16,
          "call graph roots limit mismatch");
  Require(definitions[24].parameters.at("properties").at("address").at("default") == "0x0",
          "signature sentinel mismatch");
  Require(definitions[25].description.find("never patches") != std::string::npos,
          "assemble read-only contract missing");
  for ( std::size_t index = 33; index < definitions.size(); ++index )
    for ( const auto &property : definitions[index].parameters.at("properties").items() )
      Require(property.value().contains("default"), "extended schema property omitted default");
  Require(std::none_of(definitions.begin(), definitions.end(), [](const auto &definition)
          { return definition.name.find("method") != std::string::npos || definition.name == "ida_generic"; }),
      "generic method tool was registered");
  const Json &preview = definitions[61].parameters.at("properties").at("operations");
  Require(preview.at("minItems") == 1 && preview.at("maxItems") == 100,
          "preview operation bounds mismatch");
  const Json &operation = preview.at("items");
  Require(!operation.at("additionalProperties").get<bool>()
              && operation.at("required").size() == operation.at("properties").size(),
          "preview operation schema is not strict");
  Require(operation.at("properties").at("kind").at("enum").size() == 38,
          "preview operation kinds diverged from effect apply");
  Require(definitions[67].parameters.at("properties").at("maxEdges").at("maximum") == 2000,
          "trace edge bound mismatch");
  Require(definitions[68].parameters.at("properties").at("path").at("default") == ""
      && definitions[70].parameters.at("properties").at("maxBytes").at("maximum") == 131072,
      "file schema bounds mismatch");
}

void TestFixedReadOnlyBatch()
{
  ida_agent::ai::AgentToolInvokers invokers;
  int database_calls = 0, function_calls = 0, readonly_calls = 0;
  int inventory_calls = 0, search_calls = 0, type_calls = 0;
  int p1_calls = 0, debugger_calls = 0, changeset_calls = 0, composite_calls = 0;
  invokers.database_info = [&database_calls]()
  {
    ++database_calls;
    return Json{{"database", "sample"}};
  };
  invokers.database_segments = [&database_calls](const ida_agent::ai::AgentListArguments &args)
  {
    Require(args.first == ".text" && args.limit == 7, "database dispatch mismatch");
    ++database_calls;
    return Json{{"items", Json::array({Json{{"name", ".text"}}})},
                {"nextCursor", "must-not-escape"}, {"hasMore", true}};
  };
  invokers.function_search = [&function_calls](const ida_agent::ai::AgentFunctionSearchArguments &args)
  {
    Require(args.mode == "address" && args.address == 0x401000 && args.name.empty(),
            "function search dispatch mismatch");
    ++function_calls;
    return Json{{"items", Json::array({Json{{"entryAddress", "0x401000"}}})},
                {"nextCursor", "must-not-escape"}, {"hasMore", false}};
  };
  invokers.function_disassemble = [&function_calls](const ida_agent::ai::AgentPageArguments &args)
  {
    Require(args.address == 0x401000 && args.offset == 2 && args.limit == 3,
            "function page dispatch mismatch");
    ++function_calls;
    return Json{{"items", Json::array()}, {"nextOffset", nullptr}, {"hasMore", false}};
  };
  invokers.instruction_get = [&readonly_calls](std::uint64_t address)
  {
    Require(address == 0x401000, "readonly dispatch mismatch");
    ++readonly_calls;
    return Json{{"address", "0x401000"}, {"text", "ret"}};
  };
  invokers.function_chunks = [&readonly_calls](const ida_agent::ai::AgentPageArguments &args)
  {
    Require(args.limit == 4, "readonly page dispatch mismatch");
    ++readonly_calls;
    return Json{{"items", Json::array()}, {"hasMore", false}};
  };
  invokers.symbol_imports = [&inventory_calls](const ida_agent::ai::AgentListArguments &args)
  {
    Require(args.first == "kernel32" && args.second == "CreateFileW" && args.limit == 5,
            "inventory dispatch mismatch");
    ++inventory_calls;
    return Json{{"items", Json::array()}, {"nextCursor", "secret"}, {"hasMore", true}};
  };
  invokers.string_search_regex = [&inventory_calls](const ida_agent::ai::AgentRegexArguments &args)
  {
    Require(args.pattern == "hello.*" && args.minimum_length == 6 && args.limit == 8,
            "regex dispatch mismatch");
    ++inventory_calls;
    return Json{{"items", Json::array()}, {"hasMore", false}};
  };
  invokers.memory_search_bytes = [&search_calls](const ida_agent::ai::AgentByteSearchArguments &args)
  {
    Require(args.pattern == "48 8B ??" && args.start == 0x400000 && args.end == 0x500000,
            "search dispatch mismatch");
    ++search_calls;
    return Json{{"items", Json::array({"0x401000"})}, {"nextAddress", "0x402000"}, {"hasMore", true}};
  };
  invokers.patch_assemble = [&search_calls](const ida_agent::ai::AgentAssemblyArguments &args)
  {
    Require(args.address == 0x401000 && args.instruction == "nop", "assemble dispatch mismatch");
    ++search_calls;
    return Json{{"address", "0x401000"}, {"bytes", "90"}, {"size", 1}};
  };
  invokers.type_search = [&type_calls](const ida_agent::ai::AgentTypeSearchArguments &args)
  {
    Require(args.kind == "struct" && args.ordinal == 1 && args.limit == 9,
            "type dispatch mismatch");
    ++type_calls;
    return Json{{"items", Json::array()}, {"nextOrdinal", 2}, {"hasMore", true}};
  };
  invokers.global_value = [&type_calls](const ida_agent::ai::AgentGlobalValueArguments &args)
  {
    Require(args.selector == "name" && args.address == 0 && args.name == "g_value"
                && args.max_bytes == 32,
            "global value dispatch mismatch");
    ++type_calls;
    return Json{{"symbol", "g_value"}, {"value", "1"}};
  };
  invokers.xref_struct_field = [&type_calls](const ida_agent::ai::AgentListArguments &args)
  {
    Require(args.first == "HEADER" && args.second == "size" && args.limit == 10,
            "field xref dispatch mismatch");
    ++type_calls;
    return Json{{"items", Json::array({"0x401020"})}, {"truncated", false}};
  };
  invokers.fixup_list = [&readonly_calls](const ida_agent::ai::AgentOptionalRangeArguments &args)
  {
    Require(args.has_range && args.start == 0x401000 && args.end == 0x402000
                && args.limit == 6,
            "extended readonly dispatch mismatch");
    ++readonly_calls;
    return Json{{"items", Json::array()}, {"nextAddress", "0x401100"}, {"hasMore", true}};
  };
  invokers.listing_search_text = [&search_calls](const ida_agent::ai::AgentListingArguments &args)
  {
    Require(args.mode == "regex" && args.pattern == "call.*" && args.include_disassembly
                && !args.include_comments && args.limit == 4,
            "extended search dispatch mismatch");
    ++search_calls;
    return Json{{"items", Json::array()}, {"nextCursor", "private"}, {"hasMore", false}};
  };
  invokers.function_stack_frame = [&type_calls](std::uint64_t address)
  {
    Require(address == 0x401000, "stack frame dispatch mismatch");
    ++type_calls;
    return Json{{"entryAddress", "0x401000"}, {"variables", Json::array()}};
  };
  invokers.source_files = [&p1_calls](std::uint32_t limit)
  {
    Require(limit == 11, "P1 dispatch mismatch");
    ++p1_calls;
    return Json{{"items", Json::array()}, {"nextCursor", 11}, {"hasMore", true}};
  };
  invokers.debugger_registers = [&debugger_calls](const ida_agent::ai::AgentDebuggerRegistersArguments &args)
  {
    Require(args.thread_mode == "specified" && args.thread_ids == std::vector<std::int64_t>{7}
                && args.register_mode == "named" && args.names == std::vector<std::string>{"rip"},
            "debugger dispatch mismatch");
    ++debugger_calls;
    return Json{{"items", Json::array()}};
  };
  invokers.changeset_audit = [&changeset_calls](const ida_agent::ai::AgentAuditArguments &args)
  {
    Require(args.offset == 2 && args.limit == 12, "changeset audit dispatch mismatch");
    ++changeset_calls;
    return Json{{"items", Json::array()}};
  };
  invokers.debugger_threads = [&p1_calls](std::uint32_t limit)
  {
    Require(limit == 13, "debugger threads dispatch mismatch");
    ++p1_calls;
    return Json{{"items", Json::array({7})}, {"nextCursor", 1}, {"hasMore", true}};
  };
  invokers.debugger_modules = [&p1_calls](std::uint32_t limit)
  {
    Require(limit == 14, "debugger modules dispatch mismatch");
    ++p1_calls;
    return Json{{"items", Json::array({Json{{"name", "sample.exe"}}})},
        {"nextCursor", 1}, {"hasMore", false}};
  };
  invokers.changeset_preview = [&changeset_calls](
      const ida_agent::ai::AgentChangeSetPreviewArguments &args)
  {
    Require(args.operations.size() == 1
                && args.operations[0].kind == ida_agent::services::ChangeKind::Rename
                && args.operations[0].address == 0x401000
                && args.operations[0].value == "renamed",
            "changeset preview dispatch mismatch");
    ++changeset_calls;
    return Json{{"previewId", "preview-1"},
        {"items", Json::array({Json{{"index", 0}, {"before", "old"},
            {"after", "renamed"}, {"conflict", false}}})}, {"applicable", true}};
  };
  invokers.database_survey = [&composite_calls](
      const ida_agent::ai::AgentDatabaseSurveyArguments &args)
  {
    Require(args.mode == "minimal" && args.budget == 9, "database survey dispatch mismatch");
    ++composite_calls;
    return Json{{"mode", args.mode}, {"truncated", false}};
  };
  invokers.function_profile = [&composite_calls](
      const ida_agent::ai::AgentFunctionProfileArguments &args)
  {
    Require(args.name == "sub_" && args.minimum_size == 4 && args.maximum_size == 64
                && args.library && *args.library && !args.thunk
                && args.include_prototype && args.sample_limit == 2 && args.limit == 3,
            "function profile dispatch mismatch");
    ++composite_calls;
    return Json{{"items", Json::array()}, {"hasMore", false}};
  };
  invokers.function_export = [&composite_calls](
      const ida_agent::ai::AgentFunctionExportArguments &args)
  {
    Require(args.addresses == std::vector<std::uint64_t>{0x401000, 0x402000}
                && args.format == "prototypes" && args.max_bytes == 4096,
            "function export dispatch mismatch");
    ++composite_calls;
    return Json{{"format", args.format}, {"content", "void f();"}, {"truncated", false}};
  };
  invokers.function_analyze = [&composite_calls](
      const ida_agent::ai::AgentFunctionAnalyzeArguments &args)
  {
    Require(args.addresses == std::vector<std::uint64_t>{0x401000}
                && args.sections == std::vector<std::string>{"overview", "metrics"}
                && args.per_section == 5 && args.decompile_bytes == 2048,
            "function analyze dispatch mismatch");
    ++composite_calls;
    return Json{{"items", Json::array()}};
  };
  invokers.analysis_component = [&composite_calls](
      const ida_agent::ai::AgentAnalysisComponentArguments &args)
  {
    Require(args.roots == std::vector<std::uint64_t>{0x401000}
                && args.max_depth == 2 && args.max_nodes == 20 && args.max_edges == 30
                && args.per_function == 4 && args.shared_limit == 6,
            "analysis component dispatch mismatch");
    ++composite_calls;
    return Json{{"members", Json::array()}, {"truncated", false}};
  };
  invokers.analysis_trace_data_flow = [&composite_calls](
      const ida_agent::ai::AgentTraceDataFlowArguments &args)
  {
    Require(args.address == 0x401000 && args.direction == "outgoing"
                && args.max_depth == 3 && args.max_nodes == 40 && args.max_edges == 50,
            "trace data flow dispatch mismatch");
    ++composite_calls;
    return Json{{"model", "xref_bfs"}, {"nodes", Json::array()}, {"edges", Json::array()}};
  };

  auto registry = AgentToolRegistry::ForTesting(std::move(invokers));
  registry.SetAvailable(true);
  Require(registry.Invoke(Call("ida_database_info", "{}")).success, "database info dispatch failed");
  const auto segments = registry.Invoke(Call("ida_database_segments", R"({"name":".text","limit":7})"));
  Require(segments.success && !Json::parse(segments.output).contains("nextCursor"), "database page leaked cursor");
  const auto function = registry.Invoke(Call("ida_function_search", R"({"mode":"address","name":"","address":"0x401000","limit":20})"));
  Require(function.success && !Json::parse(function.output).contains("nextCursor"), "function search failed");
  Require(registry.Invoke(Call("ida_function_disassemble", R"({"address":"0x401000","offset":2,"limit":3})")).success,
          "function page failed");
  Require(registry.Invoke(Call("ida_instruction_get", R"({"address":"0x401000"})")).success,
          "readonly address failed");
  Require(registry.Invoke(Call("ida_function_chunks", R"({"address":"0x401000","offset":0,"limit":4})")).success,
          "readonly page failed");
  const auto imports = registry.Invoke(Call("ida_symbol_imports", R"({"module":"kernel32","name":"CreateFileW","limit":5})"));
  Require(imports.success && !Json::parse(imports.output).contains("nextCursor"), "inventory cursor leaked");
  Require(registry.Invoke(Call("ida_string_search_regex", R"({"pattern":"hello.*","minimumLength":6,"limit":8})")).success,
          "regex dispatch failed");
  const auto bytes = registry.Invoke(Call("ida_memory_search_bytes", R"({"pattern":"48 8B ??","start":"0x400000","end":"0x500000","limit":20})"));
  Require(bytes.success && !Json::parse(bytes.output).contains("nextAddress"), "search continuation leaked");
  Require(registry.Invoke(Call("ida_patch_assemble", R"({"address":"0x401000","instruction":"nop"})")).success,
          "read-only assemble failed");
  Require(registry.Invoke(Call("ida_type_search", R"({"name":"","kind":"struct","ordinal":1,"limit":9})")).success,
          "type search failed");
  Require(registry.Invoke(Call("ida_global_value", R"({"selector":"name","address":"","name":"g_value","maxBytes":32})")).success,
          "global value failed");
  Require(registry.Invoke(Call("ida_xref_struct_field", R"({"type":"HEADER","field":"size","limit":10})")).success,
          "field xref failed");
  const auto fixups = registry.Invoke(Call("ida_fixup_list", R"({"start":"0x401000","end":"0x402000","limit":6})"));
  Require(fixups.success && !Json::parse(fixups.output).contains("nextAddress"),
          "fixup continuation leaked");
  const auto listing = registry.Invoke(Call("ida_listing_search_text", R"({"start":"0x401000","end":"0x402000","mode":"regex","pattern":"call.*","includeDisassembly":true,"includeComments":false,"limit":4})"));
  Require(listing.success && !Json::parse(listing.output).contains("nextCursor"),
          "listing cursor leaked");
  Require(registry.Invoke(Call("ida_function_stack_frame", R"({"address":"0x401000"})")).success,
          "stack frame dispatch failed");
  const auto sources = registry.Invoke(Call("ida_source_files", R"({"limit":11})"));
  Require(sources.success && !Json::parse(sources.output).contains("nextCursor"),
          "source cursor leaked");
  Require(registry.Invoke(Call("ida_debugger_registers", R"({"threadMode":"specified","threadIds":[7],"registerMode":"named","names":["rip"]})")).success,
          "debugger registers dispatch failed");
  Require(registry.Invoke(Call("ida_changeset_audit", R"({"offset":2,"limit":12})")).success,
          "changeset audit dispatch failed");
  const auto threads = registry.Invoke(Call("ida_debugger_threads", R"({"limit":13})"));
  Require(threads.success && !Json::parse(threads.output).contains("nextCursor"),
          "debugger threads cursor leaked");
  const auto modules = registry.Invoke(Call("ida_debugger_modules", R"({"limit":14})"));
  Require(modules.success && !Json::parse(modules.output).contains("nextCursor"),
          "debugger modules cursor leaked");
  Require(registry.Invoke(Call("ida_changeset_preview",
      Json{{"operations", Json::array({ChangeOperation()})}}.dump())).success,
      "changeset preview dispatch failed");
  Require(registry.Invoke(Call("ida_database_survey", R"({"mode":"minimal","budget":9})")).success,
          "database survey dispatch failed");
  Require(registry.Invoke(Call("ida_function_profile", R"({"name":"sub_","minSize":4,"maxSize":64,"library":true,"thunk":null,"includePrototype":true,"sampleLimit":2,"limit":3})")).success,
          "function profile dispatch failed");
  Require(registry.Invoke(Call("ida_function_export", R"({"addresses":["0x401000","0x402000"],"format":"prototypes","maxBytes":4096})")).success,
          "function export dispatch failed");
  Require(registry.Invoke(Call("ida_function_analyze", R"({"addresses":["0x401000"],"sections":["overview","metrics"],"perSection":5,"decompileBytes":2048})")).success,
          "function analyze dispatch failed");
  Require(registry.Invoke(Call("ida_analysis_component", R"({"roots":["0x401000"],"maxDepth":2,"maxNodes":20,"maxEdges":30,"perFunction":4,"sharedLimit":6})")).success,
          "analysis component dispatch failed");
  Require(registry.Invoke(Call("ida_analysis_trace_data_flow", R"({"address":"0x401000","direction":"outgoing","maxDepth":3,"maxNodes":40,"maxEdges":50})")).success,
          "trace data flow dispatch failed");
  Require(database_calls == 2 && function_calls == 2 && readonly_calls == 3
              && inventory_calls == 2 && search_calls == 3 && type_calls == 4
              && p1_calls == 3 && debugger_calls == 1 && changeset_calls == 2
              && composite_calls == 6,
          "fixed service family call count mismatch");

  RequireInvalid(registry, Call("ida_database_info", R"({"extra":true})"));
  RequireInvalid(registry, Call("ida_function_search", R"({"mode":"address","name":"bad","address":"0x401000","limit":20})"));
  RequireInvalid(registry, Call("ida_function_disassemble", R"({"address":"0x401000","offset":0,"limit":101})"));
  RequireInvalid(registry, Call("ida_function_call_graph", R"({"roots":[],"direction":"callees","maxDepth":2,"maxNodes":100,"maxEdges":200,"perFunction":100})"));
  RequireInvalid(registry, Call("ida_signature_make", R"({"mode":"range","address":"0x401000","start":"0x401000","end":"0x401010","format":"ida","wildcardOperands":true,"maxLength":10})"));
  RequireInvalid(registry, Call("ida_global_value", R"({"selector":"name","address":"","name":"","maxBytes":32})"));
  RequireInvalid(registry, Call("ida_type_read_value", R"({"address":"0x401000","name":"T","maxBytes":65537})"));
  RequireInvalid(registry, Call("ida_fixup_list", R"({"start":"0x401000","end":"","limit":20})"));
  RequireInvalid(registry, Call("ida_fixup_list", R"({"start":"0x402000","end":"0x401000","limit":20})"));
  RequireInvalid(registry, Call("ida_listing_search_text", Json{{"start", "0x401000"}, {"end", "0x402000"}, {"mode", "regex"}, {"pattern", std::string(257, 'a')}, {"includeDisassembly", true}, {"includeComments", false}, {"limit", 20}}.dump()));
  RequireInvalid(registry, Call("ida_name_demangle", R"({"selector":"name","address":"0x401000","name":"symbol"})"));
  RequireInvalid(registry, Call("ida_debugger_registers", R"({"threadMode":"specified","threadIds":[],"registerMode":"all","names":[]})"));
  RequireInvalid(registry, Call("ida_debugger_registers", R"({"threadMode":"current","threadIds":[],"registerMode":"named","names":["rip","rip"]})"));
  RequireInvalid(registry, Call("ida_debugger_stacktrace", R"({"threadId":-1,"limit":100})"));
  RequireInvalid(registry, Call("ida_debugger_memory_read", R"({"address":"0x401000","length":0})"));
  RequireInvalid(registry, Call("ida_changeset_audit", R"({"offset":0,"limit":1001})"));
  RequireInvalid(registry, Call("ida_debugger_threads", R"({"limit":101})"));
  Json extra_operation = ChangeOperation();
  extra_operation["extra"] = true;
  RequireInvalid(registry, Call("ida_changeset_preview",
      Json{{"operations", Json::array({extra_operation})}}.dump()));
  RequireInvalid(registry, Call("ida_changeset_preview",
      Json{{"operations", Json::array({ChangeOperation("type.declare", "0x401000", "int T;")})}}.dump()));
  RequireInvalid(registry, Call("ida_database_survey", R"({"mode":"full","budget":2})"));
  RequireInvalid(registry, Call("ida_function_profile", R"({"name":"","minSize":65,"maxSize":64,"library":null,"thunk":null,"includePrototype":false,"sampleLimit":0,"limit":20})"));
  RequireInvalid(registry, Call("ida_function_profile", R"({"name":"","minSize":0,"maxSize":64,"library":null,"thunk":null,"includePrototype":false,"sampleLimit":8,"limit":50})"));
  RequireInvalid(registry, Call("ida_function_export", R"({"addresses":[],"format":"json","maxBytes":4096})"));
  RequireInvalid(registry, Call("ida_function_analyze", R"({"addresses":["0x401000"],"sections":["overview","overview"],"perSection":5,"decompileBytes":2048})"));
  RequireInvalid(registry, Call("ida_analysis_component", R"({"roots":["0x401000"],"maxDepth":6,"maxNodes":20,"maxEdges":30,"perFunction":4,"sharedLimit":6})"));
  RequireInvalid(registry, Call("ida_analysis_trace_data_flow", R"({"address":"0x401000","direction":"sideways","maxDepth":3,"maxNodes":40,"maxEdges":50})"));
  RequireInvalid(registry, Call("ida_method_call", R"({"method":"debugger.start","params":{}})"));
  RequireInvalid(registry, Call("ida_debugger_start", R"({})"));
  Require(p1_calls == 3 && debugger_calls == 1 && changeset_calls == 2
              && composite_calls == 6,
          "invalid or generic call produced a side effect");

  ida_agent::ai::AgentToolInvokers oversized_invokers;
  oversized_invokers.database_info = []()
  {
    return Json{{"value", std::string(ida_agent::ai::MaxAgentToolResultBytes, 'x')}};
  };
  auto oversized = AgentToolRegistry::ForTesting(std::move(oversized_invokers));
  oversized.SetAvailable(true);
  const auto oversized_result = oversized.Invoke(Call("ida_database_info", "{}"));
  Require(!oversized_result.success && oversized_result.output.empty(),
          "oversized fixed result escaped");
}

void TestUiContextDispatch()
{
  ida_agent::ai::AgentToolInvokers invokers;
  int ui_calls = 0;
  invokers.ui_cursor = [&ui_calls]()
  {
    ++ui_calls;
    return Json{{"address", "0x401000"}, {"operand", 1}};
  };
  invokers.ui_selection = [&ui_calls]()
  {
    ++ui_calls;
    return Json{{"active", true}, {"start", "0x401000"}, {"end", "0x401010"}};
  };
  invokers.ui_highlight = [&ui_calls]()
  {
    ++ui_calls;
    return Json{{"active", true}, {"text", "sample"}, {"flags", 0}};
  };
  invokers.ui_view = [&ui_calls]()
  {
    ++ui_calls;
    return Json{{"active", true}, {"kind", "disassembly"}, {"title", "main"}};
  };
  invokers.address_boundaries = [&ui_calls](std::uint64_t address)
  {
    Require(address == 0x401000, "boundary address dispatch mismatch");
    ++ui_calls;
    return Json{{"address", "0x401000"},
        {"item", Json{{"start", "0x401000"}, {"end", "0x401003"}}},
        {"segment", nullptr}, {"function", nullptr}, {"chunk", nullptr},
        {"basicBlock", nullptr}};
  };
  auto registry = AgentToolRegistry::ForTesting(std::move(invokers));
  registry.SetAvailable(true);
  const auto cursor = registry.Invoke(Call("ida_ui_cursor", "{}"));
  Require(cursor.success && Json::parse(cursor.output).at("operand") == 1,
          "ui cursor dispatch failed");
  const auto selection = registry.Invoke(Call("ida_ui_selection", "{}"));
  Require(selection.success && Json::parse(selection.output).at("active").get<bool>(),
          "ui selection dispatch failed");
  const auto highlight = registry.Invoke(Call("ida_ui_highlight", "{}"));
  Require(highlight.success && Json::parse(highlight.output).at("text") == "sample",
          "ui highlight dispatch failed");
  const auto view = registry.Invoke(Call("ida_ui_view", "{}"));
  Require(view.success && Json::parse(view.output).at("kind") == "disassembly",
          "ui view dispatch failed");
  const auto boundaries = registry.Invoke(Call(
      "ida_address_boundaries", R"({"address":"0x401000"})"));
  Require(boundaries.success
              && Json::parse(boundaries.output).at("item").at("start") == "0x401000",
          "address boundaries dispatch failed");
  Require(ui_calls == 5, "ui context invoker count mismatch");

  RequireInvalid(registry, Call("ida_ui_cursor", R"({"extra":true})"));
  RequireInvalid(registry, Call("ida_ui_selection", R"({"extra":true})"));
  RequireInvalid(registry, Call("ida_ui_highlight", R"({"extra":true})"));
  RequireInvalid(registry, Call("ida_ui_view", R"({"extra":true})"));
  RequireInvalid(registry, Call("ida_address_boundaries", R"({})"));
  RequireInvalid(registry, Call("ida_address_boundaries", R"({"address":"401000"})"));
  RequireInvalid(registry, Call(
      "ida_address_boundaries", R"({"address":"0x401000","extra":true})"));
  Require(ui_calls == 5, "invalid ui call produced a side effect");
}

void TestValidationAndDispatch()
{
  int export_calls = 0;
  int string_calls = 0;
  int function_calls = 0;
  int decompile_calls = 0;
  int xref_calls = 0;
  int memory_calls = 0;
  auto registry = AgentToolRegistry::ForTesting(
      [&export_calls](std::string_view name, std::uint32_t limit)
      {
        Require(name == "CreateFile", "export name dispatch mismatch");
        Require(limit == 50, "export default limit mismatch");
        ++export_calls;
        return Json{
            {"items", Json::array({{{"address", "0x401000"}, {"name", "CreateFile"}, {"ordinal", 1}}})},
            {"nextCursor", "must-not-escape"},
            {"hasMore", true},
        };
      },
      [&string_calls](std::string_view query, std::uint32_t minimum, std::uint32_t limit, bool refresh)
      {
        Require(query == "hello", "string query dispatch mismatch");
        Require(minimum == 6 && limit == 7 && !refresh, "string numeric dispatch mismatch");
        ++string_calls;
        return Json{
            {"items", Json::array({{{"address", "0x402000"}, {"value", "hello"}}})},
            {"nextCursor", "must-not-escape"},
            {"hasMore", false},
        };
      },
      [&function_calls](std::uint64_t address)
      {
        Require(address == 0x401000, "function address dispatch mismatch");
        ++function_calls;
        return Json{{"address", "0x401000"}, {"name", "main"}};
      },
      [&decompile_calls](
          std::uint64_t address, std::uint32_t offset, std::uint32_t max_bytes)
      {
        Require(address == 0x401000 && offset == 2 && max_bytes == 4096,
                "decompile dispatch mismatch");
        ++decompile_calls;
        return Json{{"entryAddress", "0x401000"}, {"pseudocode", "return 0;"}};
      },
      [&xref_calls](
          std::uint64_t address,
          std::string_view direction,
          std::string_view category,
          bool include_flow,
          std::uint32_t limit)
      {
        Require(address == 0x401000 && direction == "incoming"
                    && category == "code" && include_flow && limit == 3,
                "xref dispatch mismatch");
        ++xref_calls;
        return Json{{"items", Json::array({{{"from", "0x402000"}}})}, {"hasMore", false}};
      },
      [&memory_calls](
          std::uint64_t address,
          std::string_view format,
          std::uint32_t length,
          std::uint32_t width_bits)
      {
        Require(address == 0x403000 && format == "integer"
                    && length == 0 && width_bits == 32,
                "memory dispatch mismatch");
        ++memory_calls;
        return Json{{"address", "0x403000"}, {"format", "integer"}, {"value", "1"}};
      });

  Require(!registry.Available(), "registry must default unavailable");
  RequireInvalid(registry, Call("ida_symbol_exports", "{}"));
  registry.SetAvailable(true);
  Require(registry.Available(), "registry did not become available");

  const auto exports = registry.Invoke(Call(
      "ida_symbol_exports", R"({"name":"CreateFile","limit":50})"));
  Require(exports.success && export_calls == 1, "export dispatch failed");
  const Json export_output = Json::parse(exports.output);
  Require(export_output.at("hasMore").get<bool>(), "export hasMore mismatch");
  Require(!export_output.contains("nextCursor"), "export cursor escaped");

  const auto strings = registry.Invoke(Call(
      "ida_string_search",
      R"({"query":"hello","minimumLength":6,"limit":7})"));
  Require(strings.success && string_calls == 1, "string dispatch failed");
  const Json string_output = Json::parse(strings.output);
  Require(!string_output.contains("nextCursor"), "string cursor escaped");

  const auto function = registry.Invoke(Call(
      "ida_function_get", R"({"address":"0x401000"})"));
  Require(function.success && function_calls == 1, "function dispatch failed");
  Require(Json::parse(function.output).at("name") == "main", "function output mismatch");
  const auto decompile = registry.Invoke(Call(
      "ida_decompile", R"({"address":"0x401000","offset":2,"maxBytes":4096})"));
  Require(decompile.success && decompile_calls == 1, "decompile dispatch failed");
  const auto xrefs = registry.Invoke(Call(
      "ida_xref_query",
      R"({"address":"0x401000","direction":"incoming","category":"code","includeFlow":true,"limit":3})"));
  Require(xrefs.success && xref_calls == 1, "xref dispatch failed");
  const auto memory = registry.Invoke(Call(
      "ida_memory_read",
      R"({"address":"0x403000","format":"integer","length":0,"widthBits":32})"));
  Require(memory.success && memory_calls == 1, "memory dispatch failed");

  RequireInvalid(registry, Call("ida_unknown", "{}"));
  RequireInvalid(registry, Call("ida_symbol_exports", "{"));
  RequireInvalid(registry, Call("ida_symbol_exports", R"({"name":"x"})"));
  RequireInvalid(registry, Call("ida_symbol_exports", R"({"cursor":"opaque"})"));
  RequireInvalid(registry, Call("ida_symbol_exports", R"({"limit":0})"));
  RequireInvalid(registry, Call("ida_symbol_exports", R"({"limit":1.5})"));
  RequireInvalid(registry, Call("ida_string_search", R"({"query":1})"));
  RequireInvalid(registry, Call("ida_string_search", R"({"query":"x","minimumLength":4})"));
  RequireInvalid(registry, Call("ida_string_search", R"({"query":"line\nfeed"})"));
  RequireInvalid(registry, Call("ida_string_search", R"({"query":"x","minimumLength":1025})"));
  RequireInvalid(registry, Call("ida_string_search", R"({"query":"x","extra":true})"));
  RequireInvalid(registry, Call("ida_function_get", R"({"address":"401000"})"));
  RequireInvalid(registry, Call("ida_function_get", R"({"address":"0x10000000000000000"})"));
  RequireInvalid(registry, Call("ida_decompile", R"({"address":"0x401000","offset":0,"maxBytes":3})"));
  RequireInvalid(registry, Call("ida_decompile", R"({"address":"0x401000"})"));
  RequireInvalid(registry, Call("ida_xref_query", R"({"address":"0x401000","direction":"sideways","category":"all","includeFlow":false,"limit":1})"));
  RequireInvalid(registry, Call("ida_xref_query", R"({"address":"0x401000","direction":"incoming","category":"all","includeFlow":false})"));
  RequireInvalid(registry, Call("ida_memory_read", R"({"address":"0x403000","format":"bytes","length":0,"widthBits":0})"));
  RequireInvalid(registry, Call("ida_memory_read", R"({"address":"0x403000","format":"integer","length":0,"widthBits":24})"));
  RequireInvalid(registry, Call("ida_memory_read", R"({"address":"0x403000","format":"pointer","length":1,"widthBits":0})"));
  RequireInvalid(registry, Call("ida_memory_read", R"({"address":"0x403000","format":"pointer"})"));
  RequireInvalid(registry, Call("ida_symbol_exports", Json{{"name", std::string(1025, 'a')}}.dump()));
  std::string invalid_utf8 = "{\"query\":\"";
  invalid_utf8.push_back(static_cast<char>(0xC3));
  invalid_utf8 += "\"}";
  RequireInvalid(registry, Call("ida_string_search", std::move(invalid_utf8)));

  AgentToolCall oversized_id = Call("ida_symbol_exports", "{}");
  oversized_id.id.assign(257, 'i');
  const auto invalid_id = registry.Invoke(oversized_id);
  Require(!invalid_id.success && invalid_id.call_id.empty(), "oversized id escaped");
  AgentToolCall controlled_id = Call("ida_symbol_exports", "{}");
  controlled_id.id = "bad\nid";
  const auto invalid_controlled_id = registry.Invoke(controlled_id);
  Require(
      !invalid_controlled_id.success && invalid_controlled_id.call_id.empty(),
      "controlled id escaped");
  AgentToolCall oversized_name = Call(std::string(65, 'n'), "{}");
  const auto invalid_name = registry.Invoke(oversized_name);
  Require(!invalid_name.success && invalid_name.name.empty(), "oversized name escaped");
  AgentToolCall oversized_arguments = Call("ida_symbol_exports", "{}");
  oversized_arguments.arguments_json.assign(
      ida_agent::ai::MaxAgentToolArgumentsBytes + 1, 'x');
  Require(!registry.Invoke(oversized_arguments).success, "oversized arguments succeeded");

  auto oversized_registry = AgentToolRegistry::ForTesting(
      [](std::string_view, std::uint32_t)
      {
        return Json{{"items", Json::array({std::string(ida_agent::ai::MaxAgentToolResultBytes, 'x')})}, {"hasMore", false}};
      },
      [](std::string_view, std::uint32_t, std::uint32_t, bool)
      {
        return Json{{"items", Json::array()}, {"hasMore", false}};
      });
  oversized_registry.SetAvailable(true);
  const auto oversized = oversized_registry.Invoke(Call(
      "ida_symbol_exports", R"({"name":"","limit":50})"));
  Require(!oversized.success && oversized.output.empty(), "oversized output escaped");

  auto throwing_registry = AgentToolRegistry::ForTesting(
      [](std::string_view, std::uint32_t) -> Json
      {
        throw std::runtime_error("private exception detail");
      },
      [](std::string_view, std::uint32_t, std::uint32_t, bool)
      {
        return Json{{"items", Json::array()}, {"hasMore", false}};
      });
  throwing_registry.SetAvailable(true);
  const auto failed = throwing_registry.Invoke(Call(
      "ida_symbol_exports", R"({"name":"","limit":50})"));
  Require(!failed.success && failed.output.empty(), "exception call exposed output");
  Require(
      failed.safe_message.find("private") == std::string::npos,
      "exception detail escaped");

  const auto job = registry.Submit({
      Call("ida_symbol_exports", R"({"name":"CreateFile","limit":50})"),
      {"call-2", "ida_string_search", R"({"query":"hello","minimumLength":6,"limit":7})"},
  });
  Require(job != 0, "async tool job was rejected");
  std::optional<std::vector<ida_agent::ai::AgentToolResult>> async_results;
  for ( int retry = 0; retry < 200 && !async_results.has_value(); ++retry )
  {
    async_results = registry.TryTake(job);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  Require(async_results.has_value() && async_results->size() == 2,
           "async tool results were not returned");
}

void TestCancellation()
{
  std::atomic<int> calls{0};
  auto registry = AgentToolRegistry::ForTesting(
      [&calls](std::string_view, std::uint32_t)
      {
        ++calls;
        std::this_thread::sleep_for(std::chrono::milliseconds(40));
        return Json{{"items", Json::array()}, {"hasMore", false}};
      },
      [](std::string_view, std::uint32_t, std::uint32_t, bool)
      {
        return Json{{"items", Json::array()}, {"hasMore", false}};
      });
  registry.SetAvailable(true);
  const auto job = registry.Submit({
      Call("ida_symbol_exports", R"({"name":"a","limit":1})"),
      {"call-2", "ida_symbol_exports", R"({"name":"b","limit":1})"},
  });
  Require(job != 0, "cancellation job was rejected");
  std::this_thread::sleep_for(std::chrono::milliseconds(5));
  registry.CancelAndForget(job);
  std::optional<std::vector<ida_agent::ai::AgentToolResult>> results;
  for ( int retry = 0; retry < 200 && !results.has_value(); ++retry )
  {
    results = registry.TryTake(job);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  Require(results.has_value() && results->empty(),
          "cancelled tool results escaped");
  Require(calls.load() <= 1, "cancellation did not stop the next tool");
}

} // namespace

int main()
{
  extern void RunSemanticAgentToolTests();
  RunSemanticAgentToolTests();
  extern void RunAgentStringRefreshTests();
  RunAgentStringRefreshTests();
  extern void RunAgentDebuggerRegistryTests();
  RunAgentDebuggerRegistryTests();
  TestDefinitions();
  TestFixedReadOnlyBatch();
  TestUiContextDispatch();
  TestValidationAndDispatch();
  TestCancellation();
  RunAgentPromptTests();
  RunAgentFileRegistryTests();
  return 0;
}
