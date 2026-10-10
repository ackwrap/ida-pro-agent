#include "ai/agent_effect_service.hpp"
#include "ai/agent_effect_digest.hpp"

#include <nlohmann/json.hpp>

#include <stdexcept>
#include <string>
#include <utility>

namespace
{
using namespace ida_agent;
using ai::AgentEffectName;
using ai::AgentEffectService;
using ai::AgentEffectServiceCallbacks;
using ai::AgentEffectStateUncertain;
using ai::AgentToolCall;
using Json = nlohmann::json;

void Require(bool condition, const char *message)
{
  if ( !condition ) throw std::runtime_error(message);
}

services::DebuggerAction Action()
{
  return {true, "suspended", true, true, 0x401000, 7};
}

AgentEffectServiceCallbacks Callbacks()
{
  AgentEffectServiceCallbacks callbacks;
  callbacks.changeset_preview = [](const auto &operations) {
    services::ChangePreview preview{"preview-default", {}, true};
    for ( std::size_t index = 0; index < operations.size(); ++index )
      preview.items.push_back({static_cast<std::uint32_t>(index), "before", "after", false});
    return services::PreviewOutcome{services::ChangeStatus::Success, std::move(preview)};
  };
  callbacks.changeset_apply = [](std::string_view, const auto &operations, std::string_view) {
    services::ChangeApplyResult result{"change-default", {}, true};
    for ( std::size_t index = 0; index < operations.size(); ++index )
      result.items.push_back({static_cast<std::uint32_t>(index), true, std::nullopt});
    return services::ApplyOutcome{services::ChangeStatus::Success, std::move(result)};
  };
  callbacks.changeset_rollback = [](std::string_view, std::string_view) {
    return services::ApplyOutcome{services::ChangeStatus::Success,
      services::ChangeApplyResult{"rollback-change", {{0, true, std::nullopt}}, true}};
  };
  callbacks.database_save = [](bool, bool) {
    return services::DatabaseSaveOutcome{services::DatabaseSaveStatus::Success,
                                         services::DatabaseSaveResult{false}};
  };
  callbacks.analysis_plan = [](std::uint64_t start, std::uint64_t end) {
    return services::ReadonlyResult{services::ReadonlyStatus::Success,
      Json{{"accepted", true}, {"start", start}, {"end", end}, {"queue", "used"}}};
  };
  callbacks.debugger_info = [] {
    return services::DebuggerInfoOutcome{services::DebuggerStatus::Success,
      services::DebuggerInfo{"suspended", true, true, 0x401000, 7}};
  };
  callbacks.debugger_start = [] { return services::DebuggerActionOutcome{services::DebuggerStatus::Success, Action()}; };
  callbacks.debugger_exit = [] { return services::DebuggerActionOutcome{services::DebuggerStatus::Success, Action()}; };
  callbacks.debugger_control = [](std::string_view, std::optional<std::uint64_t>) {
    return services::DebuggerActionOutcome{services::DebuggerStatus::Success, Action()};
  };
  callbacks.debugger_breakpoint = [](std::string_view, std::uint64_t, const services::BreakpointMutation &) {
    return services::DebuggerActionOutcome{services::DebuggerStatus::Success, Action()};
  };
  callbacks.debugger_memory_write = [](std::uint64_t, std::string_view) {
    return services::DebuggerActionOutcome{services::DebuggerStatus::Success, Action()};
  };
  callbacks.script_execute = [](std::string_view language, std::string_view) {
    return services::ScriptExecutionOutcome{services::ScriptStatus::Success,
      services::ScriptExecution{std::string(language), true, std::string("ok"), {}, {}, false, 2}};
  };
  callbacks.file_prepare_mutation = [](std::string_view path, std::string_view mode, std::string_view content) {
    return std::optional<ai::AgentFileMutationPlan>(ai::AgentFileMutationPlan{
      std::string(path), std::string(mode), std::string(content),
      ai::AgentFileState{true, "file", 3, ai::AgentEffectSha256("old"), 1, 2}, 1, 3});
  };
  callbacks.file_execute_mutation = [](const ai::AgentFileMutationPlan &plan) {
    return ai::AgentFileMutationOutcome{ai::AgentFileMutationStatus::Success,
      Json{{"path", plan.path}, {"mode", plan.mode}, {"bytesWritten", plan.content.size()}}};
  };
  callbacks.file_prepare_script = [](std::string_view path, std::string_view language) {
    const std::string source = "import ida_funcs\nprint(ida_funcs.get_func_qty())\n";
    return std::optional<ai::AgentFileScriptSnapshot>(ai::AgentFileScriptSnapshot{
      std::string(path), std::string(language), source, ai::AgentEffectSha256(source)});
  };
  return callbacks;
}

Json RenameOperation()
{
  return {{"kind", "rename"}, {"address", "0x401000"}, {"value", "renamed"},
          {"expected", nullptr}, {"repeatable", false}, {"offset", nullptr},
          {"size", nullptr}, {"subject", nullptr}};
}

void TestDefinitionsAreFixedAndStrict()
{
  const auto &definitions = ai::AgentEffectToolDefinitions();
  Require(definitions.size() == 16, "effect definition count mismatch");
  const char *names[]{"ida_changeset_apply", "ida_changeset_rollback", "ida_database_save",
    "ida_analysis_plan", "ida_debugger_select", "ida_debugger_configure", "ida_debugger_attach", "ida_debugger_detach", "ida_debugger_suspend", "ida_debugger_start", "ida_debugger_exit", "ida_debugger_control",
    "ida_debugger_breakpoint_mutate", "ida_debugger_memory_write", "ida_file_mutate",
    "ida_script_execute_file"};
  for ( std::size_t index = 0; index < definitions.size(); ++index )
  {
    Require(definitions[index].name == names[index], "effect definition name mismatch");
    const Json &schema = definitions[index].parameters;
    Require(schema.at("type") == "object" && schema.at("additionalProperties") == false,
            "effect schema is not strict");
    Require(schema.at("required").size() == schema.at("properties").size(),
            "effect schema properties are not all required");
  }
  const Json operation = definitions.front().parameters.at("properties").at("operations").at("items");
  Require(operation.at("additionalProperties") == false
      && operation.at("required").size() == operation.at("properties").size(),
      "change operation schema is not strict");
}

void TestApplyPreparationIsReadOnlyAndImmutable()
{
  int previews = 0, writes = 0;
  auto callbacks = Callbacks();
  callbacks.changeset_preview = [&](const auto &operations) {
    ++previews;
    Require(operations.size() == 1 && operations[0].value == "renamed",
            "prepare did not parse typed operations");
    return services::PreviewOutcome{services::ChangeStatus::Success,
      services::ChangePreview{"preview-immutable", {{0, "old_name", "renamed", false}}, true}};
  };
  callbacks.changeset_apply = [&](std::string_view preview, const auto &operations, std::string_view session) {
    ++writes;
    Require(preview == "preview-immutable", "execute did not use saved preview ID");
    Require(operations.size() == 1 && operations[0].value == "renamed",
            "execute reparsed mutated caller arguments");
    Require(session == "local-agent", "fixed local session ID missing");
    return services::ApplyOutcome{services::ChangeStatus::Success,
      services::ChangeApplyResult{"change-retained", {{0, true, std::nullopt}}, true}};
  };
  auto service = AgentEffectService::ForTesting(std::move(callbacks));
  AgentToolCall call{"apply-1", "ida_changeset_apply",
                     Json{{"operations", Json::array({RenameOperation()})}}.dump()};
  const auto prepared = service.Prepare(AgentEffectName::ChangeSetApply, call);
  Require(!prepared.opaque_payload.empty() && previews == 1 && writes == 0,
          "prepare performed a write or failed to preview");
  Require(prepared.safe_summary.find("old_name") != std::string::npos
      && prepared.safe_summary.find("->") != std::string::npos,
      "bounded preview summary is missing");
  call.arguments_json = R"({"operations":[]})";
  const auto result = service.Execute(AgentEffectName::ChangeSetApply, call,
                                      prepared.opaque_payload);
  Require(result.success && writes == 1, "prepared apply did not execute once");
  const Json output = Json::parse(result.output);
  Require(output.at("changeId") == "change-retained" && output.at("applied") == true,
          "apply result lost rollback information");
}

void TestFileMutationAndScriptSnapshotSafety()
{
  int mutations = 0, scripts = 0;
  std::string source = "import ida_funcs\nprint(ida_funcs.get_func_qty())\n";
  auto callbacks = Callbacks();
  callbacks.file_execute_mutation = [&](const ai::AgentFileMutationPlan &plan) {
    ++mutations;
    Require(plan.path == "notes.txt" && plan.mode == "overwrite" && plan.content == "approved",
        "saved mutation changed");
    return ai::AgentFileMutationOutcome{ai::AgentFileMutationStatus::Success,
      Json{{"path",plan.path},{"mode",plan.mode},{"bytesWritten",plan.content.size()}}};
  };
  callbacks.file_prepare_script = [&](std::string_view path, std::string_view language) {
    return std::optional<ai::AgentFileScriptSnapshot>(ai::AgentFileScriptSnapshot{
      std::string(path), std::string(language), source, ai::AgentEffectSha256(source)});
  };
  callbacks.script_execute = [&](std::string_view language, std::string_view code) {
    ++scripts;
    Require(language == "python" && code.find("ida_funcs") != std::string::npos
        && code.find("changed") == std::string::npos, "saved script snapshot changed");
    return services::ScriptExecutionOutcome{services::ScriptStatus::Success,
      services::ScriptExecution{"python", true, std::string("ok"), {}, {}, false, 2}};
  };
  auto service = AgentEffectService::ForTesting(std::move(callbacks));
  const auto mutation = service.Prepare(AgentEffectName::FileMutate,
    {"file-1", "ida_file_mutate", R"({"path":"notes.txt","mode":"overwrite","content":"approved"})"});
  Require(!mutation.opaque_payload.empty() && mutations == 0,
      "mutation prepare had a side effect");
  Json tampered = Json::parse(mutation.opaque_payload);
  tampered["content"] = "tampered";
  const auto rejected = service.Execute(AgentEffectName::FileMutate,
    {"file-1", "ida_file_mutate", "changed arguments"}, tampered.dump());
  Require(!rejected.success && mutations == 0, "tampered mutation payload executed");
  const auto mutated = service.Execute(AgentEffectName::FileMutate,
    {"file-1", "ida_file_mutate", "changed arguments"}, mutation.opaque_payload);
  Require(mutated.success && mutations == 1
      && mutated.output.find("approved") == std::string::npos,
      "prepared mutation failed or exposed content");

  const auto prepared = service.Prepare(AgentEffectName::ScriptExecuteFile,
    {"script-1", "ida_script_execute_file", R"({"path":"analysis.py","language":"python"})"});
  Require(!prepared.opaque_payload.empty() && scripts == 0, "script ran during prepare");
  Require(prepared.safe_summary.find("import ida_funcs") == std::string::npos
      && prepared.safe_summary.find("analysis.py") != std::string::npos
      && prepared.safe_summary.find(ai::AgentEffectSha256(source)) != std::string::npos
      && prepared.safe_summary.find("not a complete sandbox") != std::string::npos,
      "script summary exposed source or omitted identity/warning");
  Json script_tampered = Json::parse(prepared.opaque_payload);
  script_tampered["source"] = "print('tampered')";
  Require(!service.Execute(AgentEffectName::ScriptExecuteFile,
      {"script-1", "ida_script_execute_file", "mutated arguments"},
      script_tampered.dump()).success && scripts == 0,
      "tampered script payload executed");
  source = "changed after prepare";
  const auto result = service.Execute(AgentEffectName::ScriptExecuteFile,
    {"script-1", "ida_script_execute_file", "mutated arguments"}, prepared.opaque_payload);
  Require(result.success && scripts == 1, "prepared script did not execute from saved payload");
  const Json output = Json::parse(result.output);
  Require(!output.contains("result") && !output.contains("stdout")
      && !output.contains("stderr"),
      "script output content was exposed to the provider result");

  auto idc_callbacks = Callbacks();
  const std::string idc_source = "static main() { auto ea; ea = get_screen_ea(); Message(\"%x\", ea); }";
  idc_callbacks.file_prepare_script = [&](std::string_view path, std::string_view language) {
    return std::optional<ai::AgentFileScriptSnapshot>(ai::AgentFileScriptSnapshot{
      std::string(path), std::string(language), idc_source, ai::AgentEffectSha256(idc_source)});
  };
  auto idc_service = AgentEffectService::ForTesting(std::move(idc_callbacks));
  Require(!idc_service.Prepare(AgentEffectName::ScriptExecuteFile,
      {"idc", "ida_script_execute_file", R"({"path":"analysis.idc","language":"idc"})"}).opaque_payload.empty(),
      "ordinary IDC analysis source was rejected");

  const std::vector<std::pair<std::string,std::string>> denied{
    {"python", "open('x')"}, {"python", "import os"}, {"python", "import pathlib"},
    {"python", "import subprocess"}, {"python", "import ida_diskio"},
    {"python", "eval('x')"}, {"python", "p='..\\x'"},
    {"python", "p='C:\\\\x'"}, {"python", "p='\\\\server\\x'"},
    {"python", "p='/tmp/x'"}, {"python", "p='%TEMP%'"},
    {"python", "ida_loader.save_database('x')"},
    {"python", "getattr(__builtins__, '__im' + 'port__')('o' + 's').system('whoami')"},
    {"idc", "fopen(\"x\", \"r\");"}, {"idc", "exec_system(\"cmd\");"},
    {"idc", "save_database(\"x\", 0);"}};
  for ( const auto &item : denied )
  {
    auto rejected_callbacks = Callbacks();
    rejected_callbacks.file_prepare_script = [&](std::string_view path, std::string_view language) {
      return std::optional<ai::AgentFileScriptSnapshot>(ai::AgentFileScriptSnapshot{
        std::string(path), std::string(language), item.second, ai::AgentEffectSha256(item.second)});
    };
    auto rejected_service = AgentEffectService::ForTesting(std::move(rejected_callbacks));
    const auto denied_prepare = rejected_service.Prepare(AgentEffectName::ScriptExecuteFile,
      {"deny", "ida_script_execute_file", Json{{"path","bad.txt"},{"language",item.first}}.dump()});
    Require(denied_prepare.opaque_payload.empty()
        && denied_prepare.safe_summary.find(item.second) == std::string::npos,
        "sensitive script source was accepted or exposed");
  }
}

void TestDebuggerPrepareReadsStateWithoutWriting()
{
  int info = 0, writes = 0;
  auto callbacks = Callbacks();
  callbacks.debugger_info = [&] {
    ++info;
    return services::DebuggerInfoOutcome{services::DebuggerStatus::Success,
      services::DebuggerInfo{"suspended", true, true, std::nullopt, std::nullopt}};
  };
  callbacks.debugger_memory_write = [&](std::uint64_t address, std::string_view bytes) {
    ++writes;
    Require(address == 0x5000 && bytes == "DEADBEEF", "saved memory write changed");
    return services::DebuggerActionOutcome{services::DebuggerStatus::Success, Action()};
  };
  auto service = AgentEffectService::ForTesting(std::move(callbacks));
  const auto prepared = service.Prepare(AgentEffectName::DebuggerMemoryWrite,
    {"memory-1", "ida_debugger_memory_write", R"({"address":"0x5000","bytes":"DEADBEEF"})"});
  Require(!prepared.opaque_payload.empty() && info == 1 && writes == 0,
          "debugger prepare did not perform exactly one read");
  Require(prepared.safe_summary.find("suspended") != std::string::npos
      && prepared.safe_summary.find("DEADBEEF") == std::string::npos,
      "debugger summary omitted state or exposed bytes");
  const auto result = service.Execute(AgentEffectName::DebuggerMemoryWrite,
    {"memory-1", "ida_debugger_memory_write", "raw bytes changed"}, prepared.opaque_payload);
  Require(result.success && writes == 1, "debugger write did not wait for execute");
}

void TestSafeStatusAndUncertainMapping()
{
  const std::string secret = "RAW_SECRET_SOURCE_OR_BYTES";
  auto callbacks = Callbacks();
  callbacks.database_save = [&](bool, bool) {
    throw std::runtime_error(secret);
    return services::DatabaseSaveOutcome{};
  };
  auto service = AgentEffectService::ForTesting(std::move(callbacks));
  AgentToolCall call{"save-1", "ida_database_save", R"({"compact":false,"backup":true})"};
  const auto prepared = service.Prepare(AgentEffectName::DatabaseSave, call);
  bool uncertain = false;
  try { static_cast<void>(service.Execute(AgentEffectName::DatabaseSave, call, prepared.opaque_payload)); }
  catch ( const AgentEffectStateUncertain &error )
  {
    uncertain = true;
    Require(std::string(error.what()).find(secret) == std::string::npos,
            "state-uncertain exception exposed implementation text");
  }
  Require(uncertain, "throwing write was not mapped to state uncertain");

  callbacks = Callbacks();
  callbacks.file_execute_mutation = [](const ai::AgentFileMutationPlan &) {
    return ai::AgentFileMutationOutcome{ai::AgentFileMutationStatus::StateUncertain,
      Json::object()};
  };
  service = AgentEffectService::ForTesting(std::move(callbacks));
  const AgentToolCall file_call{"file-uncertain", "ida_file_mutate",
    R"({"path":"notes.txt","mode":"overwrite","content":"approved"})"};
  const auto file_prepared = service.Prepare(AgentEffectName::FileMutate, file_call);
  uncertain = false;
  try { static_cast<void>(service.Execute(AgentEffectName::FileMutate,
      file_call, file_prepared.opaque_payload)); }
  catch ( const AgentEffectStateUncertain & ) { uncertain = true; }
  Require(uncertain, "uncertain file mutation was downgraded to an ordinary failure");

  callbacks = Callbacks();
  callbacks.changeset_rollback = [&](std::string_view, std::string_view) {
    return services::ApplyOutcome{services::ChangeStatus::Conflict, std::nullopt};
  };
  service = AgentEffectService::ForTesting(std::move(callbacks));
  call = {"rollback-1", "ida_changeset_rollback", Json{{"changeId", secret}}.dump()};
  const auto rollback = service.Prepare(AgentEffectName::ChangeSetRollback, call);
  const auto failed = service.Execute(AgentEffectName::ChangeSetRollback, call,
                                      rollback.opaque_payload);
  Require(!failed.success && failed.output.empty()
      && failed.safe_message.find(secret) == std::string::npos,
      "safe status mapping exposed raw identifiers or output");
}
} // namespace

int main()
{
  try
  {
    extern void RunAgentDebuggerSetupTests();
    RunAgentDebuggerSetupTests();
    TestDefinitionsAreFixedAndStrict();
    TestApplyPreparationIsReadOnlyAndImmutable();
    TestFileMutationAndScriptSnapshotSafety();
    TestDebuggerPrepareReadsStateWithoutWriting();
    TestSafeStatusAndUncertainMapping();
    return 0;
  }
  catch ( const std::exception & ) { return 1; }
}
