#include "ai/agent_effect_coordinator.hpp"

#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace
{

using ida_agent::ai::AgentEffectBinding;
using ida_agent::ai::AgentEffectCoordinator;
using ida_agent::ai::AgentEffectName;
using ida_agent::ai::AgentEffectPreparation;
using ida_agent::ai::AgentEffectRisk;
using ida_agent::ai::AgentEffectStatus;
using ida_agent::ai::AgentToolCall;
using ida_agent::ai::AgentToolResult;

void Require(bool condition, const char *message)
{
  if ( !condition )
    throw std::runtime_error(message);
}

AgentToolCall Call(
    std::string name,
    std::string arguments = R"({"value":"ordinary"})")
{
  return {"call-1", std::move(name), std::move(arguments)};
}

AgentToolResult Success(const AgentToolCall &call)
{
  return {call.id, call.name, true, R"({"ok":true})", {}};
}

void TestPrepareHasNoSideEffectAndCopiesData()
{
  int prepare_calls = 0;
  int execute_calls = 0;
  std::string prepared_payload = "prepared-payload";
  const AgentEffectBinding binding(7, "database-context", "database-key");
  AgentEffectCoordinator coordinator(
      binding,
      [&](AgentEffectName effect, const AgentToolCall &call)
      {
        Require(effect == AgentEffectName::ScriptExecuteFile,
                "script effect classification mismatch");
        Require(call.arguments_json.find("analysis.py") != std::string::npos,
                "prepare did not receive arguments");
        ++prepare_calls;
        return AgentEffectPreparation{prepared_payload,
                                      "python script summary without source"};
      },
      [&](AgentEffectName, const AgentToolCall &call, const std::string &)
      {
        ++execute_calls;
        return Success(call);
      });

  AgentToolCall call = Call(
      "ida_script_execute_file",
      R"({"path":"analysis.py","language":"python"})");
  const auto prepared = coordinator.Prepare(call);
  Require(prepared.status() == AgentEffectStatus::Prepared,
          "inline script was not prepared");
  Require(prepared.plan().has_value(), "prepared plan missing");
  Require(prepare_calls == 1 && execute_calls == 0,
          "prepare executed a side effect");
  Require(prepared.plan()->risk() == AgentEffectRisk::Critical,
          "script risk mismatch");
  Require(prepared.plan()->binding() == binding, "plan binding mismatch");
  Require(prepared.plan()->safe_summary().find("secret-source") == std::string::npos,
          "safe summary exposed script source");
  Require(prepared.plan()->safe_summary() == "python script summary without source",
          "coordinator did not use the service-generated summary");
  Require(prepared.safe_message().find("secret-source") == std::string::npos,
          "prepare result exposed script source");

  call.id = "mutated-id";
  call.arguments_json = "mutated-arguments";
  prepared_payload = "mutated-payload";
  Require(prepared.plan()->call().id == "call-1",
          "prepared call was not deep copied");
  Require(prepared.plan()->call().arguments_json.find("analysis.py")
              != std::string::npos,
          "prepared arguments were not deep copied");
  Require(prepared.plan()->payload() == "prepared-payload",
          "prepared payload was not deep copied");
}

void TestFixedClassification()
{
  const std::vector<std::pair<const char *, AgentEffectName>> effects{
      {"ida_changeset_apply", AgentEffectName::ChangeSetApply},
      {"ida_changeset_rollback", AgentEffectName::ChangeSetRollback},
      {"ida_database_save", AgentEffectName::DatabaseSave},
      {"ida_analysis_plan", AgentEffectName::AnalysisPlan},
      {"ida_debugger_select", AgentEffectName::DebuggerSelect},
      {"ida_debugger_configure", AgentEffectName::DebuggerConfigure},
      {"ida_debugger_attach", AgentEffectName::DebuggerAttach},
      {"ida_debugger_detach", AgentEffectName::DebuggerDetach},
      {"ida_debugger_suspend", AgentEffectName::DebuggerSuspend},
      {"ida_debugger_start", AgentEffectName::DebuggerStart},
      {"ida_debugger_exit", AgentEffectName::DebuggerExit},
      {"ida_debugger_control", AgentEffectName::DebuggerControl},
      {"ida_debugger_breakpoint_mutate", AgentEffectName::DebuggerBreakpoint},
      {"ida_debugger_memory_write", AgentEffectName::DebuggerMemoryWrite},
      {"ida_file_mutate", AgentEffectName::FileMutate},
      {"ida_script_execute_file", AgentEffectName::ScriptExecuteFile},
  };
  AgentEffectName observed = AgentEffectName::DatabaseSave;
  AgentEffectCoordinator coordinator(
      AgentEffectBinding(1, "ctx", "key"),
      [&](AgentEffectName effect, const AgentToolCall &)
      {
        observed = effect;
        return AgentEffectPreparation{"payload", "typed service summary"};
      },
      [](AgentEffectName, const AgentToolCall &call, const std::string &)
      { return Success(call); });

  for ( const auto &effect : effects )
  {
    const std::string arguments = effect.second == AgentEffectName::ScriptExecuteFile
        ? R"({"path":"analysis.py","language":"python"})"
        : "{}";
    const auto prepared = coordinator.Prepare(Call(effect.first, arguments));
    Require(prepared.status() == AgentEffectStatus::Prepared,
            "fixed effect was not classified");
    Require(observed == effect.second, "fixed effect mapped to wrong enum");
    Require(!prepared.plan()->safe_summary().empty(), "safe summary missing");
    if ( effect.second == AgentEffectName::FileMutate )
      Require(prepared.plan()->risk() == AgentEffectRisk::High, "file mutation risk mismatch");
    if ( effect.second == AgentEffectName::ScriptExecuteFile )
      Require(prepared.plan()->risk() == AgentEffectRisk::Critical, "script-file risk mismatch");
  }
}

void TestConfirmBindingAndSingleUse()
{
  int execute_calls = 0;
  const AgentEffectBinding binding(3, "ctx", "key");
  AgentEffectCoordinator coordinator(
      binding,
      [](AgentEffectName, const AgentToolCall &call)
      { return AgentEffectPreparation{std::string("copy:") + call.arguments_json,
                                      "apply summary"}; },
      [&](AgentEffectName effect, const AgentToolCall &call, const std::string &payload)
      {
        Require(effect == AgentEffectName::ChangeSetApply,
                "confirm effect mismatch");
        Require(call.arguments_json == R"({"change":"original"})",
                "confirm call copy changed");
        Require(payload == R"(copy:{"change":"original"})",
                "confirm payload copy changed");
        ++execute_calls;
        return Success(call);
      });

  AgentToolCall call = Call("ida_changeset_apply", R"({"change":"original"})");
  const auto first = coordinator.Prepare(call);
  const std::string first_id = first.plan()->prepared_id();
  call.arguments_json = "changed";
  Require(coordinator.Confirm("wrong-id", binding).status()
              == AgentEffectStatus::PreparedIdMismatch,
          "wrong prepared ID was accepted");
  Require(execute_calls == 0 && coordinator.PendingPlans().size() == 1,
          "wrong ID consumed or executed the plan");

  const AgentEffectBinding wrong_generation(4, "ctx", "key");
  Require(coordinator.Confirm(first_id, wrong_generation).status()
              == AgentEffectStatus::BindingMismatch,
          "wrong generation was accepted");
  Require(execute_calls == 0 && coordinator.PendingPlans().empty(),
          "binding mismatch did not consume safely");

  const auto context_plan = coordinator.Prepare(
       Call("ida_changeset_apply", R"({"change":"original"})"));
  Require(coordinator.Confirm(
              context_plan.plan()->prepared_id(),
              AgentEffectBinding(3, "other-ctx", "key")).status()
              == AgentEffectStatus::BindingMismatch,
          "wrong database context was accepted");
  Require(execute_calls == 0, "database context mismatch executed the plan");

  const auto key_plan = coordinator.Prepare(
       Call("ida_changeset_apply", R"({"change":"original"})"));
  Require(coordinator.Confirm(
              key_plan.plan()->prepared_id(),
              AgentEffectBinding(3, "ctx", "other-key")).status()
              == AgentEffectStatus::BindingMismatch,
          "wrong database key was accepted");
  Require(execute_calls == 0, "database key mismatch executed the plan");

  const auto second = coordinator.Prepare(
       Call("ida_changeset_apply", R"({"change":"original"})"));
  const std::string second_id = second.plan()->prepared_id();
  Require(second_id != first_id, "prepared ID was reused");
  const auto confirmed = coordinator.Confirm(second_id, binding);
  Require(confirmed.status() == AgentEffectStatus::Confirmed,
          "exact confirmation failed");
  Require(confirmed.tool_result().success && execute_calls == 1,
          "executor result mismatch");
  Require(coordinator.Confirm(second_id, binding).status()
              == AgentEffectStatus::NoPendingPlan,
          "prepared ID was not single-use");
  Require(execute_calls == 1, "single-use confirmation executed twice");
}

void TestRejectIsSafeAndDoesNotExecute()
{
  int execute_calls = 0;
  const AgentEffectBinding binding(1, "ctx", "key");
  AgentEffectCoordinator coordinator(
      binding,
      [](AgentEffectName, const AgentToolCall &)
      { return AgentEffectPreparation{"payload-with-secret-bytes",
                                      "memory write summary without bytes"}; },
      [&](AgentEffectName, const AgentToolCall &call, const std::string &)
      {
        ++execute_calls;
        return Success(call);
      });
  const auto prepared = coordinator.Prepare(Call(
      "ida_debugger_memory_write", R"({"bytes":"secret-bytes"})"));
  const auto rejected = coordinator.Reject(
      prepared.plan()->prepared_id(), binding);
  Require(rejected.status() == AgentEffectStatus::Rejected,
          "reject status mismatch");
  Require(!rejected.tool_result().success && rejected.tool_result().output.empty(),
          "reject returned unsafe success/output");
  Require(rejected.tool_result().safe_message.find("secret-bytes")
              == std::string::npos,
          "reject result exposed arguments or payload");
  Require(execute_calls == 0, "reject invoked executor");
  Require(coordinator.PendingPlans().empty(), "reject did not consume plan");
}

void TestMultiplePreparedPlansPreserveOrderAndSingleUse()
{
  const AgentEffectBinding binding(1, "ctx", "key");
  std::vector<std::string> executed;
  AgentEffectCoordinator coordinator(
      binding,
      [](AgentEffectName, const AgentToolCall &call)
      { return AgentEffectPreparation{"payload:" + call.id, "summary:" + call.id}; },
      [&](AgentEffectName, const AgentToolCall &call, const std::string &)
      {
        executed.push_back(call.id);
        return Success(call);
      });
  const AgentToolCall first{"call-1", "ida_database_save", "{}"};
  const AgentToolCall second{"call-2", "ida_analysis_plan", "{}"};
  const AgentToolCall third{"call-3", "ida_debugger_start", "{}"};
  const auto first_plan = coordinator.Prepare(first);
  const auto second_plan = coordinator.Prepare(second);
  const auto third_plan = coordinator.Prepare(third);
  const std::vector<ida_agent::ai::AgentEffectPreparedPlan> pending =
      coordinator.PendingPlans();
  Require(pending.size() == 3, "prepared batch was not retained");
  Require(pending[0].call().id == "call-1"
              && pending[1].call().id == "call-2"
              && pending[2].call().id == "call-3",
          "prepared batch order changed");

  Require(coordinator.Confirm(first_plan.plan()->prepared_id(), binding).status()
              == AgentEffectStatus::Confirmed,
          "first batch effect failed");
  Require(coordinator.Confirm(second_plan.plan()->prepared_id(), binding).status()
              == AgentEffectStatus::Confirmed,
          "second batch effect failed");
  Require(coordinator.Confirm(third_plan.plan()->prepared_id(), binding).status()
              == AgentEffectStatus::Confirmed,
          "third batch effect failed");
  Require(executed == std::vector<std::string>({"call-1", "call-2", "call-3"}),
          "prepared effects did not execute in decision order");
  Require(coordinator.PendingPlans().empty(), "executed batch remained pending");
}

void TestGenerationAndDatabaseInvalidation()
{
  const AgentEffectBinding initial(1, "ctx-a", "key-a");
  AgentEffectCoordinator coordinator(
      initial,
      [](AgentEffectName, const AgentToolCall &) { return AgentEffectPreparation{"payload", "analysis summary"}; },
      [](AgentEffectName, const AgentToolCall &call, const std::string &)
      { return Success(call); });

  coordinator.Prepare(Call("ida_analysis_plan", "{}"));
  coordinator.UpdateBinding(AgentEffectBinding(2, "ctx-a", "key-a"));
  Require(coordinator.PendingPlans().empty(),
          "generation update did not invalidate plan");
  coordinator.Prepare(Call("ida_analysis_plan", "{}"));
  coordinator.UpdateBinding(AgentEffectBinding(2, "ctx-b", "key-a"));
  Require(coordinator.PendingPlans().empty(),
          "database context update did not invalidate plan");
  coordinator.Prepare(Call("ida_analysis_plan", "{}"));
  coordinator.UpdateBinding(AgentEffectBinding(2, "ctx-b", "key-b"));
  Require(coordinator.PendingPlans().empty(),
          "database key update did not invalidate plan");
  coordinator.Prepare(Call("ida_analysis_plan", "{}"));
  coordinator.Invalidate();
  Require(coordinator.PendingPlans().empty(),
          "explicit invalidation retained a pending plan");
}

void TestUnknownAndReadOnlyToolsAreRejected()
{
  int prepare_calls = 0;
  int execute_calls = 0;
  AgentEffectCoordinator coordinator(
      AgentEffectBinding(1, "ctx", "key"),
      [&](AgentEffectName, const AgentToolCall &)
      {
        ++prepare_calls;
        return AgentEffectPreparation{"payload", "summary"};
      },
      [&](AgentEffectName, const AgentToolCall &call, const std::string &)
      {
        ++execute_calls;
        return Success(call);
      });
  const std::vector<AgentToolCall> calls{
      Call("ida_memory_read", "{}"),
      Call("changeset.preview", "{}"),
      Call("unknown.write", "{}"),
      Call("script.execute", R"({"language":"python","path":"secret.py"})"),
      Call("script.execute", "not-json"),
  };
  for ( const auto &call : calls )
  {
    const auto result = coordinator.Prepare(call);
    Require(result.status() == AgentEffectStatus::UnsupportedTool,
            "unknown/read-only tool was prepared");
    Require(!result.plan().has_value(), "unsupported tool returned a plan");
  }
  Require(prepare_calls == 0 && execute_calls == 0,
          "unsupported tool reached an invoker");
}

void TestThrownExecutorIsStateUncertainAndConsumed()
{
  int execute_calls = 0;
  const AgentEffectBinding binding(9, "ctx", "key");
  AgentEffectCoordinator coordinator(
      binding,
      [](AgentEffectName, const AgentToolCall &)
      { return AgentEffectPreparation{"opaque-payload", "control summary"}; },
      [&](AgentEffectName, const AgentToolCall &, const std::string &) -> AgentToolResult
      {
        ++execute_calls;
        throw std::runtime_error("raw executor failure with secret arguments");
      });
  const auto prepared = coordinator.Prepare(Call("ida_debugger_control", "{}"));
  const auto uncertain = coordinator.Confirm(
      prepared.plan()->prepared_id(), binding);
  Require(uncertain.status() == AgentEffectStatus::StateUncertain,
          "throwing executor did not report state_uncertain");
  Require(!uncertain.tool_result().success
              && uncertain.tool_result().output.empty(),
          "uncertain result exposed output");
  Require(uncertain.tool_result().safe_message.find("secret")
              == std::string::npos,
          "uncertain result exposed exception text");
  Require(execute_calls == 1 && coordinator.PendingPlans().empty(),
          "throwing executor did not consume exactly once");
}

void TestFailedExecutorResultIsPreserved()
{
  const AgentEffectBinding binding(1, "ctx", "key");
  AgentEffectCoordinator coordinator(
      binding,
      [](AgentEffectName, const AgentToolCall &)
      { return AgentEffectPreparation{"payload", "save summary"}; },
      [](AgentEffectName, const AgentToolCall &call, const std::string &)
      {
        return AgentToolResult{
            call.id, call.name, false,
            "complete failure output", "safe failure message"};
      });
  const auto prepared = coordinator.Prepare(Call("ida_database_save", "{}"));
  const auto failed = coordinator.Confirm(prepared.plan()->prepared_id(), binding);
  Require(failed.status() == AgentEffectStatus::ExecutionFailed,
          "failed executor status mismatch");
  Require(failed.tool_result().output == "complete failure output"
              && failed.tool_result().safe_message == "safe failure message",
          "failed executor result was redacted by the coordinator");
}

void TestPreparationFailurePreservesPreparedBatch()
{
  bool fail = false;
  AgentEffectCoordinator coordinator(
      AgentEffectBinding(1, "ctx", "key"),
      [&](AgentEffectName, const AgentToolCall &) -> AgentEffectPreparation
      {
        if ( fail )
          throw std::runtime_error("unsafe raw preparation error");
        return {"payload", "save summary"};
      },
      [](AgentEffectName, const AgentToolCall &call, const std::string &)
      { return Success(call); });
  const auto initial = coordinator.Prepare(Call("ida_database_save", "{}"));
  Require(initial.plan().has_value(),
          "initial prepare failed");
  fail = true;
  const auto failed = coordinator.Prepare(Call("ida_database_save", "{}"));
  Require(failed.status() == AgentEffectStatus::PreparationFailed,
          "prepare exception status mismatch");
  Require(failed.safe_message().find("raw preparation") == std::string::npos,
          "prepare exception leaked");
  Require(coordinator.PendingPlans().size() == 1,
          "one failed preparation discarded the prepared batch");
  Require(coordinator.Confirm(initial.plan()->prepared_id(),
                              AgentEffectBinding(1, "ctx", "key")).status()
              == AgentEffectStatus::Confirmed,
          "retained prepared effect could not execute");
}

} // namespace

int main()
{
  try
  {
    TestPrepareHasNoSideEffectAndCopiesData();
    TestFixedClassification();
    TestConfirmBindingAndSingleUse();
    TestRejectIsSafeAndDoesNotExecute();
    TestMultiplePreparedPlansPreserveOrderAndSingleUse();
    TestGenerationAndDatabaseInvalidation();
    TestUnknownAndReadOnlyToolsAreRejected();
    TestThrownExecutorIsStateUncertainAndConsumed();
    TestFailedExecutorResultIsPreserved();
    TestPreparationFailurePreservesPreparedBatch();
    return 0;
  }
  catch ( const std::exception & )
  {
    return 1;
  }
}
