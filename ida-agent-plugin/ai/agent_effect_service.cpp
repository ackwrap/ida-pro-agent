#include "ai/agent_effect_service.hpp"
#include "ai/agent_effect_service_operations.hpp"

#ifndef IDA_AGENT_AGENT_EFFECT_SERVICE_TESTING
#include "bridge/ida_executor.hpp"
#endif

namespace ida_agent::ai
{

#ifndef IDA_AGENT_AGENT_EFFECT_SERVICE_TESTING
AgentEffectService::AgentEffectService(
    bridge::IdaExecutor &executor,
    services::ChangeSetService &changeset_service,
    services::DatabaseService &database_service,
    const services::ReadonlyAnalysisService &analysis_service,
    const services::DebuggerService &debugger_service,
    const services::ScriptService &script_service,
    AgentFileService &file_service)
{
  constexpr auto timeout = std::chrono::seconds(12);
  callbacks_.changeset_preview = [timeout, &executor, &changeset_service](
      const std::vector<services::ChangeOperation> &operations)
  {
    return executor.ReadFor(timeout, [&]() { return changeset_service.Preview(operations); });
  };
  callbacks_.changeset_apply = [timeout, &executor, &changeset_service](
      std::string_view preview,
      const std::vector<services::ChangeOperation> &operations,
      std::string_view session)
  {
    return executor.WriteFor(timeout, [&]() { return changeset_service.Apply(preview, operations, session); });
  };
  callbacks_.changeset_rollback = [timeout, &executor, &changeset_service](
      std::string_view change, std::string_view session)
  {
    return executor.WriteFor(timeout, [&]() { return changeset_service.Rollback(change, session); });
  };
  callbacks_.database_save = [timeout, &executor, &database_service](bool compact, bool backup)
  {
    return executor.WriteFor(timeout, [&]() { return database_service.Save(std::nullopt, compact, backup); });
  };
  callbacks_.analysis_plan = [timeout, &executor, &analysis_service](std::uint64_t start, std::uint64_t end)
  {
    return executor.WriteFor(timeout, [&]() { return analysis_service.AnalysisPlan(start, end); });
  };
  callbacks_.debugger_info = [timeout, &executor, &debugger_service]()
  {
    return executor.DebuggerFor(timeout, [&]() { return debugger_service.Info(); });
  };
  callbacks_.debugger_select = [timeout, &executor, &debugger_service](const services::DebuggerSelectRequest & request)
  {
    return executor.DebuggerFor(timeout, [&]() { return debugger_service.Select(request); });
  };
  callbacks_.debugger_configure = [timeout, &executor, &debugger_service](const services::DebuggerConfigureRequest & request)
  {
    return executor.DebuggerFor(timeout, [&]() { return debugger_service.Configure(request); });
  };
  callbacks_.debugger_attach = [timeout, &executor, &debugger_service](int request)
  {
    return executor.DebuggerFor(timeout, [&]() { return debugger_service.Attach(request); });
  };
  callbacks_.debugger_detach = [timeout, &executor, &debugger_service]()
  {
    return executor.DebuggerFor(timeout, [&]() { return debugger_service.Detach(); });
  };
  callbacks_.debugger_suspend = [timeout, &executor, &debugger_service]()
  {
    return executor.DebuggerFor(timeout, [&]() { return debugger_service.Suspend(); });
  };
  callbacks_.debugger_start = [timeout, &executor, &debugger_service]()
  {
    return executor.WriteFor(timeout, [&]() { return debugger_service.Start(); });
  };
  callbacks_.debugger_exit = [timeout, &executor, &debugger_service]()
  {
    return executor.DebuggerFor(timeout, [&]() { return debugger_service.Exit(); });
  };
  callbacks_.debugger_control = [timeout, &executor, &debugger_service](
      std::string_view action, std::optional<std::uint64_t> address)
  {
    return executor.WriteFor(timeout, [&]() { return debugger_service.Control(action, address); });
  };
  callbacks_.debugger_breakpoint = [timeout, &executor, &debugger_service](
      std::string_view action, std::uint64_t address,
      const services::BreakpointMutation &mutation)
  {
    return executor.WriteFor(timeout, [&]() { return debugger_service.Breakpoint(action, address, mutation); });
  };
  callbacks_.debugger_memory_write = [timeout, &executor, &debugger_service](
      std::uint64_t address, std::string_view bytes)
  {
    return executor.WriteFor(timeout, [&]() { return debugger_service.WriteMemory(address, bytes); });
  };
  callbacks_.script_execute = [timeout, &executor, &script_service](
      std::string_view language, std::string_view code)
  {
    return executor.WriteFor(timeout, [&]() { return script_service.Execute(language, code); });
  };
  callbacks_.file_prepare_mutation = [&file_service](
      std::string_view path, std::string_view mode, std::string_view content)
  {
    return file_service.PrepareMutation(path, mode, content);
  };
  callbacks_.file_execute_mutation = [&file_service](const AgentFileMutationPlan &plan)
  {
    return file_service.ExecuteMutation(plan);
  };
  callbacks_.file_prepare_script = [&file_service](
      std::string_view path, std::string_view language)
  {
    return file_service.PrepareScript(path, language);
  };
}
#endif

AgentEffectPreparation AgentEffectService::Prepare(
    AgentEffectName effect,
    const AgentToolCall &call) const noexcept
{
  try
  {
    if ( call.name != agent_effect_service_operations::Name(effect) )
      return {{}, "The side-effect tool name is invalid."};
    return agent_effect_service_operations::Prepare(callbacks_, effect, call);
  }
  catch ( ... )
  {
    return {{}, "The side effect could not be prepared safely."};
  }
}

AgentToolResult AgentEffectService::Execute(
    AgentEffectName effect,
    const AgentToolCall &call,
    const std::string &payload) const
{
  if ( call.name != agent_effect_service_operations::Name(effect) )
    return {call.id, call.name, false, {}, "The prepared side-effect tool name is invalid."};
  try
  {
    return agent_effect_service_operations::Execute(callbacks_, effect, call, payload);
  }
  catch ( const AgentEffectStateUncertain & )
  {
    throw;
  }
  catch ( ... )
  {
    return {call.id, call.name, false, {}, "The prepared side effect is invalid or unavailable."};
  }
}

} // namespace ida_agent::ai
