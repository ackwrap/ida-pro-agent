#pragma once

#include "ai/agent_effect_coordinator.hpp"
#include "ai/agent_file_service.hpp"
#include "services/changeset_service.hpp"
#include "services/database_service.hpp"
#include "services/debugger_service.hpp"
#include "services/readonly_analysis_service.hpp"
#include "services/script_service.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace ida_agent::bridge { class IdaExecutor; }

namespace ida_agent::ai
{

// Execute throws only this exception when a write may have started but its
// final state cannot be established. All validation and ordinary service
// failures are returned as sanitized AgentToolResult values.
class AgentEffectStateUncertain final : public std::runtime_error
{
public:
  AgentEffectStateUncertain()
      : std::runtime_error("agent effect state is uncertain")
  {
  }
};

struct AgentEffectServiceCallbacks
{
  std::function<services::PreviewOutcome(
      const std::vector<services::ChangeOperation> &)> changeset_preview;
  std::function<services::ApplyOutcome(
      std::string_view,
      const std::vector<services::ChangeOperation> &,
      std::string_view)> changeset_apply;
  std::function<services::ApplyOutcome(std::string_view, std::string_view)>
      changeset_rollback;
  std::function<services::DatabaseSaveOutcome(bool, bool)> database_save;
  std::function<services::ReadonlyResult(std::uint64_t, std::uint64_t)>
      analysis_plan;
  std::function<services::DebuggerInfoOutcome()> debugger_info;
  std::function<services::DebuggerActionOutcome(const services::DebuggerSelectRequest &)> debugger_select;
  std::function<services::DebuggerActionOutcome(const services::DebuggerConfigureRequest &)> debugger_configure;
  std::function<services::DebuggerActionOutcome(int)> debugger_attach;
  std::function<services::DebuggerActionOutcome()> debugger_detach;
  std::function<services::DebuggerActionOutcome()> debugger_suspend;
  std::function<services::DebuggerActionOutcome()> debugger_start;
  std::function<services::DebuggerActionOutcome()> debugger_exit;
  std::function<services::DebuggerActionOutcome(
      std::string_view, std::optional<std::uint64_t>)> debugger_control;
  std::function<services::DebuggerActionOutcome(
      std::string_view, std::uint64_t,
      const services::BreakpointMutation &)> debugger_breakpoint;
  std::function<services::DebuggerActionOutcome(
      std::uint64_t, std::string_view)> debugger_memory_write;
  std::function<services::ScriptExecutionOutcome(
      std::string_view, std::string_view)> script_execute;
  std::function<std::optional<AgentFileMutationPlan>(
      std::string_view, std::string_view, std::string_view)> file_prepare_mutation;
  std::function<AgentFileMutationOutcome(const AgentFileMutationPlan &)>
      file_execute_mutation;
  std::function<std::optional<AgentFileScriptSnapshot>(
      std::string_view, std::string_view)> file_prepare_script;
};

class AgentEffectService final
{
public:
  AgentEffectService(
      bridge::IdaExecutor &executor,
      services::ChangeSetService &changeset_service,
      services::DatabaseService &database_service,
      const services::ReadonlyAnalysisService &analysis_service,
      const services::DebuggerService &debugger_service,
      const services::ScriptService &script_service,
      AgentFileService &file_service);

  static AgentEffectService ForTesting(AgentEffectServiceCallbacks callbacks)
  {
    return AgentEffectService(std::move(callbacks));
  }

  AgentEffectPreparation Prepare(
      AgentEffectName effect,
      const AgentToolCall &call) const noexcept;

  // Deliberately not declared noexcept: AgentEffectStateUncertain is the sole
  // exception allowed to cross this boundary.
  AgentToolResult Execute(
      AgentEffectName effect,
      const AgentToolCall &call,
      const std::string &payload) const;

private:
  explicit AgentEffectService(AgentEffectServiceCallbacks callbacks)
      : callbacks_(std::move(callbacks))
  {
  }

  AgentEffectServiceCallbacks callbacks_;
};

} // namespace ida_agent::ai
