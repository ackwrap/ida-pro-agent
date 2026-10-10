#include "ai/ai_menu.hpp"

#include "ai/ai_menu_registry.hpp"
#include "ai/agent_prompt.hpp"
#include "ai/agent_tool_registry.hpp"
#include "ai/agent_tool_transcript.hpp"
#include "ai/chat_context.hpp"
#include "ai/provider_chat.hpp"
#include "ai/provider_chat_session.hpp"
#include "ai/provider_settings_model.hpp"

#include <algorithm>
#include <cctype>
#include <string>
#include <utility>
#include <vector>

namespace ida_agent::ai
{
namespace
{

constexpr const char *ActiveRequestMessage =
    "An AI request is already active.";
constexpr const char *PreviewLimitMessage =
    "AI response exceeded the preview limit.";
constexpr const char *EmptyResponseMessage =
    "Provider returned an empty response.";
constexpr const char *CancelledMessage =
    "AI request was cancelled.";
constexpr const char *ToolsUnavailableMessage =
    "IDA analysis tools are unavailable.";
constexpr const char *UnexpectedToolCallMessage =
    "The provider requested tools that are not enabled for this model.";
constexpr const char *ToolTranscriptErrorMessage =
    "The complete Tool transcript could not be recorded; the agent tool round was stopped.";

bool HasEnabledDefaultModel(const ProviderProfileDraft &profile)
{
  return !profile.settings.model.empty()
      && std::any_of(
          profile.models.begin(),
          profile.models.end(),
          [&profile](const ProviderModelDraft &model)
          {
            return model.enabled && model.id == profile.settings.model;
          });
}

bool IsEffectTool(std::string_view name)
{
  const auto &definitions = AgentEffectToolDefinitions();
  return std::any_of(
      definitions.begin(), definitions.end(),
      [name](const AgentToolDefinition &definition)
      {
        return definition.name == name;
      });
}

AgentToolResult DeniedEffectResult(const AgentToolCall &call)
{
  return {
      call.id,
      call.name,
      false,
      {},
      "The conversation session side-effect policy denied this tool.",
  };
}

} // namespace

void AiMenuController::SubmitChatMessage(std::string_view text)
{
  if ( HasActiveRequest() )
  {
    chat_panel_.AppendSystem(ActiveRequestMessage);
    PersistTranscript();
    return;
  }

  AdvanceEffectGeneration();
  effect_coordinator_.UpdateBinding(CurrentEffectBinding());

  ProviderSettingsSnapshot providers =
      AiMenuRegistry::Instance().ProviderSettings();
  const ProviderProfileDraft *active = ActiveProvider(providers.Manager());
  if ( !chat_panel_.AppendUser(text) )
  {
    chat_panel_.AppendSystem(
        "Message was rejected because it is invalid UTF-8 or exceeds the history limit.");
    PersistTranscript();
    return;
  }
  PersistTranscript();
  chat_panel_.ClearTransientStatus();

  if ( active == nullptr || !HasEnabledDefaultModel(*active) )
  {
    chat_panel_.AppendSystem(ProviderChatConfigurationErrorMessage);
    PersistTranscript();
    return;
  }

  const std::vector<ProviderChatMessage> messages =
      BuildConversationMessages(chat_panel_.Entries());

  const ProviderModelDraft *model = SelectedChatModel(*active);
  const bool agent_enabled = model != nullptr
      && ChatModelHasCapability(model->capabilities, "tools");
  ProviderChatBuildResult build;
  if ( agent_enabled )
  {
    if ( !agent_tools_.Available() )
    {
      chat_panel_.AppendSystem(ToolsUnavailableMessage);
      PersistTranscript();
      return;
    }
    std::vector<AgentToolDefinition> tools = agent_tools_.Definitions();
    const auto &effects = AgentEffectToolDefinitions();
    tools.insert(tools.end(), effects.begin(), effects.end());
    AgentLoopStep step = agent_loop_.Begin(
        *active,
        messages,
        std::string(AgentSystemPrompt()),
        std::move(tools));
    if ( step.error )
    {
      chat_panel_.AppendSystem(step.safe_message);
      PersistTranscript();
      return;
    }
    build = std::move(step.build);
  }
  else
  {
    build = BuildProviderChatRequest(*active, messages);
  }
  if ( build.error )
  {
    chat_panel_.AppendSystem(
        build.safe_message.empty()
            ? std::string(ProviderChatConfigurationErrorMessage)
            : build.safe_message);
    PersistTranscript();
    return;
  }
  build.request.log_session_id = conversation_session_id_;
  CaptureContextUsage(build, messages.size(), agent_enabled);
  request_purpose_ = RequestPurpose::Conversation;

  chat_panel_.BeginAssistantPreview();
  chat_session_ = std::make_unique<ProviderChatSession>();
  if ( !chat_session_->Start(
           AiMenuRegistry::Instance().StreamClientInstance(),
           std::move(build)) )
  {
    chat_session_.reset();
    chat_panel_.DiscardAssistantPreview();
    chat_panel_.DiscardReasoningPreview();
    chat_panel_.AppendSystem(ProviderChatTransportErrorMessage);
    PersistTranscript();
    return;
  }
  request_cancelling_ = false;
  pending_conversation_action_ = PendingConversationAction::None;
  local_request_error_.clear();
  OpenChat();
}

void AiMenuController::PollChatRequest()
{
  if ( !HasActiveRequest() )
    return;
  if ( request_purpose_ == RequestPurpose::Compaction )
  {
    PollContextCompaction();
    return;
  }

  if ( pending_tool_job_ != 0 )
  {
    if ( agent_loop_.DeadlineExpired() )
    {
      agent_tools_.CancelAndForget(pending_tool_job_);
      pending_tool_job_ = 0;
      AdvanceEffectGeneration();
      agent_loop_.Reset();
      chat_panel_.ClearTransientStatus();
      chat_panel_.AppendSystem("Tool execution stopped at the Agent deadline.");
      chat_panel_.AppendSystem(AgentLoopLimitMessage);
      PersistTranscript();
      return;
    }
    std::optional<std::vector<AgentToolResult>> results =
        agent_tools_.TryTake(pending_tool_job_);
    if ( !results.has_value() )
      return;
    pending_tool_job_ = 0;
    CollectReadOnlyToolResults(std::move(*results));
    return;
  }

  if ( !pending_effect_calls_.empty() )
    return;

  for ( std::size_t count = 0; count < 64 && HasActiveRequest(); ++count )
  {
    ProviderChatSessionEvent event = chat_session_->Poll();
    if ( event.kind == ProviderChatSessionEventKind::None )
      break;
    if ( event.kind == ProviderChatSessionEventKind::Delta )
    {
      if ( local_request_error_.empty()
          && ((!event.reasoning_delta.empty()
               && !chat_panel_.AppendReasoningPreview(event.reasoning_delta))
              || (!event.text_delta.empty()
                  && !chat_panel_.AppendAssistantPreview(event.text_delta))) )
      {
        local_request_error_ = PreviewLimitMessage;
        request_cancelling_ = true;
        chat_session_->Cancel();
      }
      // Keep draining the bounded queue. ChatPanel batches display insertion
      // on the UI-thread poll timer and terminal paths flush synchronously.
      continue;
    }

    if ( event.kind == ProviderChatSessionEventKind::ToolCalls )
    {
      chat_session_.reset();
      const bool committed_reasoning = chat_panel_.CommitReasoningPreview();
      const bool committed_assistant = chat_panel_.CommitAssistantPreview();
      if ( committed_reasoning || committed_assistant )
        PersistTranscript();
      if ( !agent_loop_.Active() )
      {
        chat_panel_.AppendSystem(UnexpectedToolCallMessage);
        PersistTranscript();
        return;
      }
      AgentLoopStep step = agent_loop_.BeginToolRound(
          event.calls, std::move(event.assistant_text));
      if ( step.error )
      {
        chat_panel_.ClearTransientStatus();
        agent_loop_.Reset();
        chat_panel_.AppendSystem(step.safe_message);
        PersistTranscript();
        return;
      }

      BeginAgentToolBatch(event.calls);
      return;
    }

    const PendingConversationAction conversation_action =
        pending_conversation_action_;
    if ( !local_request_error_.empty() )
    {
      event.kind = ProviderChatSessionEventKind::Error;
      event.safe_message = local_request_error_;
    }
    request_cancelling_ = false;
    pending_conversation_action_ = PendingConversationAction::None;
    local_request_error_.clear();
    chat_session_.reset();

    if ( conversation_action != PendingConversationAction::None )
    {
      agent_loop_.Reset();
      chat_panel_.ClearTransientStatus();
      chat_panel_.DiscardAssistantPreview();
      chat_panel_.DiscardReasoningPreview();
      if ( conversation_action == PendingConversationAction::New )
        StartNewConversation();
      else
        ClearCurrentConversation();
      return;
    }
    if ( event.kind == ProviderChatSessionEventKind::Completed )
    {
      chat_panel_.CommitReasoningPreview();
      if ( !chat_panel_.CommitAssistantPreview() )
      {
        chat_panel_.DiscardAssistantPreview();
        chat_panel_.AppendSystem(EmptyResponseMessage);
      }
      agent_loop_.Complete();
    }
    else
    {
      agent_loop_.Reset();
      chat_panel_.ClearTransientStatus();
      chat_panel_.CommitReasoningPreview();
      chat_panel_.DiscardAssistantPreview();
      if ( event.kind == ProviderChatSessionEventKind::Cancelled )
        chat_panel_.AppendSystem(CancelledMessage);
      else
        chat_panel_.AppendSystem(
            event.safe_message.empty()
                ? std::string(ProviderChatTransportErrorMessage)
                : event.safe_message);
    }
    PersistTranscript();
    if ( event.kind == ProviderChatSessionEventKind::Completed )
      MaybeAutoCompactContext();
    return;
  }
}

void AiMenuController::BeginAgentToolBatch(
    const std::vector<AgentToolCall> &calls)
{
  pending_tool_results_.clear();
  pending_tool_results_.resize(calls.size());
  pending_read_only_indices_.clear();
  pending_effect_calls_.clear();

  for ( const AgentToolCall &call : calls )
  {
    if ( !chat_panel_.AppendTool(FormatAgentToolCallTranscript(call)) )
    {
      AbortAgentToolBatchForTranscriptFailure();
      return;
    }
  }
  PersistTranscript();

  const AgentEffectApprovalPolicy policy = CurrentEffectPolicy();
  effect_coordinator_.UpdateBinding(CurrentEffectBinding());
  std::vector<AgentToolCall> read_only_calls;
  for ( std::size_t index = 0; index < calls.size(); ++index )
  {
    const AgentToolCall &call = calls[index];
    if ( std::optional<AgentToolResult> result =
             agent_loop_.InvokeCatalogTool(call) )
    {
      pending_tool_results_[index] = std::move(*result);
      continue;
    }
    if ( !IsEffectTool(call.name) )
    {
      pending_read_only_indices_.push_back(index);
      read_only_calls.push_back(call);
      continue;
    }
    if ( policy == AgentEffectApprovalPolicy::Deny )
    {
      pending_tool_results_[index] = DeniedEffectResult(call);
      continue;
    }

    const AgentEffectPrepareResult prepared = effect_coordinator_.Prepare(call);
    if ( !prepared.plan().has_value() )
    {
      pending_tool_results_[index] = AgentToolResult{
          call.id,
          call.name,
          false,
          {},
          prepared.safe_message().empty()
              ? "The side effect could not be prepared safely."
              : prepared.safe_message(),
      };
      continue;
    }
    pending_effect_calls_.push_back({
        index,
        prepared.plan()->prepared_id(),
        prepared.plan()->safe_summary(),
        prepared.plan()->call(),
    });
  }

  if ( !read_only_calls.empty() )
  {
    pending_tool_job_ = agent_tools_.Submit(std::move(read_only_calls));
    if ( pending_tool_job_ == 0 )
    {
      for ( const std::size_t index : pending_read_only_indices_ )
      {
        pending_tool_results_[index] = AgentToolResult{
            calls[index].id,
            calls[index].name,
            false,
            {},
            ToolsUnavailableMessage,
        };
      }
      pending_read_only_indices_.clear();
    }
  }

  if ( policy == AgentEffectApprovalPolicy::Allow )
  {
    DecidePendingEffects(true);
    return;
  }
  if ( policy == AgentEffectApprovalPolicy::Ask
      && !pending_effect_calls_.empty() )
  {
    std::vector<AgentToolCall> prepared_calls;
    prepared_calls.reserve(pending_effect_calls_.size());
    for ( const PendingEffectCall &effect : pending_effect_calls_ )
      prepared_calls.push_back(effect.call);
    const auto script_sources = ParsePreparedScriptSources(prepared_calls);
    const ChatScriptApprovalRoute script_route = RoutePreparedScriptApproval(
        policy, script_sources);
    if ( script_route == ChatScriptApprovalRoute::DenySession )
    {
      DenySessionEffects();
      PersistTranscript();
      return;
    }
    if ( script_route == ChatScriptApprovalRoute::ShowDialog )
    {
      agent_loop_.PauseDeadline();
      const ChatScriptApprovalDecision decision =
          chat_panel_.ConfirmScriptExecution(*script_sources);
      if ( decision == ChatScriptApprovalDecision::AllowSessionAndExecute )
        AllowSessionEffects();
      else
        DenySessionEffects();
      PersistTranscript();
      return;
    }

    agent_loop_.PauseDeadline();
    std::string status = std::to_string(pending_effect_calls_.size())
        + " side effect(s) are prepared. Type /y to allow all side effects "
          "for this conversation session, or /n to deny all.";
    for ( std::size_t index = 0; index < pending_effect_calls_.size(); ++index )
    {
      const PendingEffectCall &effect = pending_effect_calls_[index];
      status += "\n\n" + std::to_string(index + 1) + ". "
          + effect.call.name + "\n" + effect.safe_summary;
    }
    chat_panel_.SetTransientStatus(std::move(status));
    PersistTranscript();
    return;
  }
  MaybeCompleteAgentToolBatch();
}

void AiMenuController::CollectReadOnlyToolResults(
    std::vector<AgentToolResult> results)
{
  if ( results.size() != pending_read_only_indices_.size() )
  {
    pending_tool_results_.clear();
    pending_read_only_indices_.clear();
    pending_effect_calls_.clear();
    effect_coordinator_.Invalidate();
    agent_loop_.Reset();
    chat_panel_.ClearTransientStatus();
    chat_panel_.AppendSystem("IDA analysis tools returned an invalid batch.");
    PersistTranscript();
    return;
  }
  for ( std::size_t index = 0; index < results.size(); ++index )
    pending_tool_results_[pending_read_only_indices_[index]] = std::move(results[index]);
  pending_read_only_indices_.clear();
  MaybeCompleteAgentToolBatch();
}

void AiMenuController::DecidePendingEffects(bool confirm)
{
  if ( pending_effect_calls_.empty() )
    return;
  agent_loop_.ResumeDeadline();
  std::vector<PendingEffectCall> effects = std::move(pending_effect_calls_);
  pending_effect_calls_.clear();
  const AgentEffectBinding binding = CurrentEffectBinding();
  for ( const PendingEffectCall &effect : effects )
  {
    const AgentEffectDecisionResult decision = confirm
        ? effect_coordinator_.Confirm(effect.prepared_id, binding)
        : effect_coordinator_.Reject(effect.prepared_id, binding);
    AgentToolResult result = decision.tool_result();
    if ( result.call_id.empty() )
    {
      result.call_id = effect.call.id;
      result.name = effect.call.name;
    }
    pending_tool_results_[effect.result_index] = std::move(result);
  }
  MaybeCompleteAgentToolBatch();
}

void AiMenuController::MaybeCompleteAgentToolBatch()
{
  if ( pending_tool_job_ != 0 || !pending_effect_calls_.empty()
      || pending_tool_results_.empty() )
  {
    return;
  }
  if ( std::any_of(
           pending_tool_results_.begin(), pending_tool_results_.end(),
           [](const std::optional<AgentToolResult> &result)
           { return !result.has_value(); }) )
  {
    return;
  }

  std::vector<AgentToolResult> results;
  results.reserve(pending_tool_results_.size());
  for ( std::optional<AgentToolResult> &result : pending_tool_results_ )
    results.push_back(std::move(*result));
  pending_tool_results_.clear();
  pending_read_only_indices_.clear();
  CompleteAgentToolResults(std::move(results));
}

void AiMenuController::CompleteAgentToolResults(
    std::vector<AgentToolResult> results)
{
  chat_panel_.ClearTransientStatus();
  for ( const AgentToolResult &result : results )
  {
    if ( !chat_panel_.AppendTool(FormatAgentToolResultTranscript(result)) )
    {
      AbortAgentToolBatchForTranscriptFailure();
      return;
    }
  }
  if ( !results.empty() )
    PersistTranscript();
  AgentLoopStep step = agent_loop_.CompleteToolRound(std::move(results));
  if ( step.error )
  {
    agent_loop_.Reset();
    chat_panel_.AppendSystem(step.safe_message);
    PersistTranscript();
    return;
  }
  CaptureContextUsage(
      step.build,
      context_usage_.total_messages,
      true);
  step.build.request.log_session_id = conversation_session_id_;
  chat_panel_.BeginAssistantPreview();
  chat_session_ = std::make_unique<ProviderChatSession>();
  if ( !chat_session_->Start(
           AiMenuRegistry::Instance().StreamClientInstance(),
           std::move(step.build)) )
  {
    chat_session_.reset();
    agent_loop_.Reset();
    chat_panel_.DiscardAssistantPreview();
    chat_panel_.DiscardReasoningPreview();
    chat_panel_.AppendSystem(ProviderChatTransportErrorMessage);
    PersistTranscript();
  }
}

void AiMenuController::AbortAgentToolBatchForTranscriptFailure()
{
  AdvanceEffectGeneration();
  agent_loop_.Reset();
  chat_panel_.ClearTransientStatus();
  chat_panel_.AppendSystem(ToolTranscriptErrorMessage);
  PersistTranscript();
}

void AiMenuController::AllowSessionEffects()
{
  SetCurrentEffectPolicy(AgentEffectApprovalPolicy::Allow);
  if ( pending_effect_calls_.empty() )
  {
    chat_panel_.AppendSystem(
        "Side effects are now allowed for this conversation session.");
    return;
  }
  chat_panel_.AppendSystem(
      "Side effects are now allowed for this conversation session; "
      "executing the prepared batch.");
  DecidePendingEffects(true);
}

void AiMenuController::DenySessionEffects()
{
  SetCurrentEffectPolicy(AgentEffectApprovalPolicy::Deny);
  if ( pending_effect_calls_.empty() )
  {
    chat_panel_.AppendSystem(
        "Side effects are now denied for this conversation session.");
    return;
  }
  chat_panel_.AppendSystem(
      "Side effects are now denied for this conversation session; "
      "rejecting the prepared batch.");
  DecidePendingEffects(false);
}

void AiMenuController::CancelActive(PendingConversationAction action) noexcept
{
  if ( !HasActiveRequest() )
    return;
  if ( pending_tool_job_ != 0 || !pending_tool_results_.empty() )
  {
    if ( pending_tool_job_ != 0 )
      agent_tools_.CancelAndForget(pending_tool_job_);
    pending_tool_job_ = 0;
    AdvanceEffectGeneration();
    agent_loop_.Reset();
    chat_panel_.ClearTransientStatus();
    chat_panel_.DiscardAssistantPreview();
    chat_panel_.DiscardReasoningPreview();
    chat_panel_.AppendSystem(
        "Tool batch cancelled; no remaining prepared side effects were executed.");
    PersistTranscript();
    if ( action == PendingConversationAction::New )
      StartNewConversation();
    else if ( action == PendingConversationAction::Clear )
      ClearCurrentConversation();
    else
      chat_panel_.AppendSystem(CancelledMessage);
    return;
  }
  if ( action != PendingConversationAction::None )
    pending_conversation_action_ = action;
  AdvanceEffectGeneration();
  request_cancelling_ = true;
  chat_session_->Cancel();
}

void AiMenuController::CancelRequest()
{
  if ( !HasActiveRequest() )
  {
    chat_panel_.AppendSystem("No AI request is active.");
    return;
  }
  CancelActive();
}

bool AiMenuController::HasActiveRequest() const noexcept
{
  return (chat_session_ != nullptr && chat_session_->IsActive())
      || pending_tool_job_ != 0
      || !pending_tool_results_.empty();
}

} // namespace ida_agent::ai
