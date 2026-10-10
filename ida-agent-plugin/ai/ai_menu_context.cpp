#include "ai/ai_menu.hpp"

#include "ai/ai_menu_registry.hpp"
#include "ai/agent_prompt.hpp"
#include "ai/agent_tool_catalog.hpp"
#include "ai/agent_tool_registry.hpp"
#include "ai/provider_chat_session.hpp"

#include <algorithm>
#include <utility>

namespace ida_agent::ai
{
namespace
{

constexpr std::uint32_t CompactionMaxOutputTokens = 8192;

std::vector<AgentToolDefinition> ContextAgentTools(
    const AgentToolRegistry &registry)
{
  std::vector<AgentToolDefinition> tools = registry.Definitions();
  const auto &effects = AgentEffectToolDefinitions();
  tools.insert(tools.end(), effects.begin(), effects.end());
  return tools;
}

} // namespace

void AiMenuController::CaptureContextUsage(
    const ProviderChatBuildResult &build,
    std::size_t total_messages,
    bool agent_tools)
{
  context_usage_ = MakeChatContextUsage(
      build,
      chat_panel_.Entries(),
      total_messages,
      agent_tools);
}

bool AiMenuController::RefreshContextUsage()
{
  ProviderSettingsSnapshot providers =
      AiMenuRegistry::Instance().ProviderSettings();
  const ProviderProfileDraft *active = ActiveProvider(providers.Manager());
  if ( active == nullptr )
  {
    context_usage_ = {};
    return false;
  }
  const ProviderModelDraft *model = SelectedChatModel(*active);
  if ( model == nullptr )
  {
    context_usage_ = {};
    return false;
  }

  std::vector<ProviderChatMessage> messages =
      BuildConversationMessages(chat_panel_.Entries());
  if ( messages.empty() )
    messages.push_back({ProviderChatRole::User, {}});
  const bool agent_enabled = ChatModelHasCapability(model->capabilities, "tools");
  ProviderChatBuildResult build;
  if ( agent_enabled )
  {
    ProviderChatAgentOptions options;
    options.system_prompt = std::string(AgentSystemPrompt());
    options.tools = InitialAgentToolDefinitions(
        ContextAgentTools(agent_tools_));
    build = BuildProviderAgentRequest(*active, messages, options);
  }
  else
  {
    build = BuildProviderChatRequest(*active, messages);
  }
  CaptureContextUsage(build, messages.size(), agent_enabled);
  return context_usage_.valid;
}

void AiMenuController::ShowContextUsage(bool detailed)
{
  if ( !HasActiveRequest() )
    RefreshContextUsage();
  chat_panel_.AppendSystem(FormatChatContextUsage(context_usage_, detailed));
}

void AiMenuController::CompactContext(bool automatic)
{
  if ( HasActiveRequest() )
  {
    if ( !automatic )
      chat_panel_.AppendSystem("An AI request is already active.");
    return;
  }
  const std::optional<ChatCompactionPlan> plan =
      PlanChatCompaction(chat_panel_.Entries());
  if ( !plan.has_value() )
  {
    if ( !automatic )
    {
      chat_panel_.AppendSystem(
          "There is not enough older conversation context to compact yet.");
    }
    return;
  }

  ProviderSettingsSnapshot providers =
      AiMenuRegistry::Instance().ProviderSettings();
  const ProviderProfileDraft *active = ActiveProvider(providers.Manager());
  if ( active == nullptr || SelectedChatModel(*active) == nullptr )
  {
    chat_panel_.AppendSystem(ProviderChatConfigurationErrorMessage);
    return;
  }
  ProviderProfileDraft compact_profile = *active;
  for ( ProviderModelDraft &model : compact_profile.models )
  {
    if ( model.id == compact_profile.settings.model )
    {
      model.max_output_tokens = (std::min)(
          model.max_output_tokens, CompactionMaxOutputTokens);
      model.reasoning_summary = ProviderReasoningSummary::Hidden;
      break;
    }
  }
  const std::vector<ProviderChatMessage> messages{
      {ProviderChatRole::User, plan->prompt},
  };
  ProviderChatBuildResult build =
      BuildProviderChatRequest(compact_profile, messages);
  if ( build.error )
  {
    chat_panel_.AppendSystem(
        build.safe_message.empty()
            ? std::string(ProviderChatConfigurationErrorMessage)
            : build.safe_message);
    return;
  }

  build.request.log_session_id = conversation_session_id_;
  CaptureContextUsage(build, messages.size(), false);
  chat_session_ = std::make_unique<ProviderChatSession>();
  if ( !chat_session_->Start(
           AiMenuRegistry::Instance().StreamClientInstance(),
           std::move(build)) )
  {
    chat_session_.reset();
    chat_panel_.AppendSystem(ProviderChatTransportErrorMessage);
    return;
  }
  request_purpose_ = RequestPurpose::Compaction;
  compaction_retained_entries_ = plan->retained_entries;
  compaction_summarized_entries_ = plan->summarized_entries;
  compaction_summarized_bytes_ = plan->summarized_bytes;
  compaction_automatic_ = automatic;
  compaction_preview_.Begin();
  request_cancelling_ = false;
  pending_conversation_action_ = PendingConversationAction::None;
  local_request_error_.clear();
  chat_panel_.SetTransientStatus(
      std::string(automatic ? "Context limit reached; automatically compacting "
                            : "Compacting ")
      + std::to_string(plan->summarized_entries)
      + " older context entries...");
  OpenChat();
}

void AiMenuController::PollContextCompaction()
{
  for ( std::size_t count = 0; count < 64 && HasActiveRequest(); ++count )
  {
    ProviderChatSessionEvent event = chat_session_->Poll();
    if ( event.kind == ProviderChatSessionEventKind::None )
      return;
    if ( event.kind == ProviderChatSessionEventKind::Delta )
    {
      if ( !event.text_delta.empty()
          && !compaction_preview_.Append(event.text_delta) )
      {
        local_request_error_ = "Context compaction response exceeded the text limit.";
        request_cancelling_ = true;
        chat_session_->Cancel();
      }
      continue;
    }
    if ( event.kind == ProviderChatSessionEventKind::ToolCalls )
    {
      event.kind = ProviderChatSessionEventKind::Error;
      event.safe_message =
          "The context compaction request returned unexpected tools.";
    }

    const PendingConversationAction action = pending_conversation_action_;
    request_cancelling_ = false;
    pending_conversation_action_ = PendingConversationAction::None;
    chat_session_.reset();
    chat_panel_.ClearTransientStatus();
    if ( action != PendingConversationAction::None )
    {
      ClearCompactionState();
      if ( action == PendingConversationAction::New )
        StartNewConversation();
      else
        ClearCurrentConversation();
      return;
    }

    bool persist = false;
    if ( event.kind == ProviderChatSessionEventKind::Completed
        && local_request_error_.empty()
        && compaction_preview_.HasValue()
        && !compaction_preview_.Text().empty() )
    {
      std::vector<ChatEntry> compacted;
      compacted.reserve(compaction_retained_entries_.size() + 2);
      compacted.push_back({ChatSpeaker::Context, compaction_preview_.Text()});
      compacted.insert(
          compacted.end(),
          compaction_retained_entries_.begin(),
          compaction_retained_entries_.end());
      const std::size_t summarized_entries = compaction_summarized_entries_;
      const std::size_t summarized_bytes = compaction_summarized_bytes_;
      const bool automatic = compaction_automatic_;
      if ( !chat_panel_.Restore(std::move(compacted)) )
      {
        chat_panel_.SetTransientStatus(
            "Context compaction result could not be applied.");
      }
      else
      {
        chat_panel_.AppendSystem(
            std::string(automatic ? "Automatic context compaction completed: "
                                  : "Context compaction completed: ")
            + std::to_string(summarized_entries) + " entries / "
            + std::to_string(summarized_bytes) + " bytes summarized.");
        persist = true;
      }
    }
    else if ( !local_request_error_.empty() )
    {
      chat_panel_.SetTransientStatus(local_request_error_);
    }
    else if ( event.kind == ProviderChatSessionEventKind::Cancelled )
    {
      chat_panel_.SetTransientStatus("Context compaction was cancelled.");
    }
    else
    {
      chat_panel_.SetTransientStatus(
          event.safe_message.empty()
              ? std::string(ProviderChatTransportErrorMessage)
              : event.safe_message);
    }
    ClearCompactionState();
    if ( persist )
      PersistTranscript();
    RefreshContextUsage();
    return;
  }
}

void AiMenuController::MaybeAutoCompactContext()
{
  if ( HasActiveRequest() || !RefreshContextUsage() )
  {
    return;
  }
  if ( ShouldAutoCompactContext(context_usage_) )
    CompactContext(true);
}

void AiMenuController::ClearCompactionState() noexcept
{
  request_purpose_ = RequestPurpose::Conversation;
  compaction_retained_entries_.clear();
  compaction_preview_.Discard();
  compaction_summarized_entries_ = 0;
  compaction_summarized_bytes_ = 0;
  compaction_automatic_ = false;
  local_request_error_.clear();
}

} // namespace ida_agent::ai
