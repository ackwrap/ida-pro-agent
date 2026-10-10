#include "ai/ai_menu.hpp"

#include "ai/agent_effect_service.hpp"
#include "ai/ai_menu_registry.hpp"
#include "ai/cli_command.hpp"
#include "ai/plugin_settings.hpp"
#include "ai/plugin_settings_dialog.hpp"
#include "ai/provider_chat_session.hpp"
#include "ai/provider_settings_dialog.hpp"
#include "ai/update_controller.hpp"

#include <ida.hpp>
#include <kernwin.hpp>

#include <chrono>
#include <cstdint>
#include <exception>
#include <string>

namespace ida_agent::ai
{
namespace
{

const char *EffectPolicyName(AgentEffectApprovalPolicy policy) noexcept
{
  switch ( policy )
  {
    case AgentEffectApprovalPolicy::Ask:
      return "ask";
    case AgentEffectApprovalPolicy::Allow:
      return "allow";
    case AgentEffectApprovalPolicy::Deny:
      return "deny";
  }
  return "ask";
}

} // namespace

AiMenuController::AiMenuController(
    const void *action_owner,
    AgentToolRegistry &agent_tools,
    AgentEffectService &agent_effects)
    : action_owner_(action_owner), agent_tools_(agent_tools),
      agent_effects_(agent_effects),
      effect_coordinator_(
          AgentEffectBinding(1, "-1", {}),
          [&agent_effects](AgentEffectName effect, const AgentToolCall &call)
          {
            return agent_effects.Prepare(effect, call);
          },
          [&agent_effects](
              AgentEffectName effect,
              const AgentToolCall &call,
              const std::string &payload)
          {
            return agent_effects.Execute(effect, call, payload);
          })
{
  chat_panel_.SetSubmitHandler([this](std::string line)
  {
    try
    {
      ExecuteCliLine(line.c_str());
    }
    catch ( const std::exception &error )
    {
      msg("[ida-agent] AI input failed: %s\n", error.what());
    }
    catch ( ... )
    {
      msg("[ida-agent] AI input failed\n");
    }
    AiMenuRegistry::Instance().RefreshRequestActions();
  });
  chat_panel_.SetPollHandler([this]()
  {
    try
    {
      PollChatRequest();
    }
    catch ( ... )
    {
      msg("[ida-agent] AI stream polling failed\n");
      if ( HasActiveRequest() )
      {
        local_request_error_ = ProviderChatTransportErrorMessage;
        CancelActive();
      }
    }
    AiMenuRegistry::Instance().RefreshRequestActions();
  });
  chat_panel_.SetCloseHandler([this]()
  {
    CancelActive();
  });
}

AiMenuController::~AiMenuController()
{
  Stop();
}

bool AiMenuController::Start() noexcept
{
  try
  {
    if ( started_ )
      return true;
    database_context_id_ = get_dbctx_id();
    if ( database_context_id_ < 0 )
      return false;
    chat_panel_.SetTitle("IDA Agent AI [" + std::to_string(database_context_id_) + "]");
    chat_panel_.Reset();
    history_write_blocked_ = false;
    persistence_warning_shown_ = false;
    history_store_opened_ = false;
    effect_coordinator_.UpdateBinding(CurrentEffectBinding());
    InitializeHistory();
    if ( !AiMenuRegistry::Instance().Add(
             database_context_id_,
             this,
             action_owner_) )
    {
      database_context_id_ = -1;
      msg("[ida-agent] failed to register AI menu\n");
      return false;
    }
    started_ = true;
    return true;
  }
  catch ( const std::exception &error )
  {
    database_context_id_ = -1;
    msg("[ida-agent] failed to start AI UI: %s\n", error.what());
    return false;
  }
  catch ( ... )
  {
    database_context_id_ = -1;
    msg("[ida-agent] failed to start AI UI\n");
    return false;
  }
}

void AiMenuController::Stop(bool unregister_actions) noexcept
{
  if ( !started_ )
    return;
  if ( !unregister_actions )
    AiMenuRegistry::Instance().Updates().Stop();
  const auto trace = [this](const char *phase) noexcept
  {
    if ( !lifecycle_trace_ )
      return;
    try
    {
      lifecycle_trace_(phase);
    }
    catch ( ... )
    {
    }
  };
  const auto started_at = std::chrono::steady_clock::now();
  if ( pending_tool_job_ != 0 )
  {
    agent_tools_.CancelAndForget(pending_tool_job_);
    pending_tool_job_ = 0;
  }
  AdvanceEffectGeneration();
  CancelActive();
  agent_loop_.Reset();
  chat_panel_.ClearTransientStatus();
  chat_panel_.DiscardAssistantPreview();
  chat_panel_.DiscardReasoningPreview();
  trace("ai.stop.panel.begin");
  chat_panel_.Close();
  trace("ai.stop.panel.end");
  chat_session_.reset();
  const auto panel_closed_at = std::chrono::steady_clock::now();
  trace("ai.stop.registry.remove.begin");
  AiMenuRegistry::Instance().Remove(
      database_context_id_,
      this,
      unregister_actions,
      [trace](const char *phase) { trace(phase); });
  trace("ai.stop.registry.remove.end");
  const auto menu_removed_at = std::chrono::steady_clock::now();
  started_ = false;
  auto_opened_ = false;
  history_store_opened_ = false;
  database_context_id_ = -1;
  const auto total = std::chrono::duration_cast<std::chrono::milliseconds>(
      menu_removed_at - started_at);
  if ( total > std::chrono::milliseconds(100) )
  {
    const auto panel = std::chrono::duration_cast<std::chrono::milliseconds>(
        panel_closed_at - started_at);
    const auto menu = std::chrono::duration_cast<std::chrono::milliseconds>(
        menu_removed_at - panel_closed_at);
    msg(
        "[ida-agent] slow AI UI shutdown: panel=%lldms menu=%lldms total=%lldms\n",
        static_cast<long long>(panel.count()),
        static_cast<long long>(menu.count()),
        static_cast<long long>(total.count()));
  }
}

void AiMenuController::SetLifecycleTrace(
    std::function<void(const char *)> trace)
{
  lifecycle_trace_ = std::move(trace);
}

void AiMenuController::UiReady() noexcept
{
  try
  {
    if ( !AiMenuRegistry::Instance().SetUiReady() )
      msg("[ida-agent] failed to register AI menu after UI initialization\n");
    MaybeAutoOpenChat();
  }
  catch ( const std::exception &error )
  {
    msg("[ida-agent] failed to register AI menu after UI initialization: %s\n", error.what());
  }
  catch ( ... )
  {
    msg("[ida-agent] failed to register AI menu after UI initialization\n");
  }
}

void AiMenuController::DatabaseInitialized() noexcept
{
  try
  {
    if ( !started_ )
    {
      if ( !Start() )
        return;
    }
    else if ( !history_store_opened_ )
    {
      InitializeHistory();
    }
    AdvanceEffectGeneration();
    effect_coordinator_.UpdateBinding(CurrentEffectBinding());
    MaybeAutoOpenChat();
  }
  catch ( const std::exception &error )
  {
    msg("[ida-agent] failed to initialize AI history: %s\n", error.what());
  }
  catch ( ... )
  {
    msg("[ida-agent] failed to initialize AI history\n");
  }
}

void AiMenuController::OpenChat()
{
  if ( !chat_panel_.Open(true) )
    warning("AUTOHIDE NONE\nUnable to open the IDA Agent AI panel.");
  else
    auto_opened_ = true;
}

void AiMenuController::NewConversation()
{
  if ( HasActiveRequest() )
    CancelActive(PendingConversationAction::New);
  else
    StartNewConversation();
  OpenChat();
}

void AiMenuController::SetChatInputText(std::string text)
{
  try
  {
    chat_panel_.SetInputText(std::move(text));
  }
  catch ( const std::exception &error )
  {
    msg("[ida-agent] failed to fill the AI input: %s\n", error.what());
  }
  catch ( ... )
  {
    msg("[ida-agent] failed to fill the AI input\n");
  }
}

bool AiMenuController::ExecuteCliLine(const char *line)
{
  const CliCommand command = ParseCliCommand(line == nullptr ? "" : line);
  switch ( command.kind )
  {
    case CliCommandKind::Empty:
      return true;
    case CliCommandKind::Help:
      {
        std::string help = "Commands:";
        for ( const CliCommandDefinition &definition : AvailableCliCommands() )
          help += "\n  " + std::string(definition.command) + " - "
              + std::string(definition.description);
        help += "\nNormal text is sent to the configured provider and model.";
        chat_panel_.AppendSystem(help);
      }
      break;
    case CliCommandKind::NewConversation:
      NewConversation();
      break;
    case CliCommandKind::ClearConversation:
      if ( HasActiveRequest() )
        CancelActive(PendingConversationAction::Clear);
      else
        ClearCurrentConversation();
      break;
    case CliCommandKind::Compact:
      CompactContext();
      break;
    case CliCommandKind::Cancel:
      CancelRequest();
      break;
    case CliCommandKind::AllowSessionEffects:
      AllowSessionEffects();
      break;
    case CliCommandKind::DenySessionEffects:
      DenySessionEffects();
      break;
    case CliCommandKind::Provider:
      {
        const ProviderSettingsSnapshot providers =
            AiMenuRegistry::Instance().ProviderSettings();
        const ProviderProfileDraft *active = ActiveProvider(providers.Manager());
        if ( active == nullptr )
        {
          chat_panel_.AppendSystem("No provider is selected.");
          break;
        }
        std::string summary = "Current provider: " + active->settings.display_name
            + " (" + active->settings.base_url + ")";
        if ( !active->settings.model.empty() )
          summary += ", model=" + active->settings.model;
        chat_panel_.AppendSystem(summary);
      }
      break;
    case CliCommandKind::Providers:
      ShowProviderSettings();
      break;
    case CliCommandKind::Model:
      {
        const ProviderSettingsSnapshot providers =
            AiMenuRegistry::Instance().ProviderSettings();
        const ProviderProfileDraft *active = ActiveProvider(providers.Manager());
        if ( active == nullptr || active->settings.model.empty() )
          chat_panel_.AppendSystem("No default model is selected.");
        else
          chat_panel_.AppendSystem("Current model: " + active->settings.model + ".");
      }
      break;
    case CliCommandKind::Models:
      {
        const ProviderSettingsSnapshot providers =
            AiMenuRegistry::Instance().ProviderSettings();
        const ProviderProfileDraft *active = ActiveProvider(providers.Manager());
        if ( active == nullptr || active->models.empty() )
        {
          chat_panel_.AppendSystem("No models are configured for the current provider.");
          break;
        }
        std::string models = "Configured models:";
        for ( const ProviderModelDraft &model : active->models )
        {
          models += "\n  " + model.id;
          if ( !model.enabled )
            models += " (disabled)";
          if ( model.id == active->settings.model )
            models += " (default)";
          models += " [reasoning="
              + std::string(ProviderReasoningEffortName(model.reasoning_effort))
              + ", summary="
              + std::string(ProviderReasoningSummaryName(model.reasoning_summary))
              + "]";
        }
        chat_panel_.AppendSystem(models);
      }
      break;
    case CliCommandKind::Status:
      {
        const PluginSettings settings = AiMenuRegistry::Instance().Settings();
        const ProviderSettingsSnapshot providers =
            AiMenuRegistry::Instance().ProviderSettings();
        const ProviderProfileDraft *active = ActiveProvider(providers.Manager());
        std::string status = "Session status: provider=";
        status += active == nullptr ? "none" : active->settings.display_name;
        status += ", model=";
        status += active == nullptr || active->settings.model.empty()
            ? "none"
            : active->settings.model;
        status += ", history_entries=" + std::to_string(chat_panel_.Entries().size());
        if ( !history_store_.ActiveSessionId().empty() )
          status += ", session=" + history_store_.ActiveSessionId().substr(0, 8);
        if ( !settings.save_chat_history )
          status += ", history=saving-disabled";
        else
          status += history_write_blocked_ ? ", history=memory-only" : ", history=sqlite";
        status += ", request=";
        status += HasActiveRequest()
            ? (request_cancelling_
                    ? "cancelling"
                    : (!pending_effect_calls_.empty()
                           ? "awaiting-session-policy"
                           : (pending_tool_job_ != 0
                                   ? "executing-tools" : "streaming")))
            : "idle";
        status += ", side_effect_policy=";
        status += EffectPolicyName(CurrentEffectPolicy());
        if ( !HasActiveRequest() )
          RefreshContextUsage();
        status += ".\n" + FormatChatContextUsage(context_usage_, false);
        chat_panel_.AppendSystem(status);
      }
      break;
    case CliCommandKind::History:
      if ( !history_store_opened_ && !OpenHistoryStore() )
      {
        chat_panel_.AppendSystem(
            "Conversation history is unavailable; this session remains in memory.");
      }
      else
      {
        const ChatSessionListResult sessions = history_store_.ListSessions();
        if ( sessions.status == ChatHistoryLoadStatus::Unavailable
            || sessions.status == ChatHistoryLoadStatus::Invalid )
        {
          chat_panel_.AppendSystem("Conversation history could not be read.");
          break;
        }
        if ( sessions.sessions.empty() )
        {
          chat_panel_.AppendSystem("No stored conversations.");
          break;
        }
        std::string summary = "Stored conversations:";
        for ( std::size_t index = 0; index < sessions.sessions.size(); ++index )
        {
          const ChatSessionSummary &session = sessions.sessions[index];
          summary += "\n  " + std::to_string(index + 1) + ". ";
          summary += session.id == sessions.active_session_id ? "* " : "  ";
          summary += session.title + " [" + session.id.substr(0, 8) + ", ";
          summary += std::to_string(session.entry_count) + " entries]";
        }
        summary += "\nUse /session <number-or-id> to switch.";
        chat_panel_.AppendSystem(summary);
      }
      break;
    case CliCommandKind::SelectSession:
      SelectConversation(command.text);
      break;
    case CliCommandKind::Context:
      ShowContextUsage(true);
      break;
    case CliCommandKind::Unknown:
      chat_panel_.AppendSystem("Unknown command: " + command.text + ". Enter /help for commands.");
      break;
    case CliCommandKind::Message:
      SubmitChatMessage(command.text);
      break;
  }
  if ( command.kind != CliCommandKind::NewConversation
      && command.kind != CliCommandKind::ClearConversation
      && command.kind != CliCommandKind::Message )
    PersistTranscript();
  OpenChat();
  chat_panel_.FocusInput();
  return true;
}

void AiMenuController::ShowProviderSettings()
{
  ProviderSettingsSnapshot providers = AiMenuRegistry::Instance().ProviderSettings();
  const bool applied = ShowProviderSettingsDialog(
      providers.Manager(),
      providers.Revision(),
      AiMenuRegistry::Instance().ProviderClientInstance(),
      [](const ProviderManagerDraft &manager, std::uint64_t expected_revision)
      {
        return AiMenuRegistry::Instance().ApplyProviderSettings(
            manager,
            expected_revision);
      });
  if ( !applied )
    return;
  msg("[ida-agent] provider settings saved\n");
  chat_panel_.AppendSystem("Provider settings saved.");
  PersistTranscript();
}

void AiMenuController::ShowPluginSettings()
{
  const PluginSettings previous = AiMenuRegistry::Instance().Settings();
  PluginSettings updated = previous;
  auto &updates = AiMenuRegistry::Instance().Updates();
  const bool previous_automatic = updates.Automatic();
  bool automatic = previous_automatic;
  if ( !ShowPluginSettingsDialog(
          updated,
          [] { return AiMenuRegistry::Instance().ClearAllChatHistory(); },
          updates, automatic) )
    return;
  const bool updates_changed = automatic != previous_automatic;
  if ( updates_changed && !updates.SetAutomatic(automatic) )
  {
    warning("AUTOHIDE NONE\nUnable to save update settings.");
    return;
  }
  if ( !AiMenuRegistry::Instance().SaveSettings(updated) )
  {
    if ( updates_changed ) updates.SetAutomatic(previous_automatic);
    warning("AUTOHIDE NONE\nUnable to save IDA Agent settings.");
    msg("[ida-agent] failed to save plugin settings\n");
    return;
  }

  const bool enable_history_saving =
      !previous.save_chat_history && updated.save_chat_history;
  const bool history_loading_changed =
      previous.load_chat_history != updated.load_chat_history;
  if ( enable_history_saving )
  {
    if ( !history_store_opened_ )
      OpenHistoryStore();
    history_write_blocked_ = !history_store_opened_;
    persistence_warning_shown_ = false;
    PersistTranscript();
  }
  if ( history_loading_changed )
  {
    chat_panel_.AppendSystem(
        "The history restore setting will apply when a database is next opened.");
  }
  msg("[ida-agent] plugin settings saved\n");
}

void AiMenuController::MaybeAutoOpenChat()
{
  const PluginSettings settings = AiMenuRegistry::Instance().Settings();
  if ( !started_
      || auto_opened_
      || !settings.open_chat_on_database_open
      || !AiMenuRegistry::Instance().IsUiReady() )
  {
    return;
  }
  if ( chat_panel_.Open(settings.focus_input_on_auto_open) )
    auto_opened_ = true;
  else
    msg("[ida-agent] failed to open the AI panel automatically\n");
}

} // namespace ida_agent::ai
