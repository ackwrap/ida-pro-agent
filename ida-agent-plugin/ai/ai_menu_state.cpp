#include "ai/ai_menu.hpp"

#include "ai/ai_menu_registry.hpp"
#include "ai/agent_tool_registry.hpp"
#include "ai/plugin_settings.hpp"

#include <ida.hpp>
#include <kernwin.hpp>
#include <loader.hpp>

#include <filesystem>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace ida_agent::ai
{
namespace
{

std::string CurrentDatabaseKey()
{
  const char *path = get_path(PATH_TYPE_IDB);
  if ( path == nullptr || *path == '\0' )
    return {};
  const std::optional<std::string> key = NormalizeDatabaseKey(
      std::filesystem::u8path(path));
  return key.value_or(std::string{});
}

std::optional<std::string> ResolveSessionSelector(
    std::string_view selector,
    const std::vector<ChatSessionSummary> &sessions)
{
  if ( selector.empty() )
    return std::nullopt;
  std::size_t number = 0;
  bool numeric = true;
  for ( char character : selector )
  {
    if ( character < '0' || character > '9'
        || number > (sessions.size() + 1) / 10 )
    {
      numeric = false;
      break;
    }
    number = number * 10 + static_cast<std::size_t>(character - '0');
  }
  if ( numeric && number >= 1 && number <= sessions.size() )
    return sessions[number - 1].id;
  if ( selector.size() < 4 )
    return std::nullopt;
  std::optional<std::string> matched;
  for ( const ChatSessionSummary &session : sessions )
  {
    if ( session.id.size() >= selector.size()
        && session.id.compare(0, selector.size(), selector) == 0 )
    {
      if ( matched )
        return std::nullopt;
      matched = session.id;
    }
  }
  return matched;
}

} // namespace

bool AiMenuController::OpenHistoryStore()
{
  history_store_opened_ = history_store_.Open(CurrentDatabaseKey());
  return history_store_opened_;
}

AgentEffectApprovalPolicy AiMenuController::CurrentEffectPolicy() const
{
  return effect_policies_.Get(conversation_session_id_);
}

void AiMenuController::SetCurrentEffectPolicy(
    AgentEffectApprovalPolicy policy)
{
  effect_policies_.Set(conversation_session_id_, policy);
}

void AiMenuController::SetConversationSessionId(std::string session_id)
{
  if ( !session_id.empty() )
    conversation_session_id_ = std::move(session_id);
}

void AiMenuController::StartRuntimeConversationSession()
{
  SetConversationSessionId(
      "runtime-" + std::to_string(next_runtime_session_id_++));
}

void AiMenuController::OnAllHistoryCleared() noexcept
{
  history_store_.ResetActiveSession();
  history_write_blocked_ = false;
  persistence_warning_shown_ = false;
  try
  {
    agent_loop_.Reset();
    AdvanceEffectGeneration();
    ClearCompactionState();
    context_usage_ = {};
    chat_panel_.ClearTransientStatus();
    chat_panel_.Reset();
    StartRuntimeConversationSession();
  }
  catch ( ... )
  {
  }
}

AgentEffectBinding AiMenuController::CurrentEffectBinding() const
{
  return AgentEffectBinding(
      effect_generation_,
      std::to_string(database_context_id_),
      CurrentDatabaseKey());
}

void AiMenuController::AdvanceEffectGeneration() noexcept
{
  if ( pending_tool_job_ != 0 )
  {
    agent_tools_.CancelAndForget(pending_tool_job_);
    pending_tool_job_ = 0;
  }
  if ( effect_generation_ == (std::numeric_limits<std::uint64_t>::max)() )
    effect_generation_ = 1;
  else
    ++effect_generation_;
  pending_tool_results_.clear();
  pending_read_only_indices_.clear();
  pending_effect_calls_.clear();
  try
  {
    effect_coordinator_.Invalidate();
  }
  catch ( ... )
  {
  }
}

void AiMenuController::InitializeHistory()
{
  const PluginSettings settings = AiMenuRegistry::Instance().Settings();
  const bool requested = settings.load_chat_history || settings.save_chat_history;
  if ( !requested || history_store_opened_ )
    return;
  if ( CurrentDatabaseKey().empty() )
    return;
  if ( !OpenHistoryStore() )
  {
    history_write_blocked_ = settings.save_chat_history;
    chat_panel_.AppendSystem(
        "External AI history storage is unavailable. This session remains in memory.");
    return;
  }
  if ( !history_store_.ActiveSessionId().empty() )
    SetConversationSessionId(history_store_.ActiveSessionId());
  if ( !settings.load_chat_history )
    return;

  const ChatHistoryLoadResult history = history_store_.Load();
  if ( history.status == ChatHistoryLoadStatus::Loaded )
  {
    if ( !chat_panel_.Restore(history.entries) )
    {
      history_write_blocked_ = settings.save_chat_history;
      chat_panel_.AppendSystem(
          "Stored AI history contains unsupported text. It was not overwritten; use /new to replace it.");
    }
  }
  else if ( history.status == ChatHistoryLoadStatus::Invalid )
  {
    history_write_blocked_ = settings.save_chat_history;
    chat_panel_.AppendSystem(
        "Stored AI history is invalid or unsupported. It was not overwritten; use /new to replace it.");
  }
  else if ( history.status == ChatHistoryLoadStatus::Unavailable )
  {
    history_write_blocked_ = settings.save_chat_history;
    chat_panel_.AppendSystem(
        "External AI history storage is unavailable. This session remains in memory.");
  }
}

bool AiMenuController::PersistTranscript()
{
  if ( !AiMenuRegistry::Instance().Settings().save_chat_history )
    return true;
  const std::string previous_session_id = conversation_session_id_;
  if ( !history_store_opened_ )
  {
    if ( OpenHistoryStore() )
      history_write_blocked_ = false;
    else
      history_write_blocked_ = true;
  }
  if ( history_write_blocked_ || !history_store_opened_ )
  {
    if ( !persistence_warning_shown_ )
    {
      persistence_warning_shown_ = true;
      chat_panel_.AppendSystem(
          "External AI history could not be saved; this session remains in memory. The IDB was not modified.");
      msg("[ida-agent] failed to save AI chat history to external SQLite storage\n");
    }
    return false;
  }
  if ( history_store_.Save(chat_panel_.Entries()) )
  {
    const std::string &stored_session_id = history_store_.ActiveSessionId();
    if ( !stored_session_id.empty()
        && stored_session_id != previous_session_id )
    {
      effect_policies_.Move(previous_session_id, stored_session_id);
      SetConversationSessionId(stored_session_id);
    }
    return true;
  }
  if ( !persistence_warning_shown_ )
  {
    persistence_warning_shown_ = true;
    chat_panel_.AppendSystem(
        "External AI history could not be saved; this session remains in memory. The IDB was not modified.");
    msg("[ida-agent] failed to save AI chat history to external SQLite storage\n");
  }
  return false;
}

void AiMenuController::StartNewConversation()
{
  agent_loop_.Reset();
  ClearCompactionState();
  context_usage_ = {};
  chat_panel_.ClearTransientStatus();
  const bool saving = AiMenuRegistry::Instance().Settings().save_chat_history;
  if ( saving && !history_store_opened_ )
    OpenHistoryStore();
  const bool created = !saving
      || (history_store_opened_ && history_store_.StartNew());
  if ( saving && !created )
    msg("[ida-agent] failed to create an AI conversation in external SQLite storage\n");
  chat_panel_.Reset();
  if ( saving && created )
    SetConversationSessionId(history_store_.ActiveSessionId());
  else
    StartRuntimeConversationSession();
  if ( saving )
  {
    history_write_blocked_ = !created;
    persistence_warning_shown_ = !created;
    if ( !created )
    {
      chat_panel_.AppendSystem(
          "External AI history could not create a conversation; this session remains in memory. The IDB was not modified.");
    }
  }
  else
  {
    chat_panel_.AppendSystem(
        "External history was not changed because saving is disabled in Settings.");
  }
}

void AiMenuController::ClearCurrentConversation()
{
  agent_loop_.Reset();
  ClearCompactionState();
  context_usage_ = {};
  chat_panel_.ClearTransientStatus();
  const bool saving = AiMenuRegistry::Instance().Settings().save_chat_history;
  if ( saving && !history_store_opened_ )
    OpenHistoryStore();
  const bool cleared = !saving
      || (history_store_opened_ && history_store_.Clear());
  chat_panel_.Reset();
  if ( saving && cleared )
  {
    history_write_blocked_ = false;
    persistence_warning_shown_ = false;
  }
  else if ( saving )
  {
    history_write_blocked_ = true;
    persistence_warning_shown_ = true;
    chat_panel_.AppendSystem(
        "External AI history could not be cleared; this session remains in memory. The IDB was not modified.");
    msg("[ida-agent] failed to clear AI chat history from external SQLite storage\n");
  }
}

void AiMenuController::SelectConversation(std::string_view selector)
{
  if ( HasActiveRequest() )
  {
    chat_panel_.AppendSystem(
        "Cancel the active request before switching conversations.");
    return;
  }
  if ( !history_store_opened_ && !OpenHistoryStore() )
  {
    chat_panel_.AppendSystem("Conversation history is unavailable.");
    return;
  }
  const ChatSessionListResult sessions = history_store_.ListSessions();
  const auto id = ResolveSessionSelector(selector, sessions.sessions);
  if ( !id )
  {
    chat_panel_.AppendSystem(
        "Conversation selector is missing, ambiguous, or unknown. Use /history first.");
    return;
  }
  const ChatHistoryLoadResult selected = history_store_.SelectSession(*id);
  if ( selected.status != ChatHistoryLoadStatus::Loaded
      || !chat_panel_.Restore(selected.entries) )
  {
    chat_panel_.AppendSystem("Conversation could not be loaded.");
    return;
  }
  agent_loop_.Reset();
  ClearCompactionState();
  context_usage_ = {};
  SetConversationSessionId(*id);
  history_write_blocked_ = false;
  persistence_warning_shown_ = false;
  chat_panel_.AppendSystem("Switched to conversation " + id->substr(0, 8) + ".");
}

} // namespace ida_agent::ai
