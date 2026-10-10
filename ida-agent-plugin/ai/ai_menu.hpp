#pragma once

#include "ai/chat_panel.hpp"
#include "ai/chat_context.hpp"
#include "ai/chat_history_store.hpp"
#include "ai/chat_history_writer.hpp"
#include "ai/agent_effect_coordinator.hpp"
#include "ai/agent_effect_policy.hpp"
#include "ai/agent_loop.hpp"

#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ida_agent::ai
{

class AgentToolRegistry;
class AgentEffectService;
class AiMenuRegistry;
class ProviderChatSession;

class AiMenuController
{
public:
  AiMenuController(
      const void *action_owner,
      AgentToolRegistry &agent_tools,
      AgentEffectService &agent_effects);
  ~AiMenuController();

  AiMenuController(const AiMenuController &) = delete;
  AiMenuController &operator=(const AiMenuController &) = delete;

  bool Start() noexcept;
  void Stop(bool unregister_actions = true) noexcept;
  void SetLifecycleTrace(std::function<void(const char *)> trace);
  void UiReady() noexcept;
  void DatabaseInitialized() noexcept;
  void OpenChat();
  void NewConversation();
  void SetChatInputText(std::string text);
  bool ExecuteCliLine(const char *line);
  void ShowProviderSettings();
  void ShowPluginSettings();
  void CancelRequest();
  bool HasActiveRequest() const noexcept;

private:
  friend class AiMenuRegistry;

  enum class PendingConversationAction
  {
    None,
    New,
    Clear,
  };

  enum class RequestPurpose
  {
    Conversation,
    Compaction,
  };

  struct PendingEffectCall
  {
    std::size_t result_index;
    std::string prepared_id;
    std::string safe_summary;
    AgentToolCall call;
  };

  void MaybeAutoOpenChat();
  void InitializeHistory();
  bool OpenHistoryStore();
  bool PersistTranscript();
  void PollHistoryWrite();
  void StartNewConversation();
  void ClearCurrentConversation();
  void SelectConversation(std::string_view selector);
  void SubmitChatMessage(std::string_view text);
  void PollChatRequest();
  void CompactContext(bool automatic = false);
  void PollContextCompaction();
  void MaybeAutoCompactContext();
  void ShowContextUsage(bool detailed);
  bool RefreshContextUsage();
  void CaptureContextUsage(
      const ProviderChatBuildResult &build,
      std::size_t total_messages,
      bool agent_tools);
  void ClearCompactionState() noexcept;
  void AllowSessionEffects();
  void DenySessionEffects();
  void BeginAgentToolBatch(const std::vector<AgentToolCall> &calls);
  void CollectReadOnlyToolResults(std::vector<AgentToolResult> results);
  void DecidePendingEffects(bool confirm);
  void MaybeCompleteAgentToolBatch();
  void CompleteAgentToolResults(std::vector<AgentToolResult> results);
  void AbortAgentToolBatchForTranscriptFailure();
  AgentEffectApprovalPolicy CurrentEffectPolicy() const;
  void SetCurrentEffectPolicy(AgentEffectApprovalPolicy policy);
  void SetConversationSessionId(std::string session_id);
  void StartRuntimeConversationSession();
  void OnAllHistoryCleared() noexcept;
  AgentEffectBinding CurrentEffectBinding() const;
  void AdvanceEffectGeneration() noexcept;
  void CancelActive(
      PendingConversationAction action = PendingConversationAction::None) noexcept;

  const void *action_owner_ = nullptr;
  AgentToolRegistry &agent_tools_;
  AgentEffectService &agent_effects_;
  AgentEffectCoordinator effect_coordinator_;
  ChatPanel chat_panel_;
  std::unique_ptr<ProviderChatSession> chat_session_;
  AgentLoop agent_loop_;
  std::uint64_t pending_tool_job_ = 0;
  std::uint64_t effect_generation_ = 1;
  std::vector<std::optional<AgentToolResult>> pending_tool_results_;
  std::vector<std::size_t> pending_read_only_indices_;
  std::vector<PendingEffectCall> pending_effect_calls_;
  AgentEffectSessionPolicies effect_policies_;
  std::string conversation_session_id_ = "runtime-1";
  std::uint64_t next_runtime_session_id_ = 2;
  ChatHistoryStore history_store_;
  ChatHistoryWriter history_writer_;
  std::function<void(const char *)> lifecycle_trace_;
  std::ptrdiff_t database_context_id_ = -1;
  bool started_ = false;
  bool auto_opened_ = false;
  bool history_store_opened_ = false;
  bool history_write_blocked_ = false;
  bool persistence_warning_shown_ = false;
  bool request_cancelling_ = false;
  PendingConversationAction pending_conversation_action_ =
      PendingConversationAction::None;
  std::string local_request_error_;
  ChatContextUsage context_usage_;
  RequestPurpose request_purpose_ = RequestPurpose::Conversation;
  std::vector<ChatEntry> compaction_retained_entries_;
  ChatPreview compaction_preview_;
  std::size_t compaction_summarized_entries_ = 0;
  std::size_t compaction_summarized_bytes_ = 0;
  bool compaction_automatic_ = false;
};

} // namespace ida_agent::ai
