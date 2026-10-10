#pragma once

#include "ai/chat_script_approval.hpp"
#include "ai/chat_transcript.hpp"

#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace ida_agent::ai
{

class ChatPanel final
{
public:
  ChatPanel();
  ~ChatPanel();

  ChatPanel(const ChatPanel &) = delete;
  ChatPanel &operator=(const ChatPanel &) = delete;

  void SetSubmitHandler(std::function<void(std::string)> handler);
  void SetPollHandler(std::function<void()> handler);
  void SetCloseHandler(std::function<void()> handler);
  void SetTitle(std::string title);
  bool Open(bool focus_input = true);
  void FocusInput();
  bool SetInputText(std::string_view text);
  void Close() noexcept;
  void Reset();
  bool Restore(std::vector<ChatEntry> entries);
  const std::vector<ChatEntry> &Entries() const noexcept;
  bool AppendUser(std::string_view text);
  bool AppendAssistant(std::string_view text);
  bool AppendSystem(std::string_view text);
  bool AppendTool(std::string_view text);
  void BeginReasoningPreview();
  bool AppendReasoningPreview(std::string_view delta);
  bool CommitReasoningPreview();
  void DiscardReasoningPreview();
  bool HasReasoningPreview() const noexcept;
  void BeginAssistantPreview();
  bool AppendAssistantPreview(std::string_view delta);
  bool CommitAssistantPreview();
  void DiscardAssistantPreview();
  bool HasAssistantPreview() const noexcept;
  ChatScriptApprovalDecision ConfirmScriptExecution(
      const std::vector<ChatScriptSource> &sources);
  void SetTransientStatus(std::string status);
  void ClearTransientStatus();

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace ida_agent::ai
