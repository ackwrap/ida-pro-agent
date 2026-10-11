#pragma once

#include "ai/chat_panel.hpp"
#include "ai/chat_message_view.hpp"
#include "ai/chat_reasoning_control.hpp"
#include "ai/chat_status_label.hpp"
#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <QtWidgets>

namespace ida_agent::ai
{
struct ChatPanel::Impl final : event_listener_t
{
  ~Impl() override;
  bool Open(bool focus_input);
  void Close() noexcept;
  void FocusInput();
  void ApplyPendingInput();
  bool SetInputText(std::string_view text);
  void Reset();
  bool Restore(std::vector<ChatEntry> entries);
  bool Append(ChatSpeaker speaker, std::string_view text);
  ssize_t idaapi on_event(ssize_t code, va_list args) override;
  void Populate();
  void FlushPreviewDisplay();
  void RefreshFull();
  void BeginPreview(ChatSpeaker speaker);
  bool CommitPreview(ChatSpeaker speaker);
  void DiscardPreview(ChatSpeaker speaker);
  void DiscardPreviewModels();
  void DestroyTimer() noexcept;

  ChatTranscript transcript;
  ChatPreview preview;
  ChatPreview reasoning_preview;
  std::function<void(std::string)> submit;
  std::function<void()> poll;
  std::function<void()> close;
  std::string title = "IDA Agent AI";
  std::string transient_status;
  TWidget *widget = nullptr;
  ChatMessageView *output = nullptr;
  ChatStatusView status_view;
  ChatReasoningControl reasoning_control;
  QT::QLineEdit *input = nullptr;
  QT::QTimer *timer = nullptr;
  bool listener_hooked = false;
  bool focus_input_on_open = true;
  std::string pending_input;
};
} // namespace ida_agent::ai
