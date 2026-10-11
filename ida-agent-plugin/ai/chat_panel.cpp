#include "ai/chat_panel_impl.hpp"
#include "ai/chat_script_approval_dialog.hpp"
#include <utility>

namespace ida_agent::ai
{
void ChatPanel::Impl::Reset()
{
  DiscardPreviewModels();
  transient_status.clear();
  transcript.Reset();
  RefreshFull();
  status_view.Set(transient_status);
}

bool ChatPanel::Impl::Restore(std::vector<ChatEntry> entries)
{
  DiscardPreviewModels();
  transient_status.clear();
  if ( !transcript.Restore(std::move(entries)) )
    return false;
  RefreshFull();
  status_view.Set(transient_status);
  return true;
}

bool ChatPanel::Impl::Append(ChatSpeaker speaker, std::string_view text)
{
  const auto result = transcript.AppendDetailed(speaker, text);
  if ( result.appended && output != nullptr )
    output->AppendMessage(transcript.Entries().back(), result.trimmed_entries);
  return result.appended;
}

void ChatPanel::Impl::FlushPreviewDisplay()
{
  if ( output != nullptr )
    output->FlushPreviews(reasoning_preview.Text(), preview.Text());
}

void ChatPanel::Impl::RefreshFull()
{
  if ( output == nullptr )
    return;
  output->ResetMessages(transcript.Entries());
  if ( reasoning_preview.HasValue() )
    output->BeginPreview(ChatSpeaker::Thinking);
  if ( preview.HasValue() )
    output->BeginPreview(ChatSpeaker::Assistant);
  FlushPreviewDisplay();
}

void ChatPanel::Impl::BeginPreview(ChatSpeaker speaker)
{
  auto &model = speaker == ChatSpeaker::Thinking ? reasoning_preview : preview;
  model.Begin();
  if ( output != nullptr )
    output->BeginPreview(speaker);
}

bool ChatPanel::Impl::CommitPreview(ChatSpeaker speaker)
{
  auto &model = speaker == ChatSpeaker::Thinking ? reasoning_preview : preview;
  if ( !model.HasValue() )
    return false;
  const auto result = model.Text().empty() ? ChatTranscriptAppendResult{}
      : transcript.AppendDetailed(speaker, model.Text());
  if ( output != nullptr )
  {
    if ( result.appended )
      output->CommitPreview(speaker, transcript.Entries().back(), result.trimmed_entries);
    else
      output->DiscardPreview(speaker);
  }
  model.Discard();
  return result.appended;
}

void ChatPanel::Impl::DiscardPreview(ChatSpeaker speaker)
{
  (speaker == ChatSpeaker::Thinking ? reasoning_preview : preview).Discard();
  if ( output != nullptr )
    output->DiscardPreview(speaker);
}

void ChatPanel::Impl::DiscardPreviewModels()
{
  preview.Discard();
  reasoning_preview.Discard();
}

ChatPanel::ChatPanel() : impl_(std::make_unique<Impl>()) {}

ChatPanel::~ChatPanel() = default;

void ChatPanel::SetSubmitHandler(std::function<void(std::string)> handler)
{
  impl_->submit = std::move(handler);
}

void ChatPanel::SetPollHandler(std::function<void()> handler)
{
  impl_->poll = std::move(handler);
}

void ChatPanel::SetCloseHandler(std::function<void()> handler)
{
  impl_->close = std::move(handler);
}

void ChatPanel::SetReasoningHandler(std::function<void(ChatReasoningSelection)> handler)
{
  impl_->reasoning_control.SetHandler(std::move(handler));
}

void ChatPanel::SetReasoningState(ChatReasoningState state)
{
  impl_->reasoning_control.SetState(std::move(state));
}

void ChatPanel::SetTitle(std::string title)
{
  if ( impl_->widget == nullptr && !title.empty() )
    impl_->title = std::move(title);
}

bool ChatPanel::Open(bool focus_input)
{
  return impl_->Open(focus_input);
}

void ChatPanel::FocusInput()
{
  impl_->FocusInput();
}

bool ChatPanel::SetInputText(std::string_view text)
{
  return impl_->SetInputText(text);
}

void ChatPanel::Close() noexcept
{
  impl_->Close();
}

void ChatPanel::Reset()
{
  impl_->Reset();
}

bool ChatPanel::Restore(std::vector<ChatEntry> entries)
{
  return impl_->Restore(std::move(entries));
}

const std::vector<ChatEntry> &ChatPanel::Entries() const noexcept
{
  return impl_->transcript.Entries();
}

bool ChatPanel::AppendUser(std::string_view text)
{
  return impl_->Append(ChatSpeaker::User, text);
}

bool ChatPanel::AppendAssistant(std::string_view text)
{
  return impl_->Append(ChatSpeaker::Assistant, text);
}

bool ChatPanel::AppendSystem(std::string_view text)
{
  return impl_->Append(ChatSpeaker::System, text);
}

bool ChatPanel::AppendTool(std::string_view text)
{
  return impl_->Append(ChatSpeaker::Tool, text);
}

void ChatPanel::BeginReasoningPreview()
{
  impl_->BeginPreview(ChatSpeaker::Thinking);
}

bool ChatPanel::AppendReasoningPreview(std::string_view delta)
{
  if ( !impl_->reasoning_preview.HasValue() )
    impl_->BeginPreview(ChatSpeaker::Thinking);
  return impl_->reasoning_preview.Append(delta);
}

bool ChatPanel::CommitReasoningPreview()
{
  return impl_->CommitPreview(ChatSpeaker::Thinking);
}

void ChatPanel::DiscardReasoningPreview()
{
  impl_->DiscardPreview(ChatSpeaker::Thinking);
}

bool ChatPanel::HasReasoningPreview() const noexcept
{
  return impl_->reasoning_preview.HasValue();
}

void ChatPanel::BeginAssistantPreview()
{
  impl_->BeginPreview(ChatSpeaker::Assistant);
}

bool ChatPanel::AppendAssistantPreview(std::string_view delta)
{
  return impl_->preview.Append(delta);
}

bool ChatPanel::CommitAssistantPreview()
{
  return impl_->CommitPreview(ChatSpeaker::Assistant);
}

void ChatPanel::DiscardAssistantPreview()
{
  impl_->DiscardPreview(ChatSpeaker::Assistant);
}

bool ChatPanel::HasAssistantPreview() const noexcept
{
  return impl_->preview.HasValue();
}

ChatScriptApprovalDecision ChatPanel::ConfirmScriptExecution(
    const std::vector<ChatScriptSource> &sources)
{
  return ShowChatScriptApprovalDialog(impl_->widget, sources);
}

void ChatPanel::SetTransientStatus(std::string status)
{
  impl_->transient_status = std::move(status);
  impl_->status_view.Set(impl_->transient_status);
}

void ChatPanel::ClearTransientStatus()
{
  impl_->transient_status.clear();
  impl_->status_view.Set(impl_->transient_status);
}

} // namespace ida_agent::ai
