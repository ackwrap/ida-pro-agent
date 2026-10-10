#include "ai/chat_panel.hpp"

#include "ai/chat_command_line_edit.hpp"
#include "ai/chat_display_formatter.hpp"
#include "ai/chat_output_menu.hpp"
#include "ai/chat_output_view.hpp"
#include "ai/chat_script_approval_dialog.hpp"
#include "ai/chat_status_label.hpp"
#include "ai/chat_transcript.hpp"

#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>

#include <QtWidgets>

#include <functional>
#include <memory>
#include <string>
#include <utility>

namespace ida_agent::ai
{
namespace
{

constexpr const char *DefaultPanelTitle = "IDA Agent AI";

} // namespace

struct ChatPanel::Impl final : event_listener_t
{
  ~Impl() override
  {
    Close();
  }

  bool Open(bool focus_input)
  {
    if ( widget != nullptr )
    {
      activate_widget(widget, focus_input);
      if ( focus_input )
        FocusInput();
      return true;
    }

    focus_input_on_open = focus_input;
    widget = create_empty_widget(title.c_str());
    if ( widget == nullptr )
      return false;
    listener_hooked = ::hook_event_listener(HT_UI, this, nullptr);
    if ( !listener_hooked )
    {
      close_widget(widget, 0);
      widget = nullptr;
      return false;
    }

    display_widget(
        widget,
        WOPN_PERSIST | WOPN_NOT_CLOSED_BY_ESC | WOPN_DP_RIGHT,
        "Output window");
    if ( !set_dock_pos(title.c_str(), "Output window", DP_RIGHT) )
      set_dock_pos(title.c_str(), "Output", DP_RIGHT);
    if ( focus_input )
      FocusInput();
    return true;
  }

  void Close() noexcept
  {
    if ( listener_hooked )
    {
      unhook_event_listener(HT_UI, this);
      listener_hooked = false;
    }
    if ( input != nullptr )
      QT::QObject::disconnect(input, nullptr, nullptr, nullptr);
    DestroyTimer();
    preview.Discard();
    reasoning_preview.Discard();
    preview_formatter.Reset();
    reasoning_formatter.Reset();
    ClearPendingPreviewDisplay();
    transient_status.clear();
    committed_display.clear();
    pending_input.clear();
    output = nullptr;
    status_view.Detach();
    input = nullptr;
    if ( widget != nullptr )
    {
      close_widget(widget, WCLS_DONT_SAVE_SIZE);
      widget = nullptr;
    }
  }

  void FocusInput()
  {
    if ( input != nullptr )
      input->setFocus(QT::Qt::OtherFocusReason);
  }

  void ApplyPendingInput()
  {
    if ( input == nullptr || pending_input.empty() )
      return;
    input->setText(QT::QString::fromUtf8(pending_input.data(),
        static_cast<int>(pending_input.size())));
    input->setCursorPosition(input->text().size());
    pending_input.clear();
    FocusInput();
  }

  bool SetInputText(std::string_view text)
  {
    if ( widget == nullptr && !Open(false) )
      return false;
    pending_input.assign(text);
    ApplyPendingInput();
    return true;
  }

  void Reset()
  {
    DiscardPreviewModels();
    transient_status.clear();
    transcript.Reset();
    RefreshFull(true);
    status_view.Set(transient_status);
  }

  bool Restore(std::vector<ChatEntry> entries)
  {
    DiscardPreviewModels();
    transient_status.clear();
    if ( !transcript.Restore(std::move(entries)) )
      return false;
    RefreshFull(true);
    status_view.Set(transient_status);
    return true;
  }

  bool Append(ChatSpeaker speaker, std::string_view text)
  {
    FlushPreviewDisplay();
    const ChatTranscriptAppendResult result =
        transcript.AppendDetailed(speaker, text);
    if ( !result.appended )
      return false;
    ApplyCommittedAppend(result);
    return true;
  }

  ssize_t idaapi on_event(ssize_t code, va_list args) override
  {
    if ( code == ui_widget_visible )
    {
      TWidget *visible_widget = va_arg(args, TWidget *);
      if ( visible_widget == widget && output == nullptr )
        Populate();
    }
    else if ( code == ui_widget_invisible )
    {
      TWidget *hidden_widget = va_arg(args, TWidget *);
      if ( hidden_widget == widget )
      {
        output = nullptr;
        status_view.Detach();
        input = nullptr;
        widget = nullptr;
        unhook_event_listener(HT_UI, this);
        listener_hooked = false;
        preview.Discard();
        reasoning_preview.Discard();
        preview_formatter.Reset();
        reasoning_formatter.Reset();
        ClearPendingPreviewDisplay();
        committed_display.clear();
        pending_input.clear();
        if ( close )
          close();
      }
    }
    return 0;
  }

  void Populate()
  {
    auto *container = reinterpret_cast<QT::QWidget *>(widget);
    auto *layout = new QT::QVBoxLayout(container);
    layout->setContentsMargins(0, 0, 0, 2);
    layout->setSpacing(2);

    output = CreateChatOutputView(container);
    AttachChatOutputJumpMenu(output);
    status_view.Create(container);

    input = CreateChatCommandLineEdit(container, [this](std::string line)
    {
      if ( submit )
        submit(std::move(line));
    });

    if ( timer == nullptr )
    {
      // Created on the UI thread and owned explicitly by this controller-side
      // panel so polling survives destruction of a hidden dock widget.
      timer = new QT::QTimer();
      timer->setInterval(40);
      QT::QObject::connect(timer, &QT::QTimer::timeout, timer, [this]()
      {
        if ( poll )
          poll();
        FlushPreviewDisplay();
      });
      timer->start();
    }

    layout->addWidget(output, 1);
    layout->addWidget(status_view.Widget(), 0);
    layout->addWidget(input, 0);
    RefreshFull(true);
    status_view.Set(transient_status);
    if ( !pending_input.empty() )
      ApplyPendingInput();
    else if ( focus_input_on_open )
      FocusInput();
  }

  void RecomputePreviewPositions()
  {
    if ( output == nullptr )
      return;
    int end = output->document()->characterCount() - 1;
    if ( assistant_fragment_chars != 0 )
    {
      assistant_end = end;
      assistant_start = (std::max)(0, end - assistant_fragment_chars);
      end = assistant_start;
    }
    else
    {
      assistant_start = end;
      assistant_end = end;
    }
    if ( reasoning_fragment_chars != 0 )
    {
      reasoning_end = end;
      reasoning_start = (std::max)(0, end - reasoning_fragment_chars);
      end = reasoning_start;
    }
    else
    {
      reasoning_start = end;
      reasoning_end = end;
    }
    preview_start = end;
  }

  void InsertDisplayText(int position, const std::string &text)
  {
    if ( output == nullptr || text.empty() )
      return;
    const bool followed_bottom = IsChatOutputAtBottom(output);
    const int previous_scroll = output->verticalScrollBar()->value();
    const QT::QTextCursor selection = output->textCursor();
    QT::QTextCursor cursor(output->document());
    cursor.setPosition(position);
    cursor.insertText(ToQString(text));
    RestoreChatOutputView(output, followed_bottom, previous_scroll, selection);
  }

  void FlushPreviewDisplay()
  {
    if ( output == nullptr )
      return;

    if ( reasoning_needs_insert )
    {
      const int position = assistant_fragment_chars == 0
          ? output->document()->characterCount() - 1
          : assistant_start;
      const std::string fragment =
          FormatChatPreviewFragment(reasoning_formatter.Text(), position != 0);
      reasoning_fragment_chars = ToQString(fragment).size();
      InsertDisplayText(position, fragment);
      reasoning_needs_insert = false;
      pending_reasoning_display.clear();
      RecomputePreviewPositions();
    }
    else if ( !pending_reasoning_display.empty() )
    {
      const int added = ToQString(pending_reasoning_display).size();
      InsertDisplayText(reasoning_end, pending_reasoning_display);
      reasoning_fragment_chars += added;
      pending_reasoning_display.clear();
      RecomputePreviewPositions();
    }

    if ( assistant_needs_insert )
    {
      const int position = output->document()->characterCount() - 1;
      const std::string fragment =
          FormatChatPreviewFragment(preview_formatter.Text(), position != 0);
      assistant_fragment_chars = ToQString(fragment).size();
      InsertDisplayText(position, fragment);
      assistant_needs_insert = false;
      pending_assistant_display.clear();
      RecomputePreviewPositions();
    }
    else if ( !pending_assistant_display.empty() )
    {
      const int added = ToQString(pending_assistant_display).size();
      InsertDisplayText(assistant_end, pending_assistant_display);
      assistant_fragment_chars += added;
      pending_assistant_display.clear();
      RecomputePreviewPositions();
    }
  }

  void RebuildPreviewTail()
  {
    if ( output == nullptr )
      return;
    const bool followed_bottom = IsChatOutputAtBottom(output);
    const int previous_scroll = output->verticalScrollBar()->value();
    const QT::QTextCursor selection = output->textCursor();
    QT::QTextCursor cursor(output->document());
    cursor.setPosition(preview_start);
    cursor.movePosition(QT::QTextCursor::End, QT::QTextCursor::KeepAnchor);

    std::string tail;
    reasoning_fragment_chars = 0;
    assistant_fragment_chars = 0;
    if ( reasoning_preview.HasValue() )
    {
      const std::string fragment = FormatChatPreviewFragment(
          reasoning_formatter.Text(), preview_start != 0);
      reasoning_fragment_chars = ToQString(fragment).size();
      tail += fragment;
    }
    if ( preview.HasValue() )
    {
      const std::string fragment = FormatChatPreviewFragment(
          preview_formatter.Text(),
          preview_start != 0 || !tail.empty());
      assistant_fragment_chars = ToQString(fragment).size();
      tail += fragment;
    }
    cursor.insertText(ToQString(tail));
    ClearPendingPreviewDisplay();
    RecomputePreviewPositions();
    RestoreChatOutputView(output, followed_bottom, previous_scroll, selection);
  }

  void RefreshFull(
      bool force_bottom,
      std::string_view old_preview = {},
      ChatDisplayMigrationCandidate migration = {})
  {
    if ( output == nullptr )
      return;
    std::string next_committed = FormatChatDisplayLines(transcript.Lines());
    const std::string next_preview = PreviewDisplay();
    reasoning_fragment_chars = 0;
    assistant_fragment_chars = 0;
    if ( reasoning_preview.HasValue() )
    {
      const std::string fragment = FormatChatPreviewFragment(
          reasoning_formatter.Text(), !next_committed.empty());
      reasoning_fragment_chars = ToQString(fragment).size();
    }
    if ( preview.HasValue() )
    {
      const std::string fragment = FormatChatPreviewFragment(
          preview_formatter.Text(),
          !next_committed.empty() || reasoning_preview.HasValue());
      assistant_fragment_chars = ToQString(fragment).size();
    }
    RefreshChatOutputView(
        output, force_bottom, committed_display, next_committed,
        old_preview, next_preview, migration);
    committed_display = std::move(next_committed);
    ClearPendingPreviewDisplay();
    RecomputePreviewPositions();
  }

  std::string PreviewDisplay() const
  {
    return FormatChatPreviewDisplay(
        !committed_display.empty(),
        reasoning_preview.HasValue(), reasoning_formatter.Text(),
        preview.HasValue(), preview_formatter.Text());
  }

  void ApplyCommittedAppend(
      const ChatTranscriptAppendResult &result,
      std::string old_preview = {},
      ChatDisplayMigrationCandidate migration = {})
  {
    if ( output == nullptr )
      return;
    if ( result.display_rebuild_required )
    {
      if ( old_preview.empty() )
        old_preview = PreviewDisplay();
      RefreshFull(false, old_preview, migration);
      return;
    }
    const ChatEntry &entry = transcript.Entries().back();
    std::string fragment;
    if ( preview_start != 0 )
      fragment.push_back('\n');
    fragment += FormatChatDisplayEntry(entry.speaker, entry.text);
    InsertDisplayText(preview_start, fragment);
    committed_display += fragment;
    RecomputePreviewPositions();
  }

  void ClearPendingPreviewDisplay()
  {
    pending_reasoning_display.clear();
    pending_assistant_display.clear();
    reasoning_needs_insert = false;
    assistant_needs_insert = false;
  }

  void DiscardPreviewModels()
  {
    preview.Discard();
    reasoning_preview.Discard();
    preview_formatter.Reset();
    reasoning_formatter.Reset();
    ClearPendingPreviewDisplay();
    reasoning_fragment_chars = 0;
    assistant_fragment_chars = 0;
  }

  void DestroyTimer() noexcept
  {
    if ( timer == nullptr )
      return;
    timer->stop();
    delete timer;
    timer = nullptr;
  }

  ChatTranscript transcript;
  ChatPreview preview;
  ChatPreview reasoning_preview;
  ChatDisplayStreamFormatter preview_formatter;
  ChatDisplayStreamFormatter reasoning_formatter;
  std::function<void(std::string)> submit;
  std::function<void()> poll;
  std::function<void()> close;
  std::string title = DefaultPanelTitle;
  std::string transient_status;
  std::string committed_display;
  std::string pending_reasoning_display;
  std::string pending_assistant_display;
  TWidget *widget = nullptr;
  QT::QPlainTextEdit *output = nullptr;
  ChatStatusView status_view;
  QT::QLineEdit *input = nullptr;
  QT::QTimer *timer = nullptr;
  int preview_start = 0;
  int reasoning_start = 0;
  int reasoning_end = 0;
  int assistant_start = 0;
  int assistant_end = 0;
  int reasoning_fragment_chars = 0;
  int assistant_fragment_chars = 0;
  bool reasoning_needs_insert = false;
  bool assistant_needs_insert = false;
  bool listener_hooked = false;
  bool focus_input_on_open = true;
  std::string pending_input;
};

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
  impl_->FlushPreviewDisplay();
  if ( impl_->reasoning_preview.HasValue() )
  {
    impl_->reasoning_preview.Discard();
    impl_->reasoning_formatter.Reset();
    impl_->pending_reasoning_display.clear();
    impl_->reasoning_needs_insert = false;
    impl_->reasoning_fragment_chars = 0;
    impl_->RebuildPreviewTail();
  }
  impl_->reasoning_preview.Begin();
  impl_->reasoning_formatter.Begin(ChatSpeaker::Thinking);
  impl_->pending_reasoning_display.clear();
  impl_->reasoning_needs_insert = true;
  impl_->FlushPreviewDisplay();
}

bool ChatPanel::AppendReasoningPreview(std::string_view delta)
{
  if ( !impl_->reasoning_preview.HasValue() )
  {
    impl_->reasoning_preview.Begin();
    impl_->reasoning_formatter.Begin(ChatSpeaker::Thinking);
    impl_->reasoning_needs_insert = true;
  }
  const std::size_t previous_size = impl_->reasoning_preview.Text().size();
  if ( !impl_->reasoning_preview.Append(delta) )
    return false;
  impl_->pending_reasoning_display += impl_->reasoning_formatter.Append(
      std::string_view(impl_->reasoning_preview.Text()).substr(previous_size));
  return true;
}

bool ChatPanel::CommitReasoningPreview()
{
  if ( !impl_->reasoning_preview.HasValue() )
    return false;
  impl_->FlushPreviewDisplay();
  const std::string old_preview = impl_->PreviewDisplay();
  const std::size_t migrated_bytes = FormatChatPreviewFragment(
      impl_->reasoning_formatter.Text(), !impl_->committed_display.empty()).size();
  const ChatTranscriptAppendResult result = impl_->reasoning_preview.Text().empty()
      ? ChatTranscriptAppendResult{}
      : impl_->transcript.AppendDetailed(
          ChatSpeaker::Thinking,
          impl_->reasoning_preview.Text());
  impl_->reasoning_preview.Discard();
  impl_->reasoning_formatter.Reset();
  impl_->pending_reasoning_display.clear();
  impl_->reasoning_needs_insert = false;
  if ( result.appended )
  {
    impl_->ApplyCommittedAppend(
        result, old_preview, {0, migrated_bytes});
  }
  impl_->reasoning_fragment_chars = 0;
  impl_->RebuildPreviewTail();
  return result.appended;
}

void ChatPanel::DiscardReasoningPreview()
{
  impl_->FlushPreviewDisplay();
  impl_->reasoning_preview.Discard();
  impl_->reasoning_formatter.Reset();
  impl_->pending_reasoning_display.clear();
  impl_->reasoning_needs_insert = false;
  impl_->reasoning_fragment_chars = 0;
  impl_->RebuildPreviewTail();
}

bool ChatPanel::HasReasoningPreview() const noexcept
{
  return impl_->reasoning_preview.HasValue();
}

void ChatPanel::BeginAssistantPreview()
{
  impl_->FlushPreviewDisplay();
  if ( impl_->preview.HasValue() )
  {
    impl_->preview.Discard();
    impl_->preview_formatter.Reset();
    impl_->pending_assistant_display.clear();
    impl_->assistant_needs_insert = false;
    impl_->assistant_fragment_chars = 0;
    impl_->RebuildPreviewTail();
  }
  impl_->preview.Begin();
  impl_->preview_formatter.Begin(ChatSpeaker::Assistant);
  impl_->pending_assistant_display.clear();
  impl_->assistant_needs_insert = true;
  impl_->FlushPreviewDisplay();
}

bool ChatPanel::AppendAssistantPreview(std::string_view delta)
{
  const std::size_t previous_size = impl_->preview.Text().size();
  if ( !impl_->preview.Append(delta) )
    return false;
  impl_->pending_assistant_display += impl_->preview_formatter.Append(
      std::string_view(impl_->preview.Text()).substr(previous_size));
  return true;
}

bool ChatPanel::CommitAssistantPreview()
{
  if ( !impl_->preview.HasValue() )
    return false;
  impl_->FlushPreviewDisplay();
  const std::string old_preview = impl_->PreviewDisplay();
  const std::string migrated_preview = FormatChatPreviewFragment(
      impl_->preview_formatter.Text(),
      !impl_->committed_display.empty()
          || impl_->reasoning_preview.HasValue());
  const ChatTranscriptAppendResult result = impl_->preview.Text().empty()
      ? ChatTranscriptAppendResult{}
      : impl_->transcript.AppendDetailed(
          ChatSpeaker::Assistant,
          impl_->preview.Text());
  impl_->preview.Discard();
  impl_->preview_formatter.Reset();
  impl_->pending_assistant_display.clear();
  impl_->assistant_needs_insert = false;
  if ( result.appended )
  {
    impl_->ApplyCommittedAppend(
        result,
        old_preview,
        {old_preview.size() - migrated_preview.size(), migrated_preview.size()});
  }
  impl_->assistant_fragment_chars = 0;
  impl_->RebuildPreviewTail();
  return result.appended;
}

void ChatPanel::DiscardAssistantPreview()
{
  impl_->FlushPreviewDisplay();
  impl_->preview.Discard();
  impl_->preview_formatter.Reset();
  impl_->pending_assistant_display.clear();
  impl_->assistant_needs_insert = false;
  impl_->assistant_fragment_chars = 0;
  impl_->RebuildPreviewTail();
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
