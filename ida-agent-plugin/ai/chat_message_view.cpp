#include "ai/chat_message_view.hpp"
#include "ai/chat_render_budget.hpp"
#include "ai/chat_output_view.hpp"
#include <algorithm>

namespace ida_agent::ai
{
namespace
{
QT::QTextCursor CompleteSelectionLayout(QT::QTextCursor cursor)
{
  // Qt 6.8.2's blockBoundingRect only advances incremental layout to the
  // queried block. A table selection can then read uninitialized cell offsets
  // during focus loss or after a message edit. Finish layout before handing
  // that selection to QTextEdit's geometry code; keep its anchor and text.
  if ( cursor.hasSelection() || cursor.currentTable() != nullptr )
    cursor.document()->documentLayout()->documentSize();
  return cursor;
}
} // namespace

class ChatMessageView::ViewState
{
public:
  explicit ViewState(ChatMessageView &view, bool force_bottom = false)
      : view_(view), selection_(CompleteSelectionLayout(view.textCursor())),
        top_(view.cursorForPosition(QT::QPoint(0, 0))),
        top_y_(view.cursorRect(top_).y()),
        bottom_(force_bottom || view.follow_bottom_ || view.verticalScrollBar()->value()
            >= view.verticalScrollBar()->maximum()),
        selected_(selection_.selectedText()), selection_frame_(selection_.currentFrame())
  {
    while ( selection_frame_ && selection_frame_->parentFrame()
        && selection_frame_->parentFrame() != view_.document()->rootFrame() )
      selection_frame_ = selection_frame_->parentFrame();
    ++view_.active_edits_;
    view_.setUpdatesEnabled(false);
    edit_ = QT::QTextCursor(view.document());
    edit_.beginEditBlock();
  }

  ~ViewState()
  {
    edit_.endEditBlock();
    // Tracked cursors preserve a selection in older messages across insertions
    // and pruning. Markdown can replace the selected current message: recover
    // an unchanged selected phrase there where possible.
    if ( !selected_.isEmpty() && selection_.selectedText() != selected_
        && selection_frame_ && selection_frame_ != view_.document()->rootFrame() )
    {
      auto match = view_.document()->find(selected_, selection_frame_->firstPosition());
      if ( !match.isNull() && match.selectionEnd() <= selection_frame_->lastPosition() )
        selection_ = match;
    }
    if ( bottom_ && !selection_.hasSelection() )
      selection_.movePosition(QT::QTextCursor::End);
    CompleteSelectionLayout(selection_);
    const auto current = view_.textCursor();
    if ( current.position() != selection_.position() || current.anchor() != selection_.anchor() )
      view_.setTextCursor(selection_);
    view_.verticalScrollBar()->setValue(bottom_
        ? view_.verticalScrollBar()->maximum()
        : view_.verticalScrollBar()->value() + view_.cursorRect(top_).y() - top_y_);
    view_.follow_bottom_ = bottom_;
    view_.setUpdatesEnabled(true);
    --view_.active_edits_;
    view_.PublishStats();
  }

private:
  ChatMessageView &view_;
  QT::QTextCursor selection_;
  QT::QTextCursor top_;
  QT::QTextCursor edit_;
  int top_y_;
  bool bottom_;
  QT::QString selected_;
  QT::QPointer<QT::QTextFrame> selection_frame_;
};

ChatMessageView::ChatMessageView(QT::QWidget *parent) : QT::QTextEdit(parent)
{
  diagnostics_ = !QT::qgetenv("IDA_AGENT_TEST_DIAGNOSTICS").isEmpty();
  setObjectName("idaAgentChatOutput");
  setReadOnly(true);
  setUndoRedoEnabled(false);
  setAcceptRichText(false);
  setTextInteractionFlags(QT::Qt::TextSelectableByMouse | QT::Qt::TextSelectableByKeyboard);
  setLineWrapMode(QT::QTextEdit::WidgetWidth);
  setWordWrapMode(QT::QTextOption::WrapAtWordBoundaryOrAnywhere);
  setFont(QT::QFontDatabase::systemFont(QT::QFontDatabase::GeneralFont));
  document()->setDocumentMargin(4);
  QT::QObject::connect(verticalScrollBar(), &QT::QScrollBar::valueChanged, this,
      [this](int value)
      {
        if ( active_edits_ == 0 && !syncing_scroll_ )
          follow_bottom_ = value >= verticalScrollBar()->maximum();
      });
  QT::QObject::connect(verticalScrollBar(), &QT::QScrollBar::rangeChanged, this,
      [this](int, int maximum)
      {
        // Qt can finish laying out a rich message after its edit block ends.
        // Preserve follow intent through that deferred scrollbar range change.
        if ( active_edits_ == 0 && follow_bottom_ )
        {
          syncing_scroll_ = true;
          verticalScrollBar()->setValue(maximum);
          syncing_scroll_ = false;
        }
      });
  PublishStats();
}

QT::QVariant ChatMessageView::loadResource(int, const QT::QUrl &)
{
  // Markdown may contain images. Do not access provider-supplied paths or URLs.
  ++blocked_resources_;
  return {};
}

void ChatMessageView::focusOutEvent(QT::QFocusEvent *event)
{
  CompleteSelectionLayout(textCursor());
  QT::QTextEdit::focusOutEvent(event);
}

void ChatMessageView::ResetMessages(const std::vector<ChatEntry> &entries)
{
  ViewState state(*this, true);
  messages_.clear();
  document()->clear();
  ++resets_;
  next_sequence_ = 0;
  first_retained_sequence_ = 0;
  // Materialize only the tail that can fit, including on history restore.
  std::size_t start = entries.size();
  std::size_t bytes = 0;
  while ( start != 0 && entries.size() - start < MaxRenderedChatMessages )
  {
    const std::size_t added = BoundedChatRenderText(entries[start - 1].text).size();
    if ( bytes + added > MaxRenderedChatBytes )
      break;
    bytes += added;
    --start;
  }
  next_sequence_ = start;
  for ( std::size_t index = start; index < entries.size(); ++index )
  {
    Message &message = InsertMessage(entries[index].speaker, false);
    message.sequence = next_sequence_++;
    RenderMessage(message, entries[index].text);
  }
  PruneMessages();
}

ChatMessageView::Message &ChatMessageView::InsertMessage(ChatSpeaker speaker, bool preview)
{
  auto before = std::find_if(messages_.begin(), messages_.end(),
      [speaker, preview](const Message &message)
      {
        return message.preview && (!preview
            || (speaker == ChatSpeaker::Thinking && message.speaker == ChatSpeaker::Assistant));
      });
  QT::QTextCursor cursor(document());
  cursor.setPosition(before == messages_.end()
      ? document()->characterCount() - 1 : before->frame->firstPosition() - 1);
  Message message;
  message.frame = cursor.insertFrame(QT::QTextFrameFormat());
  // Frame insertion can inherit the compact root separator's paragraph style.
  // Reset the real header/body before inserting readable content.
  cursor.setBlockFormat(QT::QTextBlockFormat());
  cursor.setBlockCharFormat(QT::QTextCharFormat());
  message.speaker = speaker;
  message.preview = preview;
  message.inline_role = speaker == ChatSpeaker::System || speaker == ChatSpeaker::Tool
      || speaker == ChatSpeaker::Thinking;
  const char *label = u8"\u2699\uFE0F System";
  switch ( speaker )
  {
    case ChatSpeaker::User: label = u8"\U0001F464 You"; break;
    case ChatSpeaker::Assistant: label = u8"\U0001F916 AI"; break;
    case ChatSpeaker::Context: label = u8"\U0001F4CC Context"; break;
    case ChatSpeaker::Thinking: label = u8"\U0001F4AD Thinking"; break;
    case ChatSpeaker::Tool: label = u8"\U0001F527 Tool"; break;
    case ChatSpeaker::System: break;
  }
  // QString positions count UTF-16 units, including emoji surrogate pairs.
  const auto role_label = QT::QString::fromUtf8(label);
  message.role_length = static_cast<int>(role_label.size());
  cursor.insertText(role_label);
  if ( message.inline_role )
    cursor.insertText(" ");
  else
    cursor.insertBlock(QT::QTextBlockFormat(), QT::QTextCharFormat());
  auto inserted = messages_.insert(before, std::move(message));
  StyleMessage(*inserted);
  return *inserted;
}

QT::QTextCursor ChatMessageView::BodyCursor(const Message &message) const
{
  if ( message.inline_role )
  {
    QT::QTextCursor cursor(document());
    cursor.setPosition(message.frame->firstPosition() + message.role_length + 1);
    return cursor;
  }
  return QT::QTextCursor(document()->findBlock(message.frame->firstPosition()).next());
}

void ChatMessageView::CompactSeparator(int position)
{
  if ( position < 0 || position >= document()->characterCount() )
    return;
  const auto block = document()->findBlock(position);
  QT::QTextCursor cursor(block);
  if ( !block.isValid() || !block.text().isEmpty()
      || cursor.currentFrame() != document()->rootFrame() )
    return;
  QT::QTextBlockFormat spacing;
  const auto gap = QT::QFontMetricsF(font(), this).lineSpacing() / 3.0;
  spacing.setLineHeight(gap, QT::QTextBlockFormat::FixedHeight);
  cursor.setBlockFormat(spacing);
  QT::QTextCharFormat empty;
  empty.setFontPointSize(1);
  cursor.setBlockCharFormat(empty);
}

ChatMessageView::Message *ChatMessageView::FindPreview(ChatSpeaker speaker)
{
  for ( Message &message : messages_ )
    if ( message.preview && message.speaker == speaker )
      return &message;
  return nullptr;
}

void ChatMessageView::AppendMessage(const ChatEntry &entry, std::size_t trimmed_entries)
{
  ViewState state(*this);
  first_retained_sequence_ += trimmed_entries;
  Message &message = InsertMessage(entry.speaker, false);
  message.sequence = next_sequence_++;
  RenderMessage(message, entry.text);
  PruneMessages();
}

void ChatMessageView::BeginPreview(ChatSpeaker speaker)
{
  ViewState state(*this);
  if ( FindPreview(speaker) != nullptr )
  {
    for ( std::size_t index = 0; index < messages_.size(); ++index )
      if ( messages_[index].preview && messages_[index].speaker == speaker )
      {
        RemoveMessage(index);
        break;
      }
  }
  InsertMessage(speaker, true);
  PruneMessages();
}

std::size_t ChatMessageView::FlushMessage(Message &message, std::string_view text,
    std::size_t budget)
{
  if ( message.limited || message.consumed >= text.size() || budget <= ChatDisplayLimitNotice.size() )
    return 0;
  const auto remaining = text.substr(message.consumed);
  const std::size_t capacity = MaxRenderedMessageBytes - message.bytes;
  const std::size_t payload_budget = budget - ChatDisplayLimitNotice.size();
  auto chunk = MakeChatRenderChunk(remaining, (std::min)(payload_budget, capacity),
      MaxRenderedMessageLines - message.lines, message.line_bytes);
  QT::QTextCursor cursor = message.frame->lastCursorPosition();
  QT::QTextCharFormat body_format;
  body_format.setFont(font());
  body_format.setForeground(palette().color(QT::QPalette::Text));
  cursor.insertText(ToQString(chunk.text), body_format);
  message.bytes += chunk.text.size();
  message.consumed += chunk.consumed;
  message.lines += chunk.newlines;
  message.line_bytes = chunk.line_bytes;
  // A timer budget is temporary; reaching a display budget is permanent.
  std::size_t inserted = chunk.text.size();
  if ( chunk.consumed < remaining.size()
      && (chunk.line_limit || capacity <= payload_budget) )
  {
    message.limited = true;
    cursor.insertText(ToQString(ChatDisplayLimitNotice), body_format);
    message.bytes += ChatDisplayLimitNotice.size();
    inserted += ChatDisplayLimitNotice.size();
  }
  return inserted;
}

void ChatMessageView::FlushPreviews(std::string_view reasoning, std::string_view assistant)
{
  Message *thinking = FindPreview(ChatSpeaker::Thinking);
  Message *reply = FindPreview(ChatSpeaker::Assistant);
  // Keep complete preview text for Copy Message even after display clipping.
  // Append only new bytes; do not duplicate/rebuild the accumulated prefix.
  const auto update_raw = [](Message *message, std::string_view text)
  {
    if ( message != nullptr && text.size() > message->raw.size() )
      message->raw.append(text.substr(message->raw.size()));
  };
  update_raw(thinking, reasoning);
  update_raw(reply, assistant);
  if ( (thinking == nullptr || thinking->limited || thinking->consumed >= reasoning.size())
      && (reply == nullptr || reply->limited || reply->consumed >= assistant.size()) )
    return;
  ViewState state(*this);
  std::size_t consumed = 0;
  if ( thinking != nullptr )
    consumed += FlushMessage(*thinking, reasoning,
        reply != nullptr ? MaxChatStreamBatchBytes / 2 : MaxChatStreamBatchBytes);
  if ( reply != nullptr )
    consumed += FlushMessage(*reply, assistant, MaxChatStreamBatchBytes - consumed);
  streamed_bytes_ += consumed;
  max_stream_batch_ = (std::max)(max_stream_batch_, consumed);
  PruneMessages();
}

void ChatMessageView::CommitPreview(ChatSpeaker speaker, const ChatEntry &entry,
    std::size_t trimmed_entries)
{
  ViewState state(*this);
  first_retained_sequence_ += trimmed_entries;
  Message *message = FindPreview(speaker);
  if ( message == nullptr )
    message = &InsertMessage(entry.speaker, false);
  message->preview = false;
  message->sequence = next_sequence_++;
  RenderMessage(*message, entry.text);
  PruneMessages();
}

void ChatMessageView::DiscardPreview(ChatSpeaker speaker)
{
  ViewState state(*this);
  for ( std::size_t index = 0; index < messages_.size(); ++index )
    if ( messages_[index].preview && messages_[index].speaker == speaker )
    {
      RemoveMessage(index);
      break;
    }
}

void ChatMessageView::RemoveMessage(std::size_t index)
{
  const auto frame = messages_[index].frame;
  if ( frame )
  {
    QT::QTextCursor cursor(document());
    cursor.setPosition((std::max)(0, frame->firstPosition() - 1));
    cursor.setPosition((std::min)(document()->characterCount() - 1,
        frame->lastPosition() + 1), QT::QTextCursor::KeepAnchor);
    cursor.removeSelectedText();
  }
  messages_.erase(messages_.begin() + index);
}

void ChatMessageView::PruneMessages()
{
  for ( std::size_t index = 0; index < messages_.size(); )
  {
    if ( !messages_[index].preview
        && messages_[index].sequence < first_retained_sequence_ )
      RemoveMessage(index);
    else
      ++index;
  }
  std::size_t bytes = 0;
  for ( const Message &message : messages_ )
    bytes += message.bytes;
  while ( messages_.size() > MaxRenderedChatMessages || bytes > MaxRenderedChatBytes )
  {
    auto oldest = std::find_if(messages_.begin(), messages_.end(),
        [](const Message &message) { return !message.preview; });
    if ( oldest == messages_.end() )
      break;
    bytes -= oldest->bytes;
    RemoveMessage(static_cast<std::size_t>(oldest - messages_.begin()));
  }
}

void ChatMessageView::Restyle()
{
  if ( messages_.empty() )
    return;
  ViewState state(*this);
  for ( Message &message : messages_ )
    StyleMessage(message);
}

void ChatMessageView::PublishStats()
{
  if ( !diagnostics_ )
    return;
  QT::QVariantMap stats;
  std::size_t bytes = 0;
  for ( const Message &message : messages_ )
    bytes += message.bytes;
  stats["messages"] = static_cast<int>(messages_.size());
  stats["bytes"] = static_cast<double>(bytes);
  stats["resets"] = static_cast<double>(resets_);
  stats["markdownPasses"] = static_cast<double>(markdown_passes_);
  stats["streamedBytes"] = static_cast<double>(streamed_bytes_);
  stats["maxStreamBatch"] = static_cast<double>(max_stream_batch_);
  stats["blockedResources"] = static_cast<double>(blocked_resources_);
  setProperty("idaAgentRenderStats", stats);
}
} // namespace ida_agent::ai
