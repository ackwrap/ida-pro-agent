#pragma once

#include "ai/chat_transcript.hpp"
#include <QtWidgets>
#include <deque>

namespace ida_agent::ai
{
// Native rich-text rendering only. Call on the IDA UI thread.
class ChatMessageView final : public QT::QTextEdit
{
public:
  explicit ChatMessageView(QT::QWidget *parent);
  void ResetMessages(const std::vector<ChatEntry> &entries);
  void AppendMessage(const ChatEntry &entry, std::size_t trimmed_entries);
  void BeginPreview(ChatSpeaker speaker);
  void FlushPreviews(std::string_view reasoning, std::string_view assistant);
  void CommitPreview(ChatSpeaker speaker, const ChatEntry &entry, std::size_t trimmed_entries);
  void DiscardPreview(ChatSpeaker speaker);
  QT::QString CopyMessageAt(const QT::QTextCursor &cursor) const;
  QT::QString CopyCodeAt(const QT::QTextCursor &cursor) const;

protected:
  QT::QVariant loadResource(int type, const QT::QUrl &name) override;
  void focusOutEvent(QT::QFocusEvent *event) override;
  void changeEvent(QT::QEvent *event) override;

private:
  struct Message
  {
    QT::QPointer<QT::QTextFrame> frame;
    ChatSpeaker speaker = ChatSpeaker::System;
    std::string raw;
    std::size_t sequence = 0;
    std::size_t bytes = 0;
    std::size_t consumed = 0;
    std::size_t lines = 1;
    std::size_t line_bytes = 0;
    int role_length = 0;
    bool inline_role = false;
    bool preview = false;
    bool limited = false;
    bool highlight_pending = false;
  };
  class ViewState;
  Message &InsertMessage(ChatSpeaker speaker, bool preview);
  Message *FindPreview(ChatSpeaker speaker);
  QT::QTextCursor BodyCursor(const Message &message) const;
  void CompactSeparator(int position);
  void RenderMessage(Message &message, std::string_view text);
  std::size_t FlushMessage(Message &message, std::string_view text, std::size_t budget);
  void StyleMessage(Message &message);
  void Restyle();
  void RemoveMessage(std::size_t index);
  void PruneMessages();
  void PublishStats();

  std::deque<Message> messages_;
  std::size_t next_sequence_ = 0;
  std::size_t first_retained_sequence_ = 0;
  std::size_t resets_ = 0;
  std::size_t markdown_passes_ = 0;
  std::size_t streamed_bytes_ = 0;
  std::size_t max_stream_batch_ = 0;
  std::size_t blocked_resources_ = 0;
  bool diagnostics_ = false;
  bool follow_bottom_ = true;
  bool syncing_scroll_ = false;
  unsigned active_edits_ = 0;
};
} // namespace ida_agent::ai
