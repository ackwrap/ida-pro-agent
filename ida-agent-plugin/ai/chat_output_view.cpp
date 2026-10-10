#include "ai/chat_output_view.hpp"

#include <algorithm>
#include <string>

namespace ida_agent::ai
{

QT::QString ToQString(std::string_view value)
{
  return QT::QString::fromUtf8(value.data(), static_cast<int>(value.size()));
}

QT::QPlainTextEdit *CreateChatOutputView(QT::QWidget *parent)
{
  auto *output = new QT::QPlainTextEdit(parent);
  output->setReadOnly(true);
  output->setUndoRedoEnabled(false);
  // Display-only long-line segmentation adds QTextBlocks that do not exist in
  // ChatTranscript. Model-driven refresh owns clipping; Qt must not drop blocks.
  output->setMaximumBlockCount(0);
  output->setLineWrapMode(QT::QPlainTextEdit::NoWrap);
  output->setFont(QT::QFontDatabase::systemFont(QT::QFontDatabase::FixedFont));
  return output;
}

bool IsChatOutputAtBottom(QT::QPlainTextEdit *output)
{
  if ( output == nullptr )
    return true;
  QT::QScrollBar *scroll = output->verticalScrollBar();
  return scroll->value() >= scroll->maximum();
}

void RestoreChatOutputView(
    QT::QPlainTextEdit *output,
    bool followed_bottom,
    int previous_scroll,
    const QT::QTextCursor &selection)
{
  if ( output == nullptr )
    return;
  if ( !selection.isNull() && selection.document() == output->document() )
    output->setTextCursor(selection);
  output->verticalScrollBar()->setValue(
      followed_bottom
          ? output->verticalScrollBar()->maximum()
          : previous_scroll);
}

void RefreshChatOutputView(
    QT::QPlainTextEdit *output,
    bool force_bottom,
    std::string_view old_committed,
    std::string_view new_committed,
    std::string_view old_preview,
    std::string_view new_preview,
    ChatDisplayMigrationCandidate migration)
{
  const bool followed_bottom = force_bottom || IsChatOutputAtBottom(output);
  const int previous_scroll = output->verticalScrollBar()->value();
  const int previous_anchor = output->textCursor().anchor();
  const int previous_position = output->textCursor().position();
  const ChatDisplayRemapPlan remap = PlanChatDisplayRemap(
      old_committed, new_committed, old_preview, migration);
  std::size_t next_anchor = static_cast<std::size_t>(previous_anchor);
  std::size_t next_position = static_cast<std::size_t>(previous_position);
  int next_scroll = previous_scroll;
  if ( !force_bottom )
  {
    next_anchor = RemapChatDisplayCursor(remap, next_anchor);
    next_position = RemapChatDisplayCursor(remap, next_position);
    const std::size_t removed_blocks = remap.removed_display_blocks
        + remap.removed_migration_prefix_display_blocks;
    next_scroll = removed_blocks
            >= static_cast<std::size_t>(previous_scroll)
        ? 0
        : previous_scroll - static_cast<int>(removed_blocks);
  }

  output->setPlainText(ToQString(
      std::string(new_committed) + std::string(new_preview)));
  QT::QTextCursor selection(output->document());
  const std::size_t end = static_cast<std::size_t>(
      output->document()->characterCount() - 1);
  selection.setPosition(static_cast<int>((std::min)(next_anchor, end)));
  selection.setPosition(
      static_cast<int>((std::min)(next_position, end)),
      QT::QTextCursor::KeepAnchor);
  RestoreChatOutputView(output, followed_bottom, next_scroll, selection);
}

} // namespace ida_agent::ai
