#include "ai/chat_message_view.hpp"
#include "ai/chat_code_highlight.hpp"
#include "ai/chat_render_budget.hpp"
#include "ai/chat_output_view.hpp"

namespace ida_agent::ai
{
namespace
{
class MarkdownDocument final : public QT::QTextDocument
{
protected:
  QT::QVariant loadResource(int, const QT::QUrl &) override { return {}; }
};

QT::QColor Mix(const QT::QColor &base, const QT::QColor &accent, int percent)
{
  return QT::QColor((base.red() * (100 - percent) + accent.red() * percent) / 100,
      (base.green() * (100 - percent) + accent.green() * percent) / 100,
      (base.blue() * (100 - percent) + accent.blue() * percent) / 100);
}

bool IsCodeBlock(const QT::QTextBlock &block)
{
  const auto format = block.blockFormat();
  return format.hasProperty(QT::QTextFormat::BlockCodeLanguage)
      || format.hasProperty(QT::QTextFormat::BlockCodeFence);
}
} // namespace

void ChatMessageView::RenderMessage(Message &message, std::string_view text)
{
  message.raw.assign(text);
  const std::string visible = BoundedChatRenderText(text, &message.limited);
  QT::QTextCursor cursor = BodyCursor(message);
  cursor.clearSelection();
  cursor.setKeepPositionOnInsert(false);
  cursor.setPosition(message.frame->lastPosition(), QT::QTextCursor::KeepAnchor);
  cursor.removeSelectedText();
  QT::QTextCharFormat body_format;
  body_format.setFont(font());
  body_format.setForeground(palette().color(QT::QPalette::Text));
  cursor.setCharFormat(body_format);
  cursor.setBlockCharFormat(body_format);
  cursor.setBlockFormat(QT::QTextBlockFormat());
  const bool markdown = (message.speaker == ChatSpeaker::Assistant
      || message.speaker == ChatSpeaker::User || message.speaker == ChatSpeaker::Context)
      && CanRenderChatMarkdown(text);
  if ( markdown )
  {
    MarkdownDocument source;
    source.setDefaultFont(font());
    const auto prepared = PrepareChatCodeMarkdown(visible);
    source.setMarkdown(ToQString(prepared.text),
        QT::QTextDocument::MarkdownFeatures(QT::QTextDocument::MarkdownDialectGitHub)
            | QT::QTextDocument::MarkdownNoHTML);
    RestoreChatCodeGroups(source, prepared);
    const auto first_format = source.begin().blockFormat();
    cursor.insertFragment(QT::QTextDocumentFragment(&source));
    // Inserting a fragment merges its first paragraph with the destination.
    // Retain the source heading/fence properties for that first paragraph.
    QT::QTextCursor first_block(BodyCursor(message).block());
    first_block.setBlockFormat(first_format);
    ++markdown_passes_;
  }
  else
    cursor.insertText(ToQString(visible));
  message.bytes = visible.size();
  StyleMessage(message);
}

void ChatMessageView::StyleMessage(Message &message)
{
  if ( !message.frame )
    return;
  const auto colors = palette();
  const auto base = colors.color(QT::QPalette::Base);
  const auto text = colors.color(QT::QPalette::Text);
  const auto accent = colors.color(QT::QPalette::Highlight);
  const bool primary = !message.inline_role;
  const bool user = message.speaker == ChatSpeaker::User;
  auto format = message.frame->frameFormat();
  format.setPadding(primary ? 6 : 3);
  format.setTopMargin(0);
  format.setBottomMargin(0);
  format.setBorder(1);
  format.setBorderStyle(QT::QTextFrameFormat::BorderStyle_Solid);
  format.setBorderBrush(Mix(base, primary ? accent : text, primary ? 20 : 8));
  format.setBackground(Mix(base, user ? accent : text, user ? 8 : 3));
  message.frame->setFrameFormat(format);
  // Recompute the font-relative gap when the view font or style changes.
  CompactSeparator(message.frame->firstPosition() - 1);
  CompactSeparator(message.frame->lastPosition() + 1);

  QT::QTextCursor header = message.frame->firstCursorPosition();
  const auto header_text = header.block();
  header.setPosition(header_text.position() + message.role_length,
      QT::QTextCursor::KeepAnchor);
  QT::QTextCharFormat role;
  auto role_font = font();
  role_font.setWeight(QT::QFont::DemiBold);
  role.setFont(role_font);
  role.setForeground(primary ? Mix(text, accent, 25) : Mix(base, text, 65));
  header.mergeCharFormat(role);
  header.setPosition(header_text.position());
  auto header_block = header.blockFormat();
  header_block.setBottomMargin(primary ? 2 : 0);
  header.setBlockFormat(header_block);

  QT::QTextCursor body = BodyCursor(message);
  body.clearSelection();
  body.setKeepPositionOnInsert(false);
  body.setPosition(message.frame->lastPosition(), QT::QTextCursor::KeepAnchor);
  QT::QTextCharFormat body_color;
  body_color.setForeground(text);
  body.mergeCharFormat(body_color);

  auto code_font = QT::QFontDatabase::systemFont(QT::QFontDatabase::FixedFont);
  code_font.setFixedPitch(true);
  int fallback_group = 100000;
  int previous_group = 0;
  QT::QString previous_language;
  bool previous_code = false;
  for ( auto block = BodyCursor(message).block();
        block.isValid() && block.position() < message.frame->lastPosition();
        block = block.next() )
  {
    const bool code = IsCodeBlock(block);
    auto block_format = block.blockFormat();
    int group = block_format.property(ChatCodeGroupProperty).toInt();
    const auto language = block_format.property(QT::QTextFormat::BlockCodeLanguage).toString();
    if ( code && group == 0 )
      group = !previous_code || language != previous_language ? ++fallback_group : previous_group;
    if ( !code )
      block_format.clearProperty(ChatCodeGroupProperty);
    const double top_limit = block_format.headingLevel() > 0 ? 4 : 2;
    if ( block_format.topMargin() > top_limit )
      block_format.setTopMargin(top_limit);
    if ( block_format.bottomMargin() > 2 )
      block_format.setBottomMargin(2);
    if ( code )
    {
      block_format.setProperty(ChatCodeGroupProperty, group);
      block_format.setBackground(Mix(base, text, 7));
      block_format.setLeftMargin(4);
      block_format.setRightMargin(4);
      block_format.setTopMargin(previous_code && group != previous_group
          ? QT::QFontMetricsF(font(), this).lineSpacing() / 3.0 : 0);
      block_format.setBottomMargin(0);
      QT::QTextCursor code_cursor(block);
      code_cursor.setPosition(block.position() + block.length() - 1,
          QT::QTextCursor::KeepAnchor);
      QT::QTextCharFormat code_format;
      code_format.setFont(code_font);
      code_format.setForeground(text);
      code_cursor.mergeCharFormat(code_format);
    }
    QT::QTextCursor block_cursor(block);
    block_cursor.setBlockFormat(block_format);
    // Inline code keeps the parser's formatting but uses IDA's fixed font.
    for ( auto fragment = block.begin(); !fragment.atEnd(); ++fragment )
    {
      const auto run = fragment.fragment();
      if ( !run.isValid() || !run.charFormat().fontFixedPitch() )
        continue;
      QT::QTextCursor inline_code(document());
      inline_code.setPosition(run.position());
      inline_code.setPosition(run.position() + run.length(), QT::QTextCursor::KeepAnchor);
      QT::QTextCharFormat fixed;
      fixed.setFont(code_font);
      inline_code.mergeCharFormat(fixed);
    }
    previous_code = code;
    previous_group = group;
    previous_language = language;
  }
  if ( !message.preview )
    ApplyChatCodeHighlighting(message.frame, colors);
}

QT::QString ChatMessageView::CopyMessageAt(const QT::QTextCursor &cursor) const
{
  for ( const Message &message : messages_ )
    if ( message.frame && cursor.position() >= message.frame->firstPosition()
        && cursor.position() <= message.frame->lastPosition() )
      return ToQString(message.raw);
  return {};
}

QT::QString ChatMessageView::CopyCodeAt(const QT::QTextCursor &cursor) const
{
  auto block = cursor.block();
  const auto property = block.blockFormat().property(ChatCodeGroupProperty);
  if ( !property.isValid() )
    return {};
  while ( block.previous().isValid()
      && block.previous().blockFormat().property(ChatCodeGroupProperty) == property
      && QT::QTextCursor(block.previous()).currentFrame() == cursor.currentFrame() )
    block = block.previous();
  QT::QString result("");
  while ( block.isValid() && block.blockFormat().property(ChatCodeGroupProperty) == property
      && QT::QTextCursor(block).currentFrame() == cursor.currentFrame() )
  {
    if ( !result.isEmpty() )
      result += '\n';
    result += block.text();
    block = block.next();
  }
  result.replace(QT::QChar::LineSeparator, QT::QChar('\n'));
  return result;
}

void ChatMessageView::changeEvent(QT::QEvent *event)
{
  QT::QTextEdit::changeEvent(event);
  if ( event->type() == QT::QEvent::PaletteChange || event->type() == QT::QEvent::FontChange
      || event->type() == QT::QEvent::StyleChange )
    Restyle();
}
} // namespace ida_agent::ai
