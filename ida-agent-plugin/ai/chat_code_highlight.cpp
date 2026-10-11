#include "ai/chat_code_highlight.hpp"
#include "ai/chat_code_tokens.hpp"
#include <algorithm>
#include <array>
#include <cmath>

namespace ida_agent::ai
{
namespace
{
QT::QColor Mix(const QT::QColor &base, const QT::QColor &accent, int percent)
{
  return QT::QColor((base.red() * (100 - percent) + accent.red() * percent) / 100,
      (base.green() * (100 - percent) + accent.green() * percent) / 100,
      (base.blue() * (100 - percent) + accent.blue() * percent) / 100);
}

double Luminance(const QT::QColor &color)
{
  const auto linear = [](double value)
  {
    return value <= 0.04045 ? value / 12.92 : std::pow((value + 0.055) / 1.055, 2.4);
  };
  return 0.2126 * linear(color.redF()) + 0.7152 * linear(color.greenF())
      + 0.0722 * linear(color.blueF());
}

QT::QColor ReadableColor(const QT::QColor &seed, const QT::QColor &background,
    const QT::QColor &text)
{
  const double base = Luminance(background);
  for ( int weight = 0; weight <= 100; weight += 10 )
  {
    const auto color = Mix(seed, text, weight);
    const double ink = Luminance(color);
    const double ratio = ((std::max)(base, ink) + 0.05) / ((std::min)(base, ink) + 0.05);
    if ( ratio >= 4.5 )
      return color;
  }
  return text;
}

std::array<QT::QColor, 8> SyntaxColors(const QT::QPalette &palette)
{
  const auto base = palette.color(QT::QPalette::Base);
  const auto text = palette.color(QT::QPalette::Text);
  const bool dark = Luminance(base) < Luminance(text);
  // keyword, type/register, string, comment, number, function, directive, property
  const std::array<QT::QColor, 8> seeds = dark
      ? std::array<QT::QColor, 8>{QT::QColor("#c792ea"), QT::QColor("#4ec9b0"),
          QT::QColor("#ce9178"), QT::QColor("#91a88a"), QT::QColor("#b5cea8"),
          QT::QColor("#dcdcaa"), QT::QColor("#82b7f0"), QT::QColor("#82b7f0")}
      : std::array<QT::QColor, 8>{QT::QColor("#7d2ba4"), QT::QColor("#006d80"),
          QT::QColor("#a31515"), QT::QColor("#5a6d54"), QT::QColor("#098658"),
          QT::QColor("#795e26"), QT::QColor("#005faf"), QT::QColor("#005faf")};
  auto result = seeds;
  const auto code_background = Mix(base, text, 7);
  for ( auto &color : result )
    color = ReadableColor(color, code_background, text);
  return result;
}

std::u16string CodeSample(const QT::QTextBlock &first, int group, int end)
{
  std::u16string result;
  for ( auto block = first; block.isValid() && block.position() < end
      && block.blockFormat().property(ChatCodeGroupProperty).toInt() == group;
      block = block.next() )
  {
    const auto line = block.text().toStdU16String();
    result.append(line.substr(0, 4096 - result.size()));
    if ( result.size() >= 4096 )
      break;
    result.push_back(u'\n');
  }
  return result;
}
} // namespace

void RestoreChatCodeGroups(QT::QTextDocument &document, const ChatCodeMarkdown &markdown)
{
  const auto prefix = QT::QString::fromStdString(markdown.marker_prefix);
  for ( auto block = document.begin(); block.isValid(); block = block.next() )
  {
    auto format = block.blockFormat();
    const auto hint = format.property(QT::QTextFormat::BlockCodeLanguage).toString();
    if ( !hint.startsWith(prefix) )
      continue;
    bool valid = false;
    const int group = hint.mid(prefix.size()).toInt(&valid);
    if ( !valid || group <= 0 || static_cast<std::size_t>(group) > markdown.languages.size() )
      continue;
    format.setProperty(ChatCodeGroupProperty, group);
    const auto &language = markdown.languages[static_cast<std::size_t>(group - 1)];
    format.setProperty(QT::QTextFormat::BlockCodeLanguage, QT::QString::fromStdString(language));
    QT::QTextCursor cursor(block);
    cursor.setBlockFormat(format);
  }
}

void ApplyChatCodeHighlighting(QT::QTextFrame *frame, const QT::QPalette &palette)
{
  if ( frame == nullptr )
    return;
  const auto colors = SyntaxColors(palette);
  auto *document = frame->document();
  ChatCodeState state;
  ChatCodeLanguage language = ChatCodeLanguage::Plain;
  QT::QString previous_hint;
  int previous_group = 0;
  std::size_t remaining = MaxChatCodeMessageSpans;
  for ( auto block = document->findBlock(frame->firstPosition());
      block.isValid() && block.position() < frame->lastPosition(); block = block.next() )
  {
    auto *layout = block.layout();
    if ( layout == nullptr )
      continue;
    const auto format = block.blockFormat();
    const int group = format.property(ChatCodeGroupProperty).toInt();
    QT::QList<QT::QTextLayout::FormatRange> ranges;
    if ( group > 0 )
    {
      const auto hint = format.property(QT::QTextFormat::BlockCodeLanguage).toString();
      if ( group != previous_group || (!hint.isEmpty() && hint != previous_hint) )
      {
        state = {};
        language = ResolveChatCodeLanguage(hint.toStdString(),
            hint.isEmpty() ? CodeSample(block, group, frame->lastPosition()) : std::u16string());
        previous_hint = hint;
      }
      const auto line = block.text().toStdU16String();
      const auto tokens = TokenizeChatCodeLine(line, language, state, remaining);
      remaining -= tokens.size();
      for ( const auto &token : tokens )
      {
        QT::QTextLayout::FormatRange range;
        range.start = static_cast<int>(token.start);
        range.length = static_cast<int>(token.length);
        range.format.setForeground(colors[static_cast<std::size_t>(token.kind)]);
        ranges.append(range);
      }
    }
    else
    {
      state = {};
      previous_hint.clear();
    }
    previous_group = group;
    if ( !ranges.isEmpty() || !layout->formats().isEmpty() )
    {
      // Overlay colors do not split document fragments or alter clipboard text.
      layout->setFormats(ranges);
      document->markContentsDirty(block.position(), block.length());
    }
  }
}
} // namespace ida_agent::ai
