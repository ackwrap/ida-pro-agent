#include "ai/chat_render_budget.hpp"
#include <algorithm>
#include <utility>

namespace ida_agent::ai
{
std::size_t ChatUtf8PrefixBytes(std::string_view text, std::size_t limit) noexcept
{
  std::size_t end = (std::min)(text.size(), limit);
  while ( end != 0 && end < text.size()
      && (static_cast<unsigned char>(text[end]) & 0xC0) == 0x80 )
    --end;
  return end;
}

std::size_t ChatRenderPrefixBytes(std::string_view text, std::size_t bytes,
    std::size_t lines) noexcept
{
  if ( lines == 0 )
    return 0;
  const std::size_t end = ChatUtf8PrefixBytes(text, bytes);
  for ( std::size_t index = 0; index < end; ++index )
  {
    if ( text[index] == '\n' && lines-- <= 1 )
      return index;
  }
  return end;
}

bool CanRenderChatMarkdown(std::string_view text) noexcept
{
  if ( text.size() > MaxChatMarkdownBytes
      || ChatRenderPrefixBytes(text, text.size(), MaxChatMarkdownLines) != text.size() )
    return false;
  std::size_t line = 0;
  for ( const char value : text )
  {
    line = value == '\n' ? 0 : line + 1;
    if ( line > MaxRenderedChatLineBytes )
      return false;
  }
  return true;
}

ChatRenderChunk MakeChatRenderChunk(std::string_view text, std::size_t byte_budget,
    std::size_t newline_budget, std::size_t previous_line_bytes)
{
  ChatRenderChunk result;
  result.line_bytes = previous_line_bytes;
  result.text.reserve((std::min)(text.size(), byte_budget));
  while ( result.consumed < text.size() && result.text.size() < byte_budget )
  {
    const auto first = static_cast<unsigned char>(text[result.consumed]);
    const std::size_t length = first < 0x80 ? 1 : first < 0xE0 ? 2 : first < 0xF0 ? 3 : 4;
    const bool explicit_newline = first == '\n';
    if ( explicit_newline || result.line_bytes + length > MaxRenderedChatLineBytes )
    {
      if ( result.newlines >= newline_budget )
      {
        result.line_limit = true;
        break;
      }
      result.text.push_back('\n');
      ++result.newlines;
      result.line_bytes = 0;
      if ( explicit_newline )
        ++result.consumed;
      continue;
    }
    if ( length > byte_budget - result.text.size() )
      break;
    result.text.append(text.substr(result.consumed, length));
    result.consumed += length;
    result.line_bytes += length;
  }
  return result;
}

std::string BoundedChatRenderText(std::string_view text, bool *clipped)
{
  auto rendered = MakeChatRenderChunk(text, MaxRenderedMessageBytes,
      MaxRenderedMessageLines - 1);
  const bool exceeded = rendered.consumed != text.size();
  if ( clipped != nullptr )
    *clipped = exceeded;
  if ( exceeded )
    rendered.text += ChatDisplayLimitNotice;
  return std::move(rendered.text);
}
} // namespace ida_agent::ai
