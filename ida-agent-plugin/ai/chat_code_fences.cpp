#include "ai/chat_code_fences.hpp"

namespace ida_agent::ai
{
namespace
{
bool Space(char ch) { return ch == ' ' || ch == '\t' || ch == '\r'; }

struct Fence
{
  std::size_t position = 0;
  std::size_t length = 0;
  unsigned quotes = 0;
  bool list = false;
  char marker = 0;
};

bool PrefixSpace(std::string_view line, std::size_t &index)
{
  unsigned count = 0;
  while ( index < line.size() && line[index] == ' ' )
  {
    ++index;
    if ( ++count > 3 )
      return false;
  }
  return true;
}

Fence FindFence(std::string_view line, bool allow_list)
{
  Fence result;
  std::size_t index = 0;
  if ( !PrefixSpace(line, index) )
    return result;
  while ( index < line.size() && line[index] == '>' )
  {
    ++result.quotes;
    ++index;
    if ( !PrefixSpace(line, index) )
      return {};
  }
  if ( allow_list && index + 1 < line.size()
      && (line[index] == '-' || line[index] == '+' || line[index] == '*')
      && Space(line[index + 1]) )
  {
    index += 2;
    result.list = true;
    if ( !PrefixSpace(line, index) )
      return {};
  }
  else if ( allow_list && index < line.size() && line[index] >= '0' && line[index] <= '9' )
  {
    auto end = index;
    while ( end < line.size() && line[end] >= '0' && line[end] <= '9' && end - index < 9 )
      ++end;
    if ( end + 1 < line.size() && (line[end] == '.' || line[end] == ')') && Space(line[end + 1]) )
    {
      index = end + 2;
      result.list = true;
      if ( !PrefixSpace(line, index) )
        return {};
    }
  }
  if ( index >= line.size() || (line[index] != char(96) && line[index] != '~') )
    return {};
  result.position = index;
  result.marker = line[index];
  while ( index < line.size() && line[index] == result.marker )
  {
    ++result.length;
    ++index;
  }
  if ( result.length < 3 )
    return {};
  return result;
}

std::string_view Trim(std::string_view text)
{
  while ( !text.empty() && Space(text.front()) )
    text.remove_prefix(1);
  while ( !text.empty() && Space(text.back()) )
    text.remove_suffix(1);
  return text;
}
} // namespace

ChatCodeMarkdown PrepareChatCodeMarkdown(std::string_view markdown)
{
  ChatCodeMarkdown result;
  // Avoid collisions with any provider-supplied language name.
  unsigned candidate = 0;
  do
    result.marker_prefix = "ida_agent_fence_" + std::to_string(candidate++) + "_";
  while ( markdown.find(result.marker_prefix) != markdown.npos );
  result.text.reserve(markdown.size());
  Fence active;
  for ( std::size_t start = 0; start < markdown.size(); )
  {
    const auto newline = markdown.find('\n', start);
    const auto end = newline == markdown.npos ? markdown.size() : newline;
    const auto line = markdown.substr(start, end - start);
    const auto fence = FindFence(line, active.length == 0);
    const auto tail = fence.length == 0 ? std::string_view()
        : Trim(line.substr(fence.position + fence.length));
    if ( active.length > 0 )
    {
      result.text.append(line);
      if ( fence.marker == active.marker && fence.quotes == active.quotes
          && fence.length >= active.length && tail.empty() )
        active = {};
    }
    else if ( fence.length > 0 && (fence.marker != char(96) || tail.find(char(96)) == tail.npos) )
    {
      active = fence;
      result.languages.emplace_back(tail);
      result.text.append(line.substr(0, fence.position + fence.length));
      result.text += result.marker_prefix + std::to_string(result.languages.size());
      if ( !line.empty() && line.back() == '\r' )
        result.text += '\r';
    }
    else
      result.text.append(line);
    if ( newline == markdown.npos )
      break;
    result.text += '\n';
    start = newline + 1;
  }
  return result;
}
} // namespace ida_agent::ai
