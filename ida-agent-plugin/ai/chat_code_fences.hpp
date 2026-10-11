#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace ida_agent::ai
{
struct ChatCodeMarkdown
{
  std::string text;
  std::string marker_prefix;
  std::vector<std::string> languages;
};

// Give fenced blocks private identities before Qt discards adjacent boundaries.
// The native importer removes fence lines; display text and raw input are kept.
ChatCodeMarkdown PrepareChatCodeMarkdown(std::string_view markdown);
} // namespace ida_agent::ai
