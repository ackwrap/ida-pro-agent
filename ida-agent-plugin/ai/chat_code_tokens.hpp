#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace ida_agent::ai
{
enum class ChatCodeLanguage { Plain, Cpp, Python, Assembly, Json };
enum class ChatCodeTokenKind { Keyword, Type, String, Comment, Number, Function, Directive, Property };

struct ChatCodeToken
{
  std::size_t start;
  std::size_t length;
  ChatCodeTokenKind kind;
};

struct ChatCodeState
{
  enum class Mode { Normal, Comment, String };
  Mode mode = Mode::Normal;
  std::u16string terminator;
  bool escapes = true;
  bool multiline = false;
};

inline constexpr std::size_t MaxChatCodeLineSpans = 256;
inline constexpr std::size_t MaxChatCodeMessageSpans = 4096;

// Positions use UTF-16 code units, matching QString and QTextLayout.
ChatCodeLanguage ResolveChatCodeLanguage(std::string_view hint, std::u16string_view code);
std::vector<ChatCodeToken> TokenizeChatCodeLine(std::u16string_view line,
    ChatCodeLanguage language, ChatCodeState &state,
    std::size_t span_budget = MaxChatCodeLineSpans);
} // namespace ida_agent::ai
