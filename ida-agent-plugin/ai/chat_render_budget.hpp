#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace ida_agent::ai
{
inline constexpr std::size_t MaxRenderedChatMessages = 256;
inline constexpr std::size_t MaxRenderedChatBytes = 512 * 1024;
inline constexpr std::size_t MaxRenderedMessageBytes = 64 * 1024;
inline constexpr std::size_t MaxRenderedMessageLines = 1000;
inline constexpr std::size_t MaxChatMarkdownBytes = 32 * 1024;
inline constexpr std::size_t MaxChatMarkdownLines = 500;
inline constexpr std::size_t MaxRenderedChatLineBytes = 4096;
inline constexpr std::size_t MaxChatStreamBatchBytes = 16 * 1024;
inline constexpr std::string_view ChatDisplayLimitNotice =
    "\n[Display limit reached. Use Copy Message for the complete text.]";

struct ChatRenderChunk
{
  std::string text;
  std::size_t consumed = 0;
  std::size_t newlines = 0;
  std::size_t line_bytes = 0;
  bool line_limit = false;
};

ChatRenderChunk MakeChatRenderChunk(std::string_view text, std::size_t byte_budget,
    std::size_t newline_budget, std::size_t previous_line_bytes = 0);

// Input has already been validated by ChatTranscript/ChatPreview.
std::size_t ChatUtf8PrefixBytes(std::string_view text, std::size_t limit) noexcept;
std::size_t ChatRenderPrefixBytes(std::string_view text, std::size_t bytes,
    std::size_t lines) noexcept;
bool CanRenderChatMarkdown(std::string_view text) noexcept;
std::string BoundedChatRenderText(std::string_view text, bool *clipped = nullptr);
} // namespace ida_agent::ai
