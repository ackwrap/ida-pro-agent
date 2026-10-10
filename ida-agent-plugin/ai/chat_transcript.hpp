#pragma once

#include "ai/chat_limits.hpp"

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace ida_agent::ai
{

inline constexpr std::size_t MaxChatHistoryBytes = 4 * 1024 * 1024;
inline constexpr std::size_t MaxChatHistoryEntries = 5000;
inline constexpr std::size_t MaxChatEntryBytes = MaxChatResponseBytes;
// Also covers maximum file-tool arguments after control and Unicode line
// separators are expanded into a single-line display form.
inline constexpr std::size_t MaxToolChatEntryBytes = MaxChatEntryBytes;

enum class ChatSpeaker
{
  User,
  Assistant,
  Context,
  Thinking,
  Tool,
  System,
};

struct ChatEntry
{
  ChatSpeaker speaker;
  std::string text;
};

struct ChatTranscriptAppendResult
{
  bool appended = false;
  std::size_t trimmed_entries = 0;
  bool display_rebuild_required = false;
};

constexpr std::size_t MaxChatEntryBytesFor(ChatSpeaker speaker) noexcept
{
  return speaker == ChatSpeaker::Tool
      ? MaxToolChatEntryBytes
      : MaxChatEntryBytes;
}

class ChatPreview final
{
public:
  void Begin();
  bool Append(std::string_view text);
  void Discard() noexcept;
  bool HasValue() const noexcept;
  const std::string &Text() const noexcept;

private:
  std::string text_;
  bool active_ = false;
};

class ChatTranscript
{
public:
  explicit ChatTranscript(std::size_t max_lines = 5000);

  void Reset();
  bool Restore(std::vector<ChatEntry> entries);
  bool Append(ChatSpeaker speaker, std::string_view text);
  ChatTranscriptAppendResult AppendDetailed(
      ChatSpeaker speaker,
      std::string_view text);
  const std::vector<ChatEntry> &Entries() const noexcept;
  const std::vector<std::string> &Lines() const noexcept;

private:
  bool AppendEntry(
      ChatEntry entry,
      bool rebuild,
      bool trim_oldest,
      std::size_t *trimmed_entries = nullptr);
  void RebuildLines();
  static std::size_t EncodedEntryBudget(const ChatEntry &entry);

  std::size_t max_lines_;
  std::size_t encoded_budget_ = 26;
  std::vector<ChatEntry> entries_;
  std::vector<std::string> lines_;
};

} // namespace ida_agent::ai
