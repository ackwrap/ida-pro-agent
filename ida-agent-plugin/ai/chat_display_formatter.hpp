#pragma once

#include "ai/chat_transcript.hpp"

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace ida_agent::ai
{

inline constexpr std::size_t MaxChatDisplayLineBytes = 4096;

struct ChatDisplayRemapPlan
{
  std::size_t retained_overlap_utf8_bytes = 0;
  std::size_t removed_utf8_bytes = 0;
  std::size_t removed_utf16_units = 0;
  std::size_t removed_display_blocks = 0;
  std::size_t old_committed_utf16_units = 0;
  std::size_t new_committed_utf16_units = 0;
  std::size_t old_preview_utf16_units = 0;
  std::size_t migration_candidate_offset_utf16_units = 0;
  std::size_t migration_candidate_utf16_units = 0;
  std::size_t removed_migration_prefix_utf16_units = 0;
  std::size_t removed_migration_prefix_display_blocks = 0;
  std::size_t migrated_preview_offset_utf16_units = 0;
  std::size_t migrated_preview_utf16_units = 0;
};

struct ChatDisplayMigrationCandidate
{
  std::size_t old_preview_utf8_offset = 0;
  std::size_t utf8_bytes = 0;
};

class ChatDisplayStreamFormatter final
{
public:
  void Begin(ChatSpeaker speaker);
  std::string Append(std::string_view text);
  void Reset() noexcept;
  bool Active() const noexcept;
  const std::string &Text() const noexcept;

private:
  std::string rendered_;
  std::size_t prefix_bytes_ = 0;
  std::size_t line_bytes_ = 0;
  bool active_ = false;
};

std::string FormatChatDisplayEntry(ChatSpeaker speaker, std::string_view text);
std::string FormatChatDisplayLines(const std::vector<std::string> &lines);
std::string FormatChatPreviewFragment(std::string_view rendered, bool prior);
std::string FormatChatPreviewDisplay(
    bool has_committed,
    bool reasoning_active,
    std::string_view reasoning,
    bool assistant_active,
    std::string_view assistant);
ChatDisplayRemapPlan PlanChatDisplayRemap(
    std::string_view old_committed,
    std::string_view new_committed,
    std::string_view old_preview = {},
    ChatDisplayMigrationCandidate migration = {});
std::size_t RemapChatDisplayCursor(
    const ChatDisplayRemapPlan &plan,
    std::size_t old_cursor) noexcept;

} // namespace ida_agent::ai
