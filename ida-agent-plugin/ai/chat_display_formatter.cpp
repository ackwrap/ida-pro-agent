#include "ai/chat_display_formatter.hpp"

#include <algorithm>

namespace ida_agent::ai
{
namespace
{

std::string_view Prefix(ChatSpeaker speaker)
{
  switch ( speaker )
  {
    case ChatSpeaker::User:
      return "[You] ";
    case ChatSpeaker::Assistant:
      return "[AI] ";
    case ChatSpeaker::Context:
      return "[Context] ";
    case ChatSpeaker::Thinking:
      return "[Thinking] ";
    case ChatSpeaker::Tool:
      return "[Tool] ";
    case ChatSpeaker::System:
      return "[System] ";
  }
  return {};
}

std::size_t Utf8CodePointBytes(std::string_view text, std::size_t offset)
{
  const unsigned char first = static_cast<unsigned char>(text[offset]);
  if ( first < 0x80 )
    return 1;
  if ( first < 0xE0 )
    return 2;
  if ( first < 0xF0 )
    return 3;
  return 4;
}

std::size_t Utf16Units(std::string_view text)
{
  std::size_t units = 0;
  for ( std::size_t offset = 0; offset < text.size(); )
  {
    const std::size_t bytes = Utf8CodePointBytes(text, offset);
    units += bytes == 4 ? 2 : 1;
    offset += bytes;
  }
  return units;
}

std::size_t LongestSuffixPrefixOverlap(
    std::string_view old_display,
    std::string_view new_display)
{
  if ( new_display.empty() )
    return 0;
  std::vector<std::size_t> prefix(new_display.size());
  for ( std::size_t index = 1, matched = 0;
        index < new_display.size();
        ++index )
  {
    while ( matched != 0 && new_display[index] != new_display[matched] )
      matched = prefix[matched - 1];
    if ( new_display[index] == new_display[matched] )
      ++matched;
    prefix[index] = matched;
  }

  std::size_t matched = 0;
  for ( const char character : old_display )
  {
    while ( matched != 0
        && (matched == new_display.size()
            || character != new_display[matched]) )
    {
      matched = prefix[matched - 1];
    }
    if ( character == new_display[matched] )
      ++matched;
  }
  return matched;
}

std::size_t CommonUtf8SuffixBytes(
    std::string_view left,
    std::string_view right)
{
  std::size_t matched = 0;
  while ( matched < left.size() && matched < right.size()
      && left[left.size() - matched - 1] == right[right.size() - matched - 1] )
  {
    ++matched;
  }
  while ( matched != 0
      && (static_cast<unsigned char>(right[right.size() - matched]) & 0xC0) == 0x80 )
  {
    --matched;
  }
  return matched;
}

void AppendSegmentedLine(std::string &output, std::string_view line)
{
  std::size_t line_bytes = 0;
  for ( std::size_t offset = 0; offset < line.size(); )
  {
    const std::size_t code_point_bytes = Utf8CodePointBytes(line, offset);
    if ( line_bytes != 0
        && line_bytes + code_point_bytes > MaxChatDisplayLineBytes )
    {
      output.push_back('\n');
      line_bytes = 0;
    }
    output.append(line.substr(offset, code_point_bytes));
    line_bytes += code_point_bytes;
    offset += code_point_bytes;
  }
}

} // namespace

void ChatDisplayStreamFormatter::Begin(ChatSpeaker speaker)
{
  const std::string_view prefix = Prefix(speaker);
  rendered_.assign(prefix);
  prefix_bytes_ = prefix.size();
  line_bytes_ = prefix.size();
  active_ = true;
}

std::string ChatDisplayStreamFormatter::Append(std::string_view text)
{
  if ( !active_ )
    return {};

  std::string suffix;
  suffix.reserve(text.size());
  for ( std::size_t offset = 0; offset < text.size(); )
  {
    if ( text[offset] == '\n' )
    {
      suffix.push_back('\n');
      suffix.append(prefix_bytes_, ' ');
      line_bytes_ = prefix_bytes_;
      ++offset;
      continue;
    }

    const std::size_t code_point_bytes = Utf8CodePointBytes(text, offset);
    if ( line_bytes_ != 0
        && line_bytes_ + code_point_bytes > MaxChatDisplayLineBytes )
    {
      suffix.push_back('\n');
      line_bytes_ = 0;
    }
    suffix.append(text.substr(offset, code_point_bytes));
    line_bytes_ += code_point_bytes;
    offset += code_point_bytes;
  }
  rendered_ += suffix;
  return suffix;
}

void ChatDisplayStreamFormatter::Reset() noexcept
{
  rendered_.clear();
  prefix_bytes_ = 0;
  line_bytes_ = 0;
  active_ = false;
}

bool ChatDisplayStreamFormatter::Active() const noexcept
{
  return active_;
}

const std::string &ChatDisplayStreamFormatter::Text() const noexcept
{
  return rendered_;
}

std::string FormatChatDisplayEntry(ChatSpeaker speaker, std::string_view text)
{
  ChatDisplayStreamFormatter formatter;
  formatter.Begin(speaker);
  formatter.Append(text);
  return formatter.Text();
}

std::string FormatChatDisplayLines(const std::vector<std::string> &lines)
{
  std::string output;
  for ( std::size_t index = 0; index < lines.size(); ++index )
  {
    if ( index != 0 )
      output.push_back('\n');
    AppendSegmentedLine(output, lines[index]);
  }
  return output;
}

std::string FormatChatPreviewFragment(std::string_view rendered, bool prior)
{
  return (prior ? "\n" : "") + std::string(rendered);
}

std::string FormatChatPreviewDisplay(
    bool has_committed,
    bool reasoning_active,
    std::string_view reasoning,
    bool assistant_active,
    std::string_view assistant)
{
  std::string display;
  if ( reasoning_active )
    display += FormatChatPreviewFragment(reasoning, has_committed);
  if ( assistant_active )
  {
    display += FormatChatPreviewFragment(
        assistant, has_committed || !display.empty());
  }
  return display;
}

ChatDisplayRemapPlan PlanChatDisplayRemap(
    std::string_view old_committed,
    std::string_view new_committed,
    std::string_view old_preview,
    ChatDisplayMigrationCandidate migration)
{
  ChatDisplayRemapPlan plan;
  plan.retained_overlap_utf8_bytes =
      LongestSuffixPrefixOverlap(old_committed, new_committed);
  plan.removed_utf8_bytes =
      old_committed.size() - plan.retained_overlap_utf8_bytes;
  const std::string_view removed =
      old_committed.substr(0, plan.removed_utf8_bytes);
  plan.removed_utf16_units = Utf16Units(removed);
  plan.removed_display_blocks = static_cast<std::size_t>(
      std::count(removed.begin(), removed.end(), '\n'));
  if ( plan.retained_overlap_utf8_bytes == 0 && !old_committed.empty() )
    ++plan.removed_display_blocks;
  plan.old_committed_utf16_units = Utf16Units(old_committed);
  plan.new_committed_utf16_units = Utf16Units(new_committed);
  plan.old_preview_utf16_units = Utf16Units(old_preview);
  if ( migration.old_preview_utf8_offset <= old_preview.size()
      && migration.utf8_bytes
          <= old_preview.size() - migration.old_preview_utf8_offset )
  {
    const std::string_view candidate = old_preview.substr(
        migration.old_preview_utf8_offset,
        migration.utf8_bytes);
    const std::size_t migrated_bytes =
        CommonUtf8SuffixBytes(new_committed, candidate);
    const std::string_view removed_candidate_prefix =
        candidate.substr(0, candidate.size() - migrated_bytes);
    const std::size_t migrated_offset =
        migration.old_preview_utf8_offset + candidate.size() - migrated_bytes;
    plan.migration_candidate_offset_utf16_units = Utf16Units(
        old_preview.substr(0, migration.old_preview_utf8_offset));
    plan.migration_candidate_utf16_units = Utf16Units(candidate);
    plan.removed_migration_prefix_utf16_units =
        Utf16Units(removed_candidate_prefix);
    plan.removed_migration_prefix_display_blocks = static_cast<std::size_t>(
        std::count(
            removed_candidate_prefix.begin(),
            removed_candidate_prefix.end(),
            '\n'));
    if ( migrated_bytes != 0
        && !removed_candidate_prefix.empty()
        && candidate.front() == '\n'
        && removed_candidate_prefix.back() == '\n' )
    {
      --plan.removed_migration_prefix_display_blocks;
    }
    else if ( migrated_bytes == 0
        && !candidate.empty()
        && candidate.front() != '\n' )
    {
      ++plan.removed_migration_prefix_display_blocks;
    }
    plan.migrated_preview_offset_utf16_units =
        Utf16Units(old_preview.substr(0, migrated_offset));
    plan.migrated_preview_utf16_units = Utf16Units(
        old_preview.substr(migrated_offset, migrated_bytes));
  }
  return plan;
}

std::size_t RemapChatDisplayCursor(
    const ChatDisplayRemapPlan &plan,
    std::size_t old_cursor) noexcept
{
  if ( plan.old_preview_utf16_units != 0
      && old_cursor >= plan.old_committed_utf16_units )
  {
    const std::size_t preview_offset =
        old_cursor - plan.old_committed_utf16_units;
    const std::size_t candidate_start =
        plan.migration_candidate_offset_utf16_units;
    const std::size_t candidate_end =
        candidate_start + plan.migration_candidate_utf16_units;
    const std::size_t migrated_start =
        plan.migrated_preview_offset_utf16_units;
    if ( plan.migration_candidate_utf16_units != 0
        && preview_offset >= candidate_start
        && preview_offset <= migrated_start )
    {
      return plan.new_committed_utf16_units
          - plan.migrated_preview_utf16_units;
    }
    if ( plan.migrated_preview_utf16_units != 0
        && preview_offset > migrated_start
        && preview_offset <= candidate_end )
    {
      return plan.new_committed_utf16_units
          - plan.migrated_preview_utf16_units
          + preview_offset - migrated_start;
    }
    return plan.new_committed_utf16_units + preview_offset
        - (preview_offset > candidate_end
              ? plan.migration_candidate_utf16_units
              : 0);
  }
  if ( old_cursor < plan.removed_utf16_units )
    return 0;
  return old_cursor - plan.removed_utf16_units;
}

} // namespace ida_agent::ai
