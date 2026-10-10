#include "ai/chat_transcript.hpp"

#include <algorithm>
#include <utility>

namespace ida_agent::ai
{
namespace
{

const char *Prefix(ChatSpeaker speaker)
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
  return "";
}

bool IsValidUtf8(std::string_view text)
{
  for ( std::size_t index = 0; index < text.size(); )
  {
    const unsigned char first = static_cast<unsigned char>(text[index]);
    if ( first < 0x80 )
    {
      ++index;
      continue;
    }
    std::size_t length = 0;
    unsigned char minimum_second = 0x80;
    unsigned char maximum_second = 0xBF;
    if ( first >= 0xC2 && first <= 0xDF )
      length = 2;
    else if ( first >= 0xE0 && first <= 0xEF )
    {
      length = 3;
      if ( first == 0xE0 ) minimum_second = 0xA0;
      if ( first == 0xED ) maximum_second = 0x9F;
    }
    else if ( first >= 0xF0 && first <= 0xF4 )
    {
      length = 4;
      if ( first == 0xF0 ) minimum_second = 0x90;
      if ( first == 0xF4 ) maximum_second = 0x8F;
    }
    else
    {
      return false;
    }
    if ( index + length > text.size() )
      return false;
    const unsigned char second = static_cast<unsigned char>(text[index + 1]);
    if ( second < minimum_second || second > maximum_second )
      return false;
    for ( std::size_t continuation = 2; continuation < length; ++continuation )
    {
      const unsigned char value = static_cast<unsigned char>(text[index + continuation]);
      if ( value < 0x80 || value > 0xBF )
        return false;
    }
    index += length;
  }
  return true;
}

std::string Sanitize(std::string_view text)
{
  std::string result;
  result.reserve(text.size());
  for ( unsigned char character : text )
  {
    if ( character == '\n' || character == '\t' || character >= 0x20 )
      result.push_back(static_cast<char>(character));
  }
  return result;
}

std::size_t JsonStringBudget(std::string_view text)
{
  std::size_t size = 2;
  for ( unsigned char character : text )
  {
    size += character == '"' || character == '\\' || character == '\n' || character == '\t'
        ? 2
        : 1;
  }
  return size;
}

std::size_t SpeakerBytes(ChatSpeaker speaker)
{
  switch ( speaker )
  {
    case ChatSpeaker::User:
      return 4;
    case ChatSpeaker::Assistant:
      return 9;
    case ChatSpeaker::Context:
      return 7;
    case ChatSpeaker::Thinking:
      return 8;
    case ChatSpeaker::Tool:
      return 4;
    case ChatSpeaker::System:
      return 6;
  }
  return 6;
}

} // namespace

ChatTranscript::ChatTranscript(std::size_t max_lines)
    : max_lines_(std::max<std::size_t>(max_lines, 1))
{
  Reset();
}

void ChatTranscript::Reset()
{
  entries_.clear();
  lines_.clear();
  encoded_budget_ = 26;
  Append(ChatSpeaker::System, "IDA Agent AI UI is ready.");
  Append(
      ChatSpeaker::System,
      "Provider chat is ready. Configure a provider and model before sending messages.");
}

void ChatPreview::Begin()
{
  text_.clear();
  active_ = true;
}

bool ChatPreview::Append(std::string_view text)
{
  if ( !active_ || text.size() > MaxChatEntryBytes - (std::min)(text_.size(), MaxChatEntryBytes)
      || !IsValidUtf8(text) )
  {
    return false;
  }
  text_ += Sanitize(text);
  return true;
}

void ChatPreview::Discard() noexcept
{
  text_.clear();
  active_ = false;
}

bool ChatPreview::HasValue() const noexcept
{
  return active_;
}

const std::string &ChatPreview::Text() const noexcept
{
  return text_;
}

bool ChatTranscript::Restore(std::vector<ChatEntry> entries)
{
  std::vector<ChatEntry> original_entries = entries_;
  std::vector<std::string> original_lines = lines_;
  const std::size_t original_budget = encoded_budget_;
  const auto rollback = [this, &original_entries, &original_lines, original_budget]()
  {
    entries_ = std::move(original_entries);
    lines_ = std::move(original_lines);
    encoded_budget_ = original_budget;
  };
  entries_.clear();
  lines_.clear();
  encoded_budget_ = 26;
  for ( ChatEntry &entry : entries )
  {
    if ( entry.text.size() > MaxChatEntryBytesFor(entry.speaker)
        || !IsValidUtf8(entry.text) )
    {
      rollback();
      return false;
    }
    entry.text = Sanitize(entry.text);
    if ( !AppendEntry(std::move(entry), false, false) )
    {
      rollback();
      return false;
    }
  }
  if ( entries_.empty() )
    Reset();
  else
    RebuildLines();
  return true;
}

bool ChatTranscript::Append(ChatSpeaker speaker, std::string_view text)
{
  return AppendDetailed(speaker, text).appended;
}

ChatTranscriptAppendResult ChatTranscript::AppendDetailed(
    ChatSpeaker speaker,
    std::string_view text)
{
  ChatTranscriptAppendResult result;
  if ( text.size() > MaxChatEntryBytesFor(speaker) || !IsValidUtf8(text) )
    return result;

  const std::size_t previous_lines = lines_.size();
  const std::string sanitized = Sanitize(text);
  const std::size_t added_lines = 1
      + static_cast<std::size_t>(std::count(sanitized.begin(), sanitized.end(), '\n'));
  result.appended = AppendEntry(
      ChatEntry{speaker, sanitized},
      true,
      true,
      &result.trimmed_entries);
  result.display_rebuild_required = result.appended
      && (result.trimmed_entries != 0
          || previous_lines + added_lines > max_lines_);
  return result;
}

bool ChatTranscript::AppendEntry(
    ChatEntry entry,
    bool rebuild,
    bool trim_oldest,
    std::size_t *trimmed_entries)
{
  if ( trimmed_entries != nullptr )
    *trimmed_entries = 0;
  const std::size_t entry_budget = EncodedEntryBudget(entry);
  if ( entry_budget > MaxChatHistoryBytes - 26 )
    return false;

  auto addition = [this, entry_budget]()
  {
    return entry_budget + (entries_.empty() ? 0 : 1);
  };
  while ( trim_oldest
      && !entries_.empty()
      && (entries_.size() >= MaxChatHistoryEntries
          || encoded_budget_ > MaxChatHistoryBytes - addition()) )
  {
    encoded_budget_ -= EncodedEntryBudget(entries_.front()) + (entries_.size() > 1 ? 1 : 0);
    entries_.erase(entries_.begin());
    if ( trimmed_entries != nullptr )
      ++*trimmed_entries;
  }
  if ( entries_.size() >= MaxChatHistoryEntries
      || encoded_budget_ > MaxChatHistoryBytes - addition() )
  {
    return false;
  }

  encoded_budget_ += addition();
  entries_.push_back(std::move(entry));
  if ( rebuild )
    RebuildLines();
  return true;
}

const std::vector<ChatEntry> &ChatTranscript::Entries() const noexcept
{
  return entries_;
}

const std::vector<std::string> &ChatTranscript::Lines() const noexcept
{
  return lines_;
}

void ChatTranscript::RebuildLines()
{
  std::vector<std::string> reverse_lines;
  reverse_lines.reserve(max_lines_);
  for ( auto entry = entries_.rbegin();
        entry != entries_.rend() && reverse_lines.size() < max_lines_;
        ++entry )
  {
    const std::string prefix = Prefix(entry->speaker);
    std::size_t end = entry->text.size();
    while ( reverse_lines.size() < max_lines_ )
    {
      const std::size_t newline = end == 0
          ? std::string::npos
          : entry->text.rfind('\n', end - 1);
      const std::size_t start = newline == std::string::npos ? 0 : newline + 1;
      reverse_lines.push_back((newline == std::string::npos
              ? prefix
              : std::string(prefix.size(), ' '))
          + entry->text.substr(start, end - start));
      if ( newline == std::string::npos )
        break;
      end = newline;
    }
  }
  lines_.assign(reverse_lines.rbegin(), reverse_lines.rend());
}

std::size_t ChatTranscript::EncodedEntryBudget(const ChatEntry &entry)
{
  return 22 + SpeakerBytes(entry.speaker) + JsonStringBudget(entry.text);
}

} // namespace ida_agent::ai
