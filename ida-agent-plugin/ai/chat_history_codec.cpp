#include "ai/chat_history_codec.hpp"

#include <nlohmann/json.hpp>

namespace ida_agent::ai
{
namespace
{

constexpr int SchemaVersion = 1;

const char *SpeakerName(ChatSpeaker speaker)
{
  switch ( speaker )
  {
    case ChatSpeaker::User:
      return "user";
    case ChatSpeaker::Assistant:
      return "assistant";
    case ChatSpeaker::Context:
      return "context";
    case ChatSpeaker::Thinking:
      return "thinking";
    case ChatSpeaker::Tool:
      return "tool";
    case ChatSpeaker::System:
      return "system";
  }
  return "system";
}

std::optional<ChatSpeaker> ParseSpeaker(const std::string &speaker)
{
  if ( speaker == "user" )
    return ChatSpeaker::User;
  if ( speaker == "assistant" )
    return ChatSpeaker::Assistant;
  if ( speaker == "context" )
    return ChatSpeaker::Context;
  if ( speaker == "thinking" )
    return ChatSpeaker::Thinking;
  if ( speaker == "tool" )
    return ChatSpeaker::Tool;
  if ( speaker == "system" )
    return ChatSpeaker::System;
  return std::nullopt;
}

class HistorySax final : public nlohmann::json_sax<nlohmann::json>
{
public:
  bool null() override { return false; }
  bool boolean(bool) override { return false; }
  bool number_integer(number_integer_t value) override
  {
    return ConsumeVersion(value >= 0 ? static_cast<number_unsigned_t>(value) : number_unsigned_t(-1));
  }
  bool number_unsigned(number_unsigned_t value) override { return ConsumeVersion(value); }
  bool number_float(number_float_t, const string_t &) override { return false; }
  bool binary(binary_t &) override { return false; }

  bool string(string_t &value) override
  {
    if ( context_ != Context::Entry )
      return false;
    if ( pending_ == Pending::Speaker )
    {
      current_speaker_ = ParseSpeaker(value);
      pending_ = Pending::None;
      speaker_seen_ = current_speaker_.has_value();
      return speaker_seen_;
    }
    if ( pending_ == Pending::Text )
    {
      if ( value.size() > MaxToolChatEntryBytes
          || text_bytes_ > MaxChatHistoryBytes - value.size() )
      {
        return false;
      }
      text_bytes_ += value.size();
      current_text_ = std::move(value);
      pending_ = Pending::None;
      text_seen_ = true;
      return true;
    }
    return false;
  }

  bool start_object(std::size_t) override
  {
    if ( context_ == Context::None )
    {
      context_ = Context::Root;
      return true;
    }
    if ( context_ != Context::Entries
        || entries_.size() >= MaxChatHistoryEntries )
    {
      return false;
    }
    context_ = Context::Entry;
    pending_ = Pending::None;
    current_speaker_.reset();
    current_text_.clear();
    speaker_seen_ = false;
    text_seen_ = false;
    return true;
  }

  bool key(string_t &value) override
  {
    if ( pending_ != Pending::None )
      return false;
    if ( context_ == Context::Root )
    {
      if ( value == "version" && !version_seen_ )
      {
        pending_ = Pending::Version;
        return true;
      }
      if ( value == "entries" && !entries_seen_ && !entries_started_ )
      {
        pending_ = Pending::Entries;
        return true;
      }
      return false;
    }
    if ( context_ == Context::Entry )
    {
      if ( value == "speaker" && !speaker_seen_ )
      {
        pending_ = Pending::Speaker;
        return true;
      }
      if ( value == "text" && !text_seen_ )
      {
        pending_ = Pending::Text;
        return true;
      }
    }
    return false;
  }

  bool end_object() override
  {
    if ( pending_ != Pending::None )
      return false;
    if ( context_ == Context::Entry )
    {
      if ( !speaker_seen_ || !text_seen_ || !current_speaker_ )
        return false;
      if ( current_text_.size() > MaxChatEntryBytesFor(*current_speaker_) )
        return false;
      entries_.push_back(ChatEntry{*current_speaker_, std::move(current_text_)});
      context_ = Context::Entries;
      return true;
    }
    if ( context_ == Context::Root && version_seen_ && entries_seen_ )
    {
      context_ = Context::Done;
      return true;
    }
    return false;
  }

  bool start_array(std::size_t elements) override
  {
    if ( context_ != Context::Root
        || pending_ != Pending::Entries
        || (elements != std::size_t(-1) && elements > MaxChatHistoryEntries) )
    {
      return false;
    }
    pending_ = Pending::None;
    entries_started_ = true;
    context_ = Context::Entries;
    return true;
  }

  bool end_array() override
  {
    if ( context_ != Context::Entries )
      return false;
    context_ = Context::Root;
    entries_started_ = false;
    entries_seen_ = true;
    return true;
  }

  bool parse_error(std::size_t, const std::string &, const nlohmann::detail::exception &) override
  {
    return false;
  }

  bool Complete() const noexcept { return context_ == Context::Done; }
  std::vector<ChatEntry> TakeEntries() { return std::move(entries_); }

private:
  enum class Context { None, Root, Entries, Entry, Done };
  enum class Pending { None, Version, Entries, Speaker, Text };

  bool ConsumeVersion(number_unsigned_t value)
  {
    if ( context_ != Context::Root || pending_ != Pending::Version || value != SchemaVersion )
      return false;
    pending_ = Pending::None;
    version_seen_ = true;
    return true;
  }

  Context context_ = Context::None;
  Pending pending_ = Pending::None;
  bool version_seen_ = false;
  bool entries_started_ = false;
  bool entries_seen_ = false;
  bool speaker_seen_ = false;
  bool text_seen_ = false;
  std::size_t text_bytes_ = 0;
  std::optional<ChatSpeaker> current_speaker_;
  std::string current_text_;
  std::vector<ChatEntry> entries_;
};

} // namespace

std::optional<std::string> EncodeChatHistory(const std::vector<ChatEntry> &entries)
{
  if ( entries.size() > MaxChatHistoryEntries )
    return std::nullopt;
  try
  {
    nlohmann::json encoded_entries = nlohmann::json::array();
    std::size_t text_bytes = 0;
    for ( const ChatEntry &entry : entries )
    {
      if ( entry.text.size() > MaxChatEntryBytesFor(entry.speaker)
          || text_bytes > MaxChatHistoryBytes - entry.text.size() )
      {
        return std::nullopt;
      }
      text_bytes += entry.text.size();
      encoded_entries.push_back({{"speaker", SpeakerName(entry.speaker)}, {"text", entry.text}});
    }
    nlohmann::json root{{"version", SchemaVersion}, {"entries", std::move(encoded_entries)}};
    std::string encoded = root.dump();
    if ( encoded.size() > MaxChatHistoryBytes )
      return std::nullopt;
    return encoded;
  }
  catch ( const nlohmann::json::exception & )
  {
    return std::nullopt;
  }
}

std::optional<std::vector<ChatEntry>> DecodeChatHistory(std::string_view encoded)
{
  if ( encoded.empty() || encoded.size() > MaxChatHistoryBytes )
    return std::nullopt;
  try
  {
    HistorySax sax;
    if ( !nlohmann::json::sax_parse(encoded, &sax) || !sax.Complete() )
      return std::nullopt;
    return sax.TakeEntries();
  }
  catch ( const std::exception & )
  {
    return std::nullopt;
  }
}

} // namespace ida_agent::ai
