#include "ai/sse_parser.hpp"

#include <algorithm>
#include <limits>
#include <utility>

namespace ida_agent::ai
{
namespace
{

bool IsValidUtf8(std::string_view value)
{
  std::size_t index = 0;
  while ( index < value.size() )
  {
    const unsigned char first = static_cast<unsigned char>(value[index]);
    if ( first <= 0x7f )
    {
      ++index;
      continue;
    }

    std::size_t continuation_count = 0;
    std::uint32_t code_point = 0;
    if ( first >= 0xc2 && first <= 0xdf )
    {
      continuation_count = 1;
      code_point = first & 0x1f;
    }
    else if ( first >= 0xe0 && first <= 0xef )
    {
      continuation_count = 2;
      code_point = first & 0x0f;
    }
    else if ( first >= 0xf0 && first <= 0xf4 )
    {
      continuation_count = 3;
      code_point = first & 0x07;
    }
    else
    {
      return false;
    }
    if ( continuation_count > value.size() - index - 1 )
      return false;
    for ( std::size_t offset = 1; offset <= continuation_count; ++offset )
    {
      const unsigned char continuation = static_cast<unsigned char>(value[index + offset]);
      if ( (continuation & 0xc0) != 0x80 )
        return false;
      code_point = (code_point << 6) | (continuation & 0x3f);
    }
    if ( (continuation_count == 2 && code_point < 0x800)
        || (continuation_count == 3 && code_point < 0x10000)
        || (code_point >= 0xd800 && code_point <= 0xdfff)
        || code_point > 0x10ffff )
    {
      return false;
    }
    index += continuation_count + 1;
  }
  return true;
}

bool ParseDecimal(std::string_view value, std::uint64_t &parsed)
{
  if ( value.empty() )
    return false;
  parsed = 0;
  for ( const unsigned char character : value )
  {
    if ( character < '0' || character > '9' )
      return false;
    const std::uint64_t digit = character - '0';
    if ( parsed > ((std::numeric_limits<std::uint64_t>::max)() - digit) / 10 )
      return false;
    parsed = parsed * 10 + digit;
  }
  return true;
}

} // namespace

SseParser::SseParser(SseParserLimits limits) : limits_(limits)
{
  if ( limits_.max_line_bytes == 0
      || limits_.max_line_bytes > SseHardMaxLineBytes
      || limits_.max_event_bytes == 0
      || limits_.max_event_bytes > SseHardMaxEventBytes
      || limits_.max_scratch_bytes == 0
      || limits_.max_scratch_bytes > SseHardMaxScratchBytes )
  {
    failed_ = true;
    failure_message_ = "SSE parser limits are invalid.";
  }
}

SseParseResult SseParser::Feed(std::string_view bytes)
{
  SseParseResult result;
  if ( failed_ )
  {
    result.status = SseParseStatus::Error;
    result.message = failure_message_;
    return result;
  }
  if ( finished_ )
  {
    result.status = SseParseStatus::Finished;
    return result;
  }

  std::string resolved_prefix;
  if ( !bom_checked_ )
  {
    constexpr std::string_view bom("\xEF\xBB\xBF", 3);
    std::size_t consumed = 0;
    while ( consumed < bytes.size() && !bom_checked_ )
    {
      bom_probe_.push_back(bytes[consumed++]);
      const bool matches = bom.substr(0, bom_probe_.size()) == bom_probe_;
      if ( !matches || bom_probe_.size() == bom.size() )
      {
        bom_checked_ = true;
        if ( !matches )
          resolved_prefix = std::move(bom_probe_);
        bom_probe_.clear();
      }
    }
    if ( !bom_checked_ )
      return result;
    bytes.remove_prefix(consumed);
  }

  const auto process_bytes = [&](std::string_view input)
  {
    for ( const char character : input )
    {
      if ( pending_cr_ )
      {
        pending_cr_ = false;
        if ( character == '\n' )
          continue;
      }
      if ( character == '\r' || character == '\n' )
      {
        if ( !ProcessLine(result) )
          return false;
        pending_cr_ = character == '\r';
        continue;
      }
      if ( line_.size() == limits_.max_line_bytes )
      {
        Fail(result, "SSE line exceeds the size limit.");
        return false;
      }
      line_.push_back(character);
      if ( !CheckScratch(result) )
        return false;
    }
    return true;
  };
  if ( !process_bytes(resolved_prefix) || !process_bytes(bytes) )
    return result;

  result.status = result.events.empty()
      ? SseParseStatus::Ok
      : SseParseStatus::EventAvailable;
  return result;
}

SseParseResult SseParser::Finish()
{
  SseParseResult result;
  if ( failed_ )
  {
    result.status = SseParseStatus::Error;
    result.message = failure_message_;
    return result;
  }
  if ( finished_ )
  {
    result.status = SseParseStatus::Finished;
    return result;
  }
  if ( !bom_checked_ )
  {
    bom_checked_ = true;
    line_.append(bom_probe_);
    bom_probe_.clear();
    if ( !CheckScratch(result) )
      return result;
  }
  pending_cr_ = false;
  if ( !line_.empty() && !ProcessLine(result) )
    return result;
  if ( !Dispatch(result) )
    return result;
  finished_ = true;
  result.status = result.events.empty()
      ? SseParseStatus::Finished
      : SseParseStatus::EventAvailable;
  return result;
}

bool SseParser::CheckScratch(SseParseResult &result)
{
  const std::size_t used = line_.size() + data_.size() + event_.size()
      + last_event_id_.size();
  return used <= limits_.max_scratch_bytes
      || Fail(result, "SSE parser scratch space exceeds the size limit.");
}

bool SseParser::ProcessLine(SseParseResult &result)
{
  if ( !IsValidUtf8(line_) )
    return Fail(result, "SSE stream contains invalid UTF-8.");
  if ( line_.empty() )
    return Dispatch(result);
  if ( line_[0] == ':' )
  {
    line_.clear();
    return true;
  }

  const std::size_t colon = line_.find(':');
  const std::string_view field(line_.data(), colon == std::string::npos ? line_.size() : colon);
  std::string_view value;
  if ( colon != std::string::npos )
  {
    const std::size_t value_offset = colon + 1
        + (colon + 1 < line_.size() && line_[colon + 1] == ' ' ? 1 : 0);
    value = std::string_view(line_).substr(value_offset);
  }

  if ( field == "data" )
  {
    const std::size_t separator = data_seen_ ? 1 : 0;
    if ( value.size() > limits_.max_event_bytes - (std::min)(
            limits_.max_event_bytes,
            data_.size() + event_.size() + last_event_id_.size() + separator) )
    {
      return Fail(result, "SSE event exceeds the size limit.");
    }
    if ( data_seen_ )
      data_.push_back('\n');
    data_.append(value.data(), value.size());
    data_seen_ = true;
  }
  else if ( field == "event" )
  {
    if ( value.size() > limits_.max_event_bytes - (std::min)(
            limits_.max_event_bytes,
            data_.size() + last_event_id_.size()) )
      return Fail(result, "SSE event exceeds the size limit.");
    event_.assign(value.data(), value.size());
  }
  else if ( field == "id" )
  {
    if ( value.find('\0') == std::string_view::npos )
    {
      if ( value.size() > limits_.max_event_bytes - (std::min)(
              limits_.max_event_bytes,
              data_.size() + event_.size()) )
      {
        return Fail(result, "SSE event exceeds the size limit.");
      }
      last_event_id_.assign(value.data(), value.size());
    }
  }
  else if ( field == "retry" )
  {
    std::uint64_t retry = 0;
    if ( ParseDecimal(value, retry) )
      retry_ms_ = retry;
  }
  line_.clear();
  return CheckScratch(result);
}

bool SseParser::Dispatch(SseParseResult &result)
{
  line_.clear();
  if ( !data_seen_ )
  {
    ResetEvent();
    return true;
  }
  SseEvent dispatched;
  dispatched.event = event_.empty() ? "message" : std::move(event_);
  dispatched.data = std::move(data_);
  dispatched.id = last_event_id_;
  dispatched.retry_ms = retry_ms_;
  result.events.push_back(std::move(dispatched));
  ResetEvent();
  return true;
}

bool SseParser::Fail(SseParseResult &result, std::string message)
{
  failed_ = true;
  failure_message_ = std::move(message);
  result.status = SseParseStatus::Error;
  result.message = failure_message_;
  return false;
}

void SseParser::ResetEvent()
{
  data_.clear();
  event_.clear();
  retry_ms_.reset();
  data_seen_ = false;
}

} // namespace ida_agent::ai
