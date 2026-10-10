#pragma once

#include "ai/chat_limits.hpp"
#include "ai/provider_agent_protocol.hpp"
#include "ai/provider_settings_model.hpp"
#include "ai/stream_client.hpp"

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

namespace ida_agent::ai
{

inline constexpr std::size_t MaxProviderChatTextBytes = MaxChatResponseBytes;
inline constexpr std::size_t MaxProviderRequestBodyBytes = 8 * 1024 * 1024;
inline constexpr std::size_t MaxProviderJsonStringBytes = 1024 * 1024;
inline constexpr std::size_t MaxProviderAgentFixedPayloadBytes = 1024 * 1024;
inline constexpr std::uint64_t ProviderChatMessageOverheadTokens = 8;
inline constexpr std::uint64_t ProviderChatReservedTokens = 4096;
inline constexpr std::string_view ProviderChatConfigurationErrorMessage =
    "Provider chat configuration is invalid.";
inline constexpr std::string_view ProviderChatProtocolErrorMessage =
    "Provider chat stream protocol error.";
inline constexpr std::string_view ProviderChatProviderErrorMessage =
    "Provider chat provider reported an error.";
inline constexpr std::string_view ProviderChatToolLimitMessage =
    "Provider tool call data exceeded size limits.";

namespace provider_chat_detail
{

struct TextTokenCounts
{
  std::uint64_t ascii_bytes = 0;
  std::uint64_t non_ascii_code_points = 0;
  std::uint64_t invalid_bytes = 0;
};

inline void CountTextTokens(std::string_view text, TextTokenCounts &counts)
{
  for ( std::size_t index = 0; index < text.size(); )
  {
    const unsigned char first = static_cast<unsigned char>(text[index]);
    if ( first < 0x80 )
    {
      ++counts.ascii_bytes;
      ++index;
      continue;
    }

    std::size_t length = 0;
    std::uint32_t code_point = 0;
    if ( first >= 0xC2 && first <= 0xDF )
    {
      length = 2;
      code_point = first & 0x1F;
    }
    else if ( first >= 0xE0 && first <= 0xEF )
    {
      length = 3;
      code_point = first & 0x0F;
    }
    else if ( first >= 0xF0 && first <= 0xF4 )
    {
      length = 4;
      code_point = first & 0x07;
    }
    if ( length == 0 || index + length > text.size() )
    {
      ++counts.invalid_bytes;
      ++index;
      continue;
    }

    bool valid = true;
    for ( std::size_t offset = 1; offset < length; ++offset )
    {
      const unsigned char continuation =
          static_cast<unsigned char>(text[index + offset]);
      if ( (continuation & 0xC0) != 0x80 )
      {
        valid = false;
        break;
      }
      code_point = (code_point << 6) | (continuation & 0x3F);
    }
    const std::uint32_t minimum = length == 2 ? 0x80
        : length == 3 ? 0x800 : 0x10000;
    if ( !valid || code_point < minimum || code_point > 0x10FFFF
        || (code_point >= 0xD800 && code_point <= 0xDFFF) )
    {
      ++counts.invalid_bytes;
      ++index;
      continue;
    }
    ++counts.non_ascii_code_points;
    index += length;
  }
}

inline std::uint64_t EstimateTextTokens(
    std::initializer_list<std::string_view> parts)
{
  TextTokenCounts counts;
  for ( const std::string_view part : parts )
    CountTextTokens(part, counts);
  return (counts.ascii_bytes + 3) / 4
      + counts.non_ascii_code_points + counts.invalid_bytes
      + ProviderChatMessageOverheadTokens;
}

inline std::uint64_t EstimateTextTokens(std::string_view text)
{
  return EstimateTextTokens({text});
}

} // namespace provider_chat_detail

enum class ProviderChatRole
{
  User,
  Assistant,
};

struct ProviderChatMessage
{
  ProviderChatRole role = ProviderChatRole::User;
  std::string text;
};

enum class ProviderChatCodec
{
  OpenAIResponses,
  OpenAIChatCompletions,
  ClaudeMessages,
};

struct ProviderChatBuildResult
{
  ProviderChatCodec codec = ProviderChatCodec::OpenAIResponses;
  StreamRequest request;
  std::vector<ProviderChatMessage> messages;
  std::uint32_t context_length = 0;
  std::uint32_t max_output_tokens = 0;
  std::uint64_t input_token_budget = 0;
  std::uint64_t estimated_input_tokens = 0;
  bool show_reasoning = false;
  bool error = false;
  std::string safe_message;
};

struct ProviderChatDecodeResult
{
  std::string text_delta;
  std::string reasoning_delta;
  std::vector<ProviderToolCallUpdate> updates;
  bool completed = false;
  bool error = false;
  std::string safe_message;
};

ProviderChatBuildResult BuildProviderChatRequest(
    const ProviderProfileDraft &profile,
    const std::vector<ProviderChatMessage> &messages);

ProviderChatBuildResult BuildProviderAgentRequest(
    const ProviderProfileDraft &profile,
    const std::vector<ProviderChatMessage> &transcript_messages,
    const ProviderChatAgentOptions &options);

ProviderChatDecodeResult DecodeProviderChatEvent(
    ProviderChatCodec codec,
    const SseEvent &event);

} // namespace ida_agent::ai
