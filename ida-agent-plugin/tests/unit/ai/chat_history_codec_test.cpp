#include "ai/chat_history_codec.hpp"
#include "ai/agent_tool_registry.hpp"
#include "ai/agent_tool_transcript.hpp"
#include "ai/provider_agent_protocol.hpp"

#include <stdexcept>
#include <string>
#include <vector>

namespace
{

void Require(bool condition, const char *message)
{
  if ( !condition )
    throw std::runtime_error(message);
}

} // namespace

int main()
{
  using namespace ida_agent::ai;

  const AgentToolCall tool_call{
      "call-history", "ida_decompile",
      R"({"address":"0x401000","max_lines":128})"};
  const AgentToolResult tool_result{
      "call-history", "ida_decompile", false,
      R"({"complete":"failure output"})", "display-safe-message"};
  const std::string tool_call_text = FormatAgentToolCallTranscript(tool_call);
  const std::string tool_result_text = FormatAgentToolResultTranscript(tool_result);
  Require(
      tool_call_text
          == "Call: ida_decompile, Arguments: address=0x401000, max_lines=128",
      "tool call display omitted its arguments");
  Require(
      FormatAgentToolCallTranscript({"empty", "empty_tool", "{}"})
          == "Call: empty_tool, Arguments: (none)",
      "empty tool call arguments were not identified");
  Require(
      FormatAgentToolCallTranscript({"invalid", "invalid_tool", "[1]"})
          == "Call: invalid_tool, Arguments: (invalid)",
      "non-object tool call arguments were accepted");
  const std::string escaped_call_text = FormatAgentToolCallTranscript({
      "escaped", "escaped_tool",
      R"({"z\nkey":"first\nsecond\rthird\tlast","a":true,"nested":{"items":[1,null],"line":"x\u0085y"},"separator":"before\u2028after","c1":"before\u0085after"})"});
  Require(
      escaped_call_text
          == "Call: escaped_tool, Arguments: z\\nkey=first\\nsecond\\rthird\\tlast, a=true, nested={\"items\":[1,null],\"line\":\"x\\u0085y\"}, separator=before\\u2028after, c1=before\\u0085after"
          && escaped_call_text.find('\n') == std::string::npos
          && escaped_call_text.find('\r') == std::string::npos
          && escaped_call_text.find("\xC2\x85") == std::string::npos,
      "tool call arguments were not kept on one line in source order");
  Require(tool_result_text == "Result: ida_decompile - failed"
              && tool_result_text.find(tool_result.output) == std::string::npos
              && tool_result_text.find(tool_result.safe_message) == std::string::npos,
          "tool result display was not reduced to success/failure");
  const std::vector<ChatEntry> entries{
      {ChatSpeaker::User, "question"},
      {ChatSpeaker::Thinking, "summary"},
      {ChatSpeaker::Tool, tool_call_text},
      {ChatSpeaker::Tool, tool_result_text},
      {ChatSpeaker::Context, "earlier context"},
      {ChatSpeaker::Assistant, "answer"},
      {ChatSpeaker::System, "tool summary"},
  };
  const auto encoded = EncodeChatHistory(entries);
  Require(encoded.has_value(), "valid history was not encoded");
  Require(encoded->find("api_key") == std::string::npos, "unexpected credential field encoded");
  const auto decoded = DecodeChatHistory(*encoded);
  Require(decoded.has_value(), "valid history was not decoded");
  Require(decoded->size() == entries.size(), "history entry count mismatch");
  Require((*decoded)[0].speaker == ChatSpeaker::User, "user speaker mismatch");
  Require((*decoded)[1].speaker == ChatSpeaker::Thinking, "thinking speaker mismatch");
  Require((*decoded)[2].speaker == ChatSpeaker::Tool, "tool speaker mismatch");
  Require((*decoded)[2].text == tool_call_text
              && (*decoded)[3].text == tool_result_text,
          "full tool call/result did not survive history round-trip");
  Require((*decoded)[4].speaker == ChatSpeaker::Context, "context speaker mismatch");
  Require((*decoded)[5].speaker == ChatSpeaker::Assistant, "assistant speaker mismatch");
  Require((*decoded)[6].text == "tool summary", "system text mismatch");

  const auto escaped_history = EncodeChatHistory({
      {ChatSpeaker::Tool, escaped_call_text},
  });
  Require(escaped_history.has_value(), "escaped tool call was not encoded");
  const auto escaped_round_trip = DecodeChatHistory(*escaped_history);
  Require(escaped_round_trip.has_value()
              && escaped_round_trip->size() == 1
              && (*escaped_round_trip)[0].text == escaped_call_text,
          "escaped tool call did not survive history round-trip");

  const AgentToolResult maximum_result{
      "call-maximum", "ida_function_export", true,
      std::string(MaxAgentToolResultBytes, 'r'), {}};
  const std::string maximum_result_text =
      FormatAgentToolResultTranscript(maximum_result);
  Require(maximum_result_text == "Result: ida_function_export - success",
          "maximum tool result leaked its payload");
  Require(EncodeChatHistory({{ChatSpeaker::Tool, maximum_result_text}}).has_value(),
          "complete maximum tool result could not be persisted");

  const AgentToolCall maximum_call{
      std::string(MaxAgentToolCallIdBytes, 'i'),
      std::string(MaxAgentToolNameBytes, 'n'),
      "{\"value\":\""
          + std::string(MaxAgentToolArgumentsBytes - 12, 'a') + "\"}",
  };
  Require(maximum_call.arguments_json.size() == MaxAgentToolArgumentsBytes,
          "maximum tool call fixture size mismatch");
  const AgentToolCall maximum_file_call{
      "call-maximum-file",
      "ida_file_mutate",
      "{\"content\":\""
          + std::string(MaxAgentFileToolArgumentsBytes - 14, 'f') + "\"}",
  };
  Require(
      maximum_file_call.arguments_json.size()
          == MaxAgentFileToolArgumentsBytes,
      "maximum file tool call fixture size mismatch");
  const AgentToolResult dual_field_failure{
      maximum_call.id,
      maximum_call.name,
      false,
      std::string(MaxAgentToolResultBytes, 'o'),
      std::string(MaxAgentToolResultBytes, 'm'),
  };
  const std::string maximum_call_text =
      FormatAgentToolCallTranscript(maximum_call);
  const std::string dual_field_failure_text =
      FormatAgentToolResultTranscript(dual_field_failure);
  const std::string maximum_file_call_text =
      FormatAgentToolCallTranscript(maximum_file_call);
  Require(maximum_call_text
              == "Call: " + maximum_call.name
                  + ", Arguments: value="
                  + std::string(MaxAgentToolArgumentsBytes - 12, 'a'),
          "maximum tool call arguments were not preserved");
  Require(dual_field_failure_text == "Result: " + maximum_call.name + " - failed",
          "dual-field failure was not reduced to failed status");
  Require(maximum_file_call_text
              == "Call: " + maximum_file_call.name
                  + ", Arguments: content="
                  + std::string(MaxAgentFileToolArgumentsBytes - 14, 'f'),
          "maximum file tool call arguments were not preserved");
  ChatTranscript maximum_transcript;
  Require(maximum_transcript.Append(ChatSpeaker::Tool, maximum_call_text)
              && maximum_transcript.Append(
                  ChatSpeaker::Tool, dual_field_failure_text)
              && maximum_transcript.Append(
                  ChatSpeaker::Tool, maximum_file_call_text),
           "maximum Tool status transcript could not be displayed");
  const auto maximum_history = EncodeChatHistory(maximum_transcript.Entries());
  Require(maximum_history.has_value(),
           "maximum Tool status transcript could not be encoded");
  const auto maximum_history_round_trip = DecodeChatHistory(*maximum_history);
  Require(maximum_history_round_trip.has_value()
              && maximum_history_round_trip->size() == 5
              && (*maximum_history_round_trip)[2].text == maximum_call_text
              && (*maximum_history_round_trip)[3].text
                  == dual_field_failure_text
              && (*maximum_history_round_trip)[4].text
                  == maximum_file_call_text,
           "maximum Tool status transcript did not survive history round-trip");
  Require(dual_field_failure_text.find(dual_field_failure.output)
              == std::string::npos
              && dual_field_failure_text.find(dual_field_failure.safe_message)
                  == std::string::npos,
          "dual-field failure payload leaked into the transcript");

  Require(!DecodeChatHistory("{}").has_value(), "missing fields accepted");
  Require(
      !DecodeChatHistory(R"({"version":2,"entries":[]})").has_value(),
      "unknown version accepted");
  Require(
      !DecodeChatHistory(R"({"version":1,"entries":[],"extra":true})").has_value(),
      "unknown root field accepted");
  Require(
      !DecodeChatHistory(R"({"version":1,"entries":[{"speaker":"developer","text":"x"}]})").has_value(),
      "unknown speaker accepted");
  Require(
      !DecodeChatHistory(R"({"version":1,"entries":[{"speaker":"user","text":"x","extra":1}]})").has_value(),
      "unknown entry field accepted");

  std::vector<ChatEntry> oversized{{ChatSpeaker::User, std::string(MaxChatEntryBytes + 1, 'x')}};
  Require(!EncodeChatHistory(oversized).has_value(), "oversized entry encoded");
  const std::string invalid_utf8(1, static_cast<char>(0xFF));
  Require(
      !EncodeChatHistory({{ChatSpeaker::User, invalid_utf8}}).has_value(),
      "invalid UTF-8 entry encoded");

  std::string excessive_entries = R"({"version":1,"entries":[)";
  for ( std::size_t index = 0; index <= MaxChatHistoryEntries; ++index )
  {
    if ( index != 0 ) excessive_entries.push_back(',');
    excessive_entries += R"({"speaker":"user","text":""})";
  }
  excessive_entries += "]}";
  Require(
      !DecodeChatHistory(excessive_entries).has_value(),
      "excessive entry count accepted");

  std::vector<ChatEntry> near_limit(
      MaxChatHistoryEntries,
      ChatEntry{ChatSpeaker::User, std::string(790, 'a')});
  const auto near_limit_encoded = EncodeChatHistory(near_limit);
  Require(near_limit_encoded.has_value(), "near-limit valid history was not encoded");
  ChatTranscript restored;
  Require(restored.Restore(near_limit), "near-limit valid history was not restored");
  Require(restored.Entries().size() == near_limit.size(), "restore silently trimmed valid history");
  Require(restored.Entries().front().text == near_limit.front().text, "restore lost first entry");
  Require(restored.Entries().back().text == near_limit.back().text, "restore lost last entry");
  return 0;
}
