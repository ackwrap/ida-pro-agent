#include "ai/agent_tool_transcript.hpp"

#include "ai/agent_tool_registry.hpp"

#include <string_view>

namespace ida_agent::ai
{
namespace
{

constexpr char HexDigits[] = "0123456789abcdef";

std::string EscapeSingleLine(std::string_view value)
{
  std::string escaped;
  escaped.reserve(value.size());
  for ( std::size_t index = 0; index < value.size(); ++index )
  {
    const unsigned char character = static_cast<unsigned char>(value[index]);
    if ( index + 1 < value.size()
        && character == 0xC2
        && static_cast<unsigned char>(value[index + 1]) >= 0x80
        && static_cast<unsigned char>(value[index + 1]) <= 0x9F )
    {
      const unsigned char second = static_cast<unsigned char>(value[index + 1]);
      escaped += "\\u00";
      escaped.push_back(HexDigits[second >> 4]);
      escaped.push_back(HexDigits[second & 0x0F]);
      ++index;
      continue;
    }
    if ( index + 2 < value.size()
        && character == 0xE2
        && static_cast<unsigned char>(value[index + 1]) == 0x80
        && (static_cast<unsigned char>(value[index + 2]) == 0xA8
            || static_cast<unsigned char>(value[index + 2]) == 0xA9) )
    {
      escaped += static_cast<unsigned char>(value[index + 2]) == 0xA8
          ? "\\u2028" : "\\u2029";
      index += 2;
      continue;
    }
    switch ( character )
    {
      case '\\':
        escaped += "\\\\";
        break;
      case '\b':
        escaped += "\\b";
        break;
      case '\f':
        escaped += "\\f";
        break;
      case '\n':
        escaped += "\\n";
        break;
      case '\r':
        escaped += "\\r";
        break;
      case '\t':
        escaped += "\\t";
        break;
      default:
        if ( character < 0x20 || character == 0x7F )
        {
          escaped += "\\u00";
          escaped.push_back(HexDigits[character >> 4]);
          escaped.push_back(HexDigits[character & 0x0F]);
        }
        else
        {
          escaped.push_back(static_cast<char>(character));
        }
        break;
    }
  }
  return escaped;
}

std::string EscapeJsonLineSeparators(std::string_view value)
{
  std::string escaped;
  escaped.reserve(value.size());
  for ( std::size_t index = 0; index < value.size(); ++index )
  {
    if ( index + 1 < value.size()
        && static_cast<unsigned char>(value[index]) == 0xC2
        && static_cast<unsigned char>(value[index + 1]) >= 0x80
        && static_cast<unsigned char>(value[index + 1]) <= 0x9F )
    {
      const unsigned char second = static_cast<unsigned char>(value[index + 1]);
      escaped += "\\u00";
      escaped.push_back(HexDigits[second >> 4]);
      escaped.push_back(HexDigits[second & 0x0F]);
      ++index;
      continue;
    }
    if ( index + 2 < value.size()
        && static_cast<unsigned char>(value[index]) == 0xE2
        && static_cast<unsigned char>(value[index + 1]) == 0x80
        && (static_cast<unsigned char>(value[index + 2]) == 0xA8
            || static_cast<unsigned char>(value[index + 2]) == 0xA9) )
    {
      escaped += static_cast<unsigned char>(value[index + 2]) == 0xA8
          ? "\\u2028" : "\\u2029";
      index += 2;
      continue;
    }
    escaped.push_back(value[index]);
  }
  return escaped;
}

std::string FormatArgumentValue(const nlohmann::ordered_json &value)
{
  if ( value.is_string() )
    return EscapeSingleLine(value.get_ref<const std::string &>());
  return EscapeJsonLineSeparators(value.dump());
}

} // namespace

std::string FormatAgentToolCallTranscript(const AgentToolCall &call)
{
  std::string transcript = "Call: " + call.name + ", Arguments: ";
  const nlohmann::ordered_json arguments = nlohmann::ordered_json::parse(
      call.arguments_json, nullptr, false);
  if ( !arguments.is_object() )
    return transcript + "(invalid)";
  if ( arguments.empty() )
    return transcript + "(none)";

  bool first = true;
  for ( auto argument = arguments.cbegin(); argument != arguments.cend(); ++argument )
  {
    if ( !first ) transcript += ", ";
    transcript += EscapeSingleLine(argument.key())
        + "=" + FormatArgumentValue(*argument);
    first = false;
  }
  return transcript;
}

std::string FormatAgentToolResultTranscript(const AgentToolResult &result)
{
  return "Result: " + result.name
      + " - " + (result.success ? "success" : "failed");
}

} // namespace ida_agent::ai
