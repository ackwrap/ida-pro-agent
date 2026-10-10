#include "ai/provider_chat.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <limits>
#include <string_view>

namespace ida_agent::ai
{
namespace
{

using Json = nlohmann::json;

ProviderChatDecodeResult TerminalError(std::string_view message)
{
  ProviderChatDecodeResult result;
  result.completed = true;
  result.error = true;
  result.safe_message = message;
  return result;
}

ProviderChatDecodeResult ProtocolError()
{
  return TerminalError(ProviderChatProtocolErrorMessage);
}

ProviderChatDecodeResult ProviderError()
{
  return TerminalError(ProviderChatProviderErrorMessage);
}

bool ReadIndex(const Json &object, const char *field, std::size_t &result)
{
  if ( !object.contains(field) || !object.at(field).is_number_integer() )
    return false;
  try
  {
    if ( object.at(field).is_number_unsigned() )
    {
      const std::uint64_t value = object.at(field).get<std::uint64_t>();
      if ( value > (std::numeric_limits<std::size_t>::max)() )
        return false;
      result = static_cast<std::size_t>(value);
      return true;
    }
    const std::int64_t value = object.at(field).get<std::int64_t>();
    if ( value < 0 )
      return false;
    result = static_cast<std::size_t>(value);
    return true;
  }
  catch ( const Json::exception & )
  {
    return false;
  }
}

bool ReadOptionalString(
    const Json &object,
    const char *field,
    std::optional<std::string> &result)
{
  if ( !object.contains(field) )
    return true;
  if ( !object.at(field).is_string() )
    return false;
  result = object.at(field).get<std::string>();
  return true;
}

ProviderChatDecodeResult DecodeResponses(const Json &document)
{
  if ( !document.is_object()
      || !document.contains("type")
      || !document.at("type").is_string() )
  {
    return ProtocolError();
  }
  const std::string type = document.at("type").get<std::string>();
  if ( type == "response.output_text.delta" )
  {
    if ( !document.contains("delta") || !document.at("delta").is_string() )
      return ProtocolError();
    ProviderChatDecodeResult result;
    result.text_delta = document.at("delta").get<std::string>();
    return result;
  }
  if ( type == "response.reasoning_summary_text.delta" )
  {
    if ( !document.contains("delta") || !document.at("delta").is_string() )
      return ProtocolError();
    ProviderChatDecodeResult result;
    result.reasoning_delta = document.at("delta").get<std::string>();
    return result;
  }
  if ( type == "response.function_call_arguments.delta" )
  {
    ProviderToolCallUpdate update;
    if ( !ReadIndex(document, "output_index", update.index)
        || !document.contains("delta") || !document.at("delta").is_string() )
    {
      return ProtocolError();
    }
    update.arguments_delta = document.at("delta").get<std::string>();
    ProviderChatDecodeResult result;
    result.updates.push_back(std::move(update));
    return result;
  }
  if ( type == "response.completed" )
  {
    ProviderChatDecodeResult result;
    result.completed = true;
    return result;
  }
  if ( type == "response.failed"
      || type == "response.incomplete"
      || type == "error" )
  {
    return ProviderError();
  }
  if ( type == "response.output_item.added"
      || type == "response.output_item.done" )
  {
    if ( !document.contains("item")
        || !document.at("item").is_object()
        || !document.at("item").contains("type")
        || !document.at("item").at("type").is_string() )
    {
      return ProtocolError();
    }
    const Json &item = document.at("item");
    if ( item.at("type").get<std::string>() != "function_call" )
      return {};
    ProviderToolCallUpdate update;
    if ( !ReadIndex(document, "output_index", update.index)
        || !ReadOptionalString(item, "call_id", update.id_snapshot)
        || !ReadOptionalString(item, "name", update.name_snapshot)
        || !ReadOptionalString(item, "arguments", update.arguments_snapshot)
        || !update.id_snapshot.has_value() || !update.name_snapshot.has_value()
        || !update.arguments_snapshot.has_value() )
    {
      return ProtocolError();
    }
    update.done = type == "response.output_item.done";
    update.initialize = type == "response.output_item.added";
    ProviderChatDecodeResult result;
    result.updates.push_back(std::move(update));
    return result;
  }
  return {};
}

bool DecodeChatToolCall(
    const Json &encoded,
    ProviderToolCallUpdate &update)
{
  if ( !encoded.is_object() || !ReadIndex(encoded, "index", update.index) )
    return false;
  if ( encoded.contains("type")
      && (!encoded.at("type").is_string()
          || encoded.at("type").get<std::string>() != "function") )
  {
    return false;
  }
  update.initialize = encoded.contains("type");
  if ( !ReadOptionalString(encoded, "id", update.id_delta) )
    return false;
  if ( !encoded.contains("function") )
    return true;
  if ( !encoded.at("function").is_object() )
    return false;
  const Json &function = encoded.at("function");
  return ReadOptionalString(function, "name", update.name_delta)
      && ReadOptionalString(function, "arguments", update.arguments_delta);
}

bool DecodeDeprecatedFunctionCall(
    const Json &encoded,
    ProviderToolCallUpdate &update)
{
  if ( !encoded.is_object() )
    return false;
  update.index = 0;
  return ReadOptionalString(encoded, "name", update.name_delta)
      && ReadOptionalString(encoded, "arguments", update.arguments_delta);
}

ProviderChatDecodeResult DecodeChatCompletions(const Json &document)
{
  if ( !document.is_object() )
    return ProtocolError();
  if ( document.contains("error") )
  {
    return document.at("error").is_object()
        ? ProviderError()
        : ProtocolError();
  }
  if ( !document.contains("choices") || !document.at("choices").is_array() )
    return ProtocolError();

  ProviderChatDecodeResult result;
  for ( const Json &choice : document.at("choices") )
  {
    if ( !choice.is_object() )
      return ProtocolError();
    if ( choice.contains("delta") )
    {
      const Json &delta = choice.at("delta");
      if ( !delta.is_object() )
        return ProtocolError();
      if ( delta.contains("content") && !delta.at("content").is_null() )
      {
        if ( !delta.at("content").is_string() )
          return ProtocolError();
        result.text_delta += delta.at("content").get<std::string>();
      }
      if ( delta.contains("reasoning_content")
          && !delta.at("reasoning_content").is_null() )
      {
        if ( !delta.at("reasoning_content").is_string() )
          return ProtocolError();
        result.reasoning_delta +=
            delta.at("reasoning_content").get<std::string>();
      }
      if ( delta.contains("tool_calls") )
      {
        if ( !delta.at("tool_calls").is_array() )
          return ProtocolError();
        for ( const Json &encoded : delta.at("tool_calls") )
        {
          ProviderToolCallUpdate update;
          if ( !DecodeChatToolCall(encoded, update) )
            return ProtocolError();
          result.updates.push_back(std::move(update));
        }
      }
      if ( delta.contains("function_call") )
      {
        ProviderToolCallUpdate update;
        if ( !DecodeDeprecatedFunctionCall(delta.at("function_call"), update) )
          return ProtocolError();
        result.updates.push_back(std::move(update));
      }
    }
    if ( choice.contains("finish_reason")
        && !choice.at("finish_reason").is_null() )
    {
      if ( !choice.at("finish_reason").is_string() )
        return ProtocolError();
      result.completed = true;
    }
  }
  return result;
}

ProviderChatDecodeResult DecodeClaude(const Json &document)
{
  if ( !document.is_object()
      || !document.contains("type")
      || !document.at("type").is_string() )
  {
    return ProtocolError();
  }
  const std::string type = document.at("type").get<std::string>();
  if ( type == "content_block_delta" )
  {
    if ( !document.contains("delta")
        || !document.at("delta").is_object()
        || !document.at("delta").contains("type")
        || !document.at("delta").at("type").is_string() )
    {
      return ProtocolError();
    }
    const Json &delta = document.at("delta");
    const std::string delta_type = delta.at("type").get<std::string>();
    if ( delta_type == "text_delta" )
    {
      if ( !delta.contains("text") || !delta.at("text").is_string() )
        return ProtocolError();
      ProviderChatDecodeResult result;
      result.text_delta = delta.at("text").get<std::string>();
      return result;
    }
    if ( delta_type == "thinking_delta" )
    {
      if ( !delta.contains("thinking") || !delta.at("thinking").is_string() )
        return ProtocolError();
      ProviderChatDecodeResult result;
      result.reasoning_delta = delta.at("thinking").get<std::string>();
      return result;
    }
    if ( delta_type == "input_json_delta" )
    {
      ProviderToolCallUpdate update;
      if ( !ReadIndex(document, "index", update.index)
          || !delta.contains("partial_json")
          || !delta.at("partial_json").is_string() )
      {
        return ProtocolError();
      }
      update.arguments_delta = delta.at("partial_json").get<std::string>();
      ProviderChatDecodeResult result;
      result.updates.push_back(std::move(update));
      return result;
    }
    return {};
  }
  if ( type == "content_block_start" )
  {
    if ( !document.contains("content_block")
        || !document.at("content_block").is_object()
        || !document.at("content_block").contains("type")
        || !document.at("content_block").at("type").is_string() )
    {
      return ProtocolError();
    }
    const Json &block = document.at("content_block");
    if ( block.at("type").get<std::string>() != "tool_use" )
      return {};
    ProviderToolCallUpdate update;
    if ( !ReadIndex(document, "index", update.index)
        || !ReadOptionalString(block, "id", update.id_snapshot)
        || !ReadOptionalString(block, "name", update.name_snapshot)
        || !update.id_snapshot.has_value() || !update.name_snapshot.has_value() )
    {
      return ProtocolError();
    }
    if ( block.contains("input") )
    {
      if ( !block.at("input").is_object() )
        return ProtocolError();
      if ( !block.at("input").empty() )
        update.arguments_snapshot = block.at("input").dump();
      else
        update.empty_object_start = true;
    }
    update.initialize = true;
    ProviderChatDecodeResult result;
    result.updates.push_back(std::move(update));
    return result;
  }
  if ( type == "content_block_stop" )
  {
    ProviderToolCallUpdate update;
    if ( !ReadIndex(document, "index", update.index) )
      return ProtocolError();
    update.done = true;
    ProviderChatDecodeResult result;
    result.updates.push_back(std::move(update));
    return result;
  }
  if ( type == "message_delta" )
  {
    if ( document.contains("delta") )
    {
      if ( !document.at("delta").is_object() )
        return ProtocolError();
      const Json &delta = document.at("delta");
      if ( delta.contains("stop_reason")
          && !delta.at("stop_reason").is_null()
          && !delta.at("stop_reason").is_string() )
      {
        return ProtocolError();
      }
    }
    return {};
  }
  if ( type == "message_stop" )
  {
    ProviderChatDecodeResult result;
    result.completed = true;
    return result;
  }
  if ( type == "error" )
  {
    if ( document.contains("error") && !document.at("error").is_object() )
      return ProtocolError();
    return ProviderError();
  }
  return {};
}

} // namespace

ProviderChatDecodeResult DecodeProviderChatEvent(
    ProviderChatCodec codec,
    const SseEvent &event)
{
  if ( codec == ProviderChatCodec::OpenAIChatCompletions
      && event.data == "[DONE]" )
  {
    ProviderChatDecodeResult result;
    result.completed = true;
    return result;
  }

  const Json document = Json::parse(event.data, nullptr, false);
  if ( document.is_discarded() )
    return ProtocolError();
  switch ( codec )
  {
    case ProviderChatCodec::OpenAIResponses:
      return DecodeResponses(document);
    case ProviderChatCodec::OpenAIChatCompletions:
      return DecodeChatCompletions(document);
    case ProviderChatCodec::ClaudeMessages:
      return DecodeClaude(document);
  }
  return ProtocolError();
}

} // namespace ida_agent::ai
