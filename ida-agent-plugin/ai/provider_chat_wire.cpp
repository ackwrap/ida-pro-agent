#include "ai/provider_chat_wire.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <utility>

namespace ida_agent::ai::provider_chat_wire
{
namespace
{

using Json = nlohmann::json;

const char *RoleName(ProviderChatRole role)
{
  return role == ProviderChatRole::User ? "user" : "assistant";
}

Json BuildMessagesJson(const std::vector<ProviderChatMessage> &messages)
{
  Json result = Json::array();
  for ( const ProviderChatMessage &message : messages )
  {
    result.push_back({
        {"role", RoleName(message.role)},
        {"content", message.text},
    });
  }
  return result;
}

const AgentToolResult *FindResult(
    const ProviderAgentExchange &exchange,
    const AgentToolCall &call)
{
  const auto found = std::find_if(
      exchange.results.begin(), exchange.results.end(),
      [&call](const AgentToolResult &result)
      {
        return result.call_id == call.id;
      });
  return found == exchange.results.end() ? nullptr : &*found;
}

std::string OpenAIResultContent(const AgentToolResult &result)
{
  if ( result.success )
    return result.output;
  return Json{{"error", result.safe_message}}.dump();
}

Json BuildResponsesInput(
    const std::vector<ProviderChatMessage> &messages,
    const ProviderChatAgentOptions &options)
{
  Json input = BuildMessagesJson(messages);
  for ( const ProviderAgentExchange &exchange : options.exchanges )
  {
    if ( !exchange.assistant_text.empty() )
    {
      input.push_back({
          {"role", "assistant"},
          {"content", exchange.assistant_text},
      });
    }
    for ( const AgentToolCall &call : exchange.calls )
    {
      input.push_back({
          {"type", "function_call"},
          {"call_id", call.id},
          {"name", call.name},
          {"arguments", call.arguments_json},
      });
    }
    for ( const AgentToolCall &call : exchange.calls )
    {
      input.push_back({
          {"type", "function_call_output"},
          {"call_id", call.id},
          {"output", OpenAIResultContent(*FindResult(exchange, call))},
      });
    }
  }
  return input;
}

Json BuildChatMessages(
    const std::vector<ProviderChatMessage> &messages,
    const ProviderChatAgentOptions &options)
{
  Json result = Json::array();
  if ( !options.system_prompt.empty() )
    result.push_back({{"role", "system"}, {"content", options.system_prompt}});
  for ( const ProviderChatMessage &message : messages )
  {
    result.push_back({
        {"role", RoleName(message.role)},
        {"content", message.text},
    });
  }
  for ( const ProviderAgentExchange &exchange : options.exchanges )
  {
    Json calls = Json::array();
    for ( const AgentToolCall &call : exchange.calls )
    {
      calls.push_back({
          {"id", call.id},
          {"type", "function"},
          {"function", {{"name", call.name}, {"arguments", call.arguments_json}}},
      });
    }
    result.push_back({
        {"role", "assistant"},
        {"content", exchange.assistant_text.empty()
            ? Json(nullptr) : Json(exchange.assistant_text)},
        {"tool_calls", std::move(calls)},
    });
    for ( const AgentToolCall &call : exchange.calls )
    {
      const AgentToolResult &tool_result = *FindResult(exchange, call);
      result.push_back({
          {"role", "tool"},
          {"tool_call_id", call.id},
          {"content", OpenAIResultContent(tool_result)},
      });
    }
  }
  return result;
}

Json BuildClaudeMessages(
    const std::vector<ProviderChatMessage> &messages,
    const ProviderChatAgentOptions &options)
{
  Json result = BuildMessagesJson(messages);
  for ( const ProviderAgentExchange &exchange : options.exchanges )
  {
    Json assistant = Json::array();
    if ( !exchange.assistant_text.empty() )
      assistant.push_back({{"type", "text"}, {"text", exchange.assistant_text}});
    for ( const AgentToolCall &call : exchange.calls )
    {
      assistant.push_back({
          {"type", "tool_use"},
          {"id", call.id},
          {"name", call.name},
          {"input", Json::parse(call.arguments_json)},
      });
    }
    result.push_back({{"role", "assistant"}, {"content", std::move(assistant)}});

    Json outputs = Json::array();
    for ( const AgentToolCall &call : exchange.calls )
    {
      const AgentToolResult &tool_result = *FindResult(exchange, call);
      Json block{
          {"type", "tool_result"},
          {"tool_use_id", call.id},
          {"content", tool_result.success
              ? tool_result.output : tool_result.safe_message},
      };
      if ( !tool_result.success )
        block["is_error"] = true;
      outputs.push_back(std::move(block));
    }
    result.push_back({{"role", "user"}, {"content", std::move(outputs)}});
  }
  return result;
}

Json BuildOpenAITools(const std::vector<AgentToolDefinition> &tools, bool responses)
{
  Json result = Json::array();
  for ( const AgentToolDefinition &tool : tools )
  {
    Json function{
        {"name", tool.name},
        {"description", tool.description},
        {"parameters", tool.parameters},
        {"strict", true},
    };
    if ( responses )
    {
      function["type"] = "function";
      result.push_back(std::move(function));
    }
    else
    {
      result.push_back({{"type", "function"}, {"function", std::move(function)}});
    }
  }
  return result;
}

Json BuildClaudeTools(const std::vector<AgentToolDefinition> &tools)
{
  Json result = Json::array();
  for ( const AgentToolDefinition &tool : tools )
  {
    result.push_back({
        {"name", tool.name},
        {"description", tool.description},
        {"input_schema", tool.parameters},
    });
  }
  return result;
}

} // namespace

std::string BuildRequestBody(
    ProviderChatCodec codec,
    const ProviderSettingsDraft &settings,
    const ProviderModelDraft &model,
    std::uint32_t max_output_tokens,
    const std::vector<ProviderChatMessage> &messages,
    const ProviderChatAgentOptions &options)
{
  Json body;
  body["model"] = settings.model;
  body["stream"] = true;
  if ( codec == ProviderChatCodec::OpenAIResponses )
  {
    body["input"] = BuildResponsesInput(messages, options);
    body["max_output_tokens"] = max_output_tokens;
    body["store"] = false;
    if ( !options.system_prompt.empty() )
      body["instructions"] = options.system_prompt;
    if ( !options.tools.empty() )
      body["tools"] = BuildOpenAITools(options.tools, true);
    if ( model.reasoning_effort != ProviderReasoningEffort::Default )
    {
      body["reasoning"]["effort"] =
          ProviderReasoningEffortName(model.reasoning_effort);
    }
    if ( model.reasoning_summary != ProviderReasoningSummary::Hidden
        && model.reasoning_summary != ProviderReasoningSummary::Visible )
    {
      body["reasoning"]["summary"] =
          ProviderReasoningSummaryName(model.reasoning_summary);
    }
  }
  else if ( codec == ProviderChatCodec::OpenAIChatCompletions )
  {
    body["messages"] = BuildChatMessages(messages, options);
    body["max_completion_tokens"] = max_output_tokens;
    if ( model.reasoning_effort != ProviderReasoningEffort::Default )
    {
      body["reasoning_effort"] =
          ProviderReasoningEffortName(model.reasoning_effort);
    }
    if ( !options.tools.empty() )
      body["tools"] = BuildOpenAITools(options.tools, false);
  }
  else
  {
    body["messages"] = BuildClaudeMessages(messages, options);
    body["max_tokens"] = max_output_tokens;
    if ( !options.system_prompt.empty() )
      body["system"] = options.system_prompt;
    if ( !options.tools.empty() )
      body["tools"] = BuildClaudeTools(options.tools);
  }
  if ( !options.tools.empty() && codec != ProviderChatCodec::ClaudeMessages )
  {
    body["tool_choice"] = "auto";
    body["parallel_tool_calls"] = false;
  }
  return body.dump();
}

std::size_t FixedMessageItemCount(
    ProviderChatCodec codec,
    const ProviderChatAgentOptions &options)
{
  std::size_t count = codec == ProviderChatCodec::OpenAIChatCompletions
          && !options.system_prompt.empty()
      ? 1 : 0;
  for ( const ProviderAgentExchange &exchange : options.exchanges )
  {
    if ( codec == ProviderChatCodec::OpenAIResponses )
    {
      count += (exchange.assistant_text.empty() ? 0 : 1)
          + exchange.calls.size() * 2;
    }
    else if ( codec == ProviderChatCodec::OpenAIChatCompletions )
    {
      count += 1 + exchange.calls.size();
    }
    else
    {
      count += 2;
    }
  }
  return count;
}

} // namespace ida_agent::ai::provider_chat_wire
