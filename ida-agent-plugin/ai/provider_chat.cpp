#include "ai/provider_chat.hpp"

#include "ai/provider_request.hpp"
#include "ai/provider_chat_wire.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <optional>
#include <unordered_set>
#include <utility>

namespace ida_agent::ai
{
namespace
{

using Json = nlohmann::json;
using provider_chat_detail::EstimateTextTokens;
static_assert(MaxAgentFileToolArgumentsBytes < MaxProviderAgentFixedPayloadBytes);
static_assert(MaxAgentFileToolResultBytes < MaxProviderAgentResultBytes);

ProviderChatBuildResult ConfigurationError()
{
  ProviderChatBuildResult result;
  result.error = true;
  result.safe_message = ProviderChatConfigurationErrorMessage;
  return result;
}

std::uint64_t EstimateMessageTokens(const ProviderChatMessage &message)
{
  return EstimateTextTokens(message.text);
}

std::size_t JsonStringBytes(std::string_view value)
{
  std::size_t bytes = 2;
  for ( unsigned char character : value )
  {
    const std::size_t addition = character < 0x20
        ? 6
        : character == '"' || character == '\\' ? 2 : 1;
    if ( addition > MaxProviderJsonStringBytes - (std::min)(
            bytes, MaxProviderJsonStringBytes) )
    {
      return MaxProviderJsonStringBytes + 1;
    }
    bytes += addition;
  }
  return bytes;
}

bool AddAgentFixedPayloadBytes(std::size_t &total, std::size_t addition)
{
  if ( addition > MaxProviderAgentFixedPayloadBytes - (std::min)(
          total, MaxProviderAgentFixedPayloadBytes) )
  {
    return false;
  }
  total += addition;
  return true;
}

const char *RoleName(ProviderChatRole role)
{
  return role == ProviderChatRole::User ? "user" : "assistant";
}

std::optional<ProviderProfileDraft> NormalizeAndValidateProfile(
    const ProviderProfileDraft &profile)
{
  ProviderManagerDraft manager;
  manager.profiles.push_back(profile);
  manager.active_profile_id = profile.id;
  NormalizeProviderManagerDraft(manager);
  if ( !IsValidManagerDraft(manager) )
    return std::nullopt;
  return std::move(manager.profiles.front());
}

const ProviderModelDraft *FindSelectedModel(const ProviderProfileDraft &profile)
{
  const auto found = std::find_if(
      profile.models.begin(), profile.models.end(),
      [&profile](const ProviderModelDraft &model)
      {
        return model.enabled && model.id == profile.settings.model;
      });
  return found == profile.models.end() ? nullptr : &*found;
}

std::vector<ProviderChatMessage> CropMessages(
    const std::vector<ProviderChatMessage> &history,
    std::uint64_t budget,
    std::size_t fixed_body_bytes,
    std::size_t fixed_message_items,
    std::uint64_t &estimated_tokens)
{
  estimated_tokens = 0;
  std::vector<ProviderChatMessage> eligible;
  eligible.reserve(history.size());
  for ( const ProviderChatMessage &message : history )
  {
    if ( !message.text.empty() )
      eligible.push_back(message);
  }

  std::optional<std::size_t> last_user;
  for ( std::size_t index = eligible.size(); index != 0; --index )
  {
    if ( eligible[index - 1].role == ProviderChatRole::User )
    {
      last_user = index - 1;
      break;
    }
  }
  if ( !last_user.has_value() )
    return {};

  std::vector<bool> included(eligible.size(), false);
  included[*last_user] = true;
  const std::uint64_t last_user_tokens = EstimateMessageTokens(eligible[*last_user]);
  estimated_tokens = last_user_tokens;
  if ( last_user_tokens > budget )
    return {};
  std::uint64_t used = last_user_tokens;
  std::uint64_t remaining = budget - used;

  for ( std::size_t index = eligible.size(); index != 0; --index )
  {
    const std::size_t current = index - 1;
    if ( current == *last_user )
      continue;
    const std::uint64_t tokens = EstimateMessageTokens(eligible[current]);
    if ( tokens > remaining )
      break;
    included[current] = true;
    used += tokens;
    remaining -= tokens;
  }

  std::vector<ProviderChatMessage> cropped;
  for ( std::size_t index = 0; index < eligible.size(); ++index )
  {
    if ( included[index] )
      cropped.push_back(std::move(eligible[index]));
  }
  while ( !cropped.empty()
      && cropped.front().role == ProviderChatRole::Assistant )
  {
    used -= EstimateMessageTokens(cropped.front());
    cropped.erase(cropped.begin());
  }

  std::vector<std::size_t> wire_bytes;
  wire_bytes.reserve(cropped.size());
  std::size_t wire_sum = 0;
  for ( const ProviderChatMessage &message : cropped )
  {
    const std::size_t bytes = Json{
        {"role", RoleName(message.role)},
        {"content", message.text},
    }.dump().size();
    wire_bytes.push_back(bytes);
    wire_sum += bytes;
  }

  const auto body_bytes = [fixed_body_bytes, fixed_message_items](
      std::size_t message_bytes, std::size_t message_count)
  {
    const std::size_t separators = message_count == 0 ? 0
        : fixed_message_items == 0 ? message_count - 1 : message_count;
    if ( fixed_body_bytes > MaxProviderRequestBodyBytes
        || message_bytes > MaxProviderRequestBodyBytes - fixed_body_bytes
        || separators > MaxProviderRequestBodyBytes
            - fixed_body_bytes - message_bytes )
    {
      return MaxProviderRequestBodyBytes + 1;
    }
    return fixed_body_bytes + message_bytes + separators;
  };

  const auto latest = std::find_if(
      cropped.rbegin(), cropped.rend(),
      [](const ProviderChatMessage &message)
      {
        return message.role == ProviderChatRole::User;
      });
  if ( latest == cropped.rend() )
    return {};
  const std::size_t latest_index = static_cast<std::size_t>(
      std::distance(cropped.begin(), latest.base()) - 1);
  const std::uint64_t latest_tokens = EstimateMessageTokens(cropped[latest_index]);
  if ( body_bytes(wire_bytes[latest_index], 1) > MaxProviderRequestBodyBytes )
  {
    estimated_tokens = latest_tokens;
    return {};
  }

  std::size_t first = 0;
  while ( body_bytes(wire_sum, cropped.size() - first)
          > MaxProviderRequestBodyBytes
      && first < latest_index )
  {
    wire_sum -= wire_bytes[first];
    used -= EstimateMessageTokens(cropped[first]);
    ++first;
    while ( first < latest_index
        && cropped[first].role == ProviderChatRole::Assistant )
    {
      wire_sum -= wire_bytes[first];
      used -= EstimateMessageTokens(cropped[first]);
      ++first;
    }
  }
  if ( body_bytes(wire_sum, cropped.size() - first)
      > MaxProviderRequestBodyBytes )
  {
    ProviderChatMessage latest_user = std::move(cropped[latest_index]);
    cropped.clear();
    cropped.push_back(std::move(latest_user));
    estimated_tokens = latest_tokens;
    return cropped;
  }
  if ( first != 0 )
    cropped.erase(cropped.begin(), cropped.begin() + first);
  estimated_tokens = used;
  return cropped;
}

ProviderChatCodec SelectCodec(const ProviderSettingsDraft &settings)
{
  if ( settings.protocol == ProviderProtocol::Claude )
    return ProviderChatCodec::ClaudeMessages;
  return settings.openai_api_mode == OpenAIApiMode::ChatCompletions
      ? ProviderChatCodec::OpenAIChatCompletions
      : ProviderChatCodec::OpenAIResponses;
}

bool ParseArgumentsObject(
    std::string_view name,
    const std::string &arguments,
    Json &parsed)
{
  const std::size_t limit = name == "ida_file_mutate"
      ? MaxAgentFileToolArgumentsBytes : MaxAgentToolArgumentsBytes;
  if ( arguments.empty() || arguments.size() > limit )
    return false;
  parsed = Json::parse(arguments, nullptr, false);
  return !parsed.is_discarded() && parsed.is_object();
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

bool ValidateAgentOptions(
    const ProviderChatAgentOptions &options,
    std::uint64_t &estimated_tokens)
{
  estimated_tokens = 0;
  if ( options.system_prompt.size() > MaxProviderSystemPromptBytes )
  {
    return false;
  }
  if ( !options.system_prompt.empty() )
    estimated_tokens += EstimateTextTokens(options.system_prompt);

  std::size_t schema_bytes = 0;
  std::size_t payload_bytes = 256;
  if ( !AddAgentFixedPayloadBytes(
          payload_bytes, JsonStringBytes(options.system_prompt)) )
    return false;
  std::unordered_set<std::string> tool_names;
  try
  {
    for ( const AgentToolDefinition &tool : options.tools )
    {
      if ( tool.name.empty() || tool.name.size() > MaxAgentToolNameBytes
          || !tool.parameters.is_object()
          || !tool_names.insert(tool.name).second )
      {
        return false;
      }
      const std::string schema = tool.parameters.dump();
      if ( schema.size() > MaxProviderToolSchemaBytes -
              (std::min)(schema_bytes, MaxProviderToolSchemaBytes) )
      {
        return false;
      }
      schema_bytes += schema.size();
      if ( !AddAgentFixedPayloadBytes(payload_bytes, 128)
          || !AddAgentFixedPayloadBytes(
              payload_bytes, JsonStringBytes(tool.name))
          || !AddAgentFixedPayloadBytes(
              payload_bytes, JsonStringBytes(tool.description))
          || !AddAgentFixedPayloadBytes(payload_bytes, schema.size()) )
      {
        return false;
      }
      estimated_tokens += EstimateTextTokens(
          {tool.name, tool.description, schema});
    }
  }
  catch ( const Json::exception & )
  {
    return false;
  }

  std::size_t result_bytes = 0;
  std::unordered_set<std::string> call_ids;
  for ( const ProviderAgentExchange &exchange : options.exchanges )
  {
    if ( exchange.calls.empty()
        || exchange.calls.size() != exchange.results.size() )
    {
      return false;
    }
    if ( !AddAgentFixedPayloadBytes(payload_bytes, 128)
        || !AddAgentFixedPayloadBytes(
            payload_bytes, JsonStringBytes(exchange.assistant_text)) )
    {
      return false;
    }
    if ( !exchange.assistant_text.empty() )
      estimated_tokens += EstimateTextTokens(exchange.assistant_text);

    std::unordered_set<std::string> result_ids;
    for ( const AgentToolResult &result : exchange.results )
    {
      if ( result.call_id.empty() || !result_ids.insert(result.call_id).second )
        return false;
    }
    for ( const AgentToolCall &call : exchange.calls )
    {
      Json parsed;
      if ( call.id.empty() || call.id.size() > MaxAgentToolCallIdBytes
          || call.name.empty() || call.name.size() > MaxAgentToolNameBytes
          || tool_names.find(call.name) == tool_names.end()
          || !call_ids.insert(call.id).second
          || !ParseArgumentsObject(call.name, call.arguments_json, parsed) )
      {
        return false;
      }
      const AgentToolResult *result = FindResult(exchange, call);
      const std::size_t result_limit = call.name == "ida_file_read"
          ? MaxAgentFileToolResultBytes : MaxAgentToolResultBytes;
      if ( result == nullptr || result->name != call.name
          || result->output.size() > result_limit
          || result->safe_message.size() > result_limit
          || (!result->success
              && result->safe_message.empty()) )
      {
        return false;
      }
      const std::optional<std::size_t> current_result_bytes =
          AgentToolResultContentBytes(*result);
      if ( !current_result_bytes.has_value()
          || result_bytes > MaxProviderAgentResultBytes
          || *current_result_bytes > MaxProviderAgentResultBytes - result_bytes )
      {
        return false;
      }
      result_bytes += *current_result_bytes;
      if ( !AddAgentFixedPayloadBytes(payload_bytes, 256)
          || !AddAgentFixedPayloadBytes(
              payload_bytes, JsonStringBytes(call.id))
          || !AddAgentFixedPayloadBytes(
              payload_bytes, JsonStringBytes(call.name))
          || !AddAgentFixedPayloadBytes(
              payload_bytes, JsonStringBytes(call.arguments_json))
          || !AddAgentFixedPayloadBytes(
              payload_bytes,
              JsonStringBytes(result->success
                  ? std::string_view(result->output)
                  : std::string_view(result->safe_message))) )
      {
        return false;
      }
      estimated_tokens += EstimateTextTokens(
          {call.id, call.name, call.arguments_json});
      estimated_tokens += EstimateTextTokens(
          result->success ? std::string_view(result->output)
                          : std::string_view(result->safe_message));
    }
  }
  return true;
}

ProviderChatBuildResult BuildRequest(
    const ProviderProfileDraft &profile,
    const std::vector<ProviderChatMessage> &messages,
    const ProviderChatAgentOptions *agent_options)
{
  const std::optional<ProviderProfileDraft> normalized =
      NormalizeAndValidateProfile(profile);
  if ( !normalized.has_value() || normalized->settings.model.empty() )
    return ConfigurationError();
  const ProviderModelDraft *model = FindSelectedModel(*normalized);
  if ( model == nullptr )
    return ConfigurationError();
  const std::optional<ProviderRequestParts> parts =
      BuildProviderRequestParts(*normalized, true);
  if ( !parts.has_value() )
    return ConfigurationError();
  const std::optional<HttpProxyConfig> proxy = BuildHttpProxyConfig(parts->proxy);
  if ( !proxy.has_value() )
    return ConfigurationError();

  const ProviderChatAgentOptions empty_options;
  const ProviderChatAgentOptions &options = agent_options == nullptr
      ? empty_options : *agent_options;
  std::uint64_t required_tokens = 0;
  if ( !ValidateAgentOptions(options, required_tokens) )
    return ConfigurationError();

  ProviderChatBuildResult result;
  result.codec = SelectCodec(parts->settings);
  result.context_length = model->context_length;
  result.max_output_tokens = (std::min)(
      model->max_output_tokens, MaxProviderChatOutputTokens);
  result.show_reasoning =
      model->reasoning_summary != ProviderReasoningSummary::Hidden;
  const std::uint64_t reserved = static_cast<std::uint64_t>(result.max_output_tokens)
      + ProviderChatReservedTokens;
  result.input_token_budget = result.context_length > reserved
      ? static_cast<std::uint64_t>(result.context_length) - reserved
      : 0;
  if ( required_tokens > result.input_token_budget )
    return ConfigurationError();
  std::size_t fixed_body_bytes = 0;
  try
  {
    fixed_body_bytes = provider_chat_wire::BuildRequestBody(
        result.codec, parts->settings, *model, result.max_output_tokens,
        {}, options).size();
  }
  catch ( const Json::exception & )
  {
    return ConfigurationError();
  }
  std::uint64_t transcript_tokens = 0;
  try
  {
    result.messages = CropMessages(
        messages, result.input_token_budget - required_tokens,
        fixed_body_bytes,
        provider_chat_wire::FixedMessageItemCount(result.codec, options),
        transcript_tokens);
  }
  catch ( const Json::exception & )
  {
    return ConfigurationError();
  }
  result.estimated_input_tokens = required_tokens + transcript_tokens;
  const bool has_user = std::any_of(
      result.messages.begin(), result.messages.end(),
      [](const ProviderChatMessage &message)
      {
        return message.role == ProviderChatRole::User;
      });
  if ( !has_user )
  {
    result.error = true;
    result.safe_message = ProviderChatConfigurationErrorMessage;
    result.request = {};
    return result;
  }

  try
  {
    result.request.body = provider_chat_wire::BuildRequestBody(
        result.codec, parts->settings, *model, result.max_output_tokens,
        result.messages, options);
    if ( result.codec == ProviderChatCodec::OpenAIResponses )
    {
      result.request.url = parts->settings.base_url + "/responses";
    }
    else if ( result.codec == ProviderChatCodec::OpenAIChatCompletions )
    {
      result.request.url = parts->settings.base_url + "/chat/completions";
    }
    else
    {
      result.request.url = parts->settings.base_url + "/messages";
    }
  }
  catch ( const Json::exception & )
  {
    return ConfigurationError();
  }

  if ( result.request.body.size() > MaxProviderRequestBodyBytes )
    return ConfigurationError();
  result.request.method = HttpMethod::Post;
  result.request.user_agent = parts->user_agent;
  result.request.proxy = *proxy;
  result.request.headers.reserve(parts->headers.size());
  for ( const ProviderHeaderDraft &header : parts->headers )
    result.request.headers.push_back(HttpHeader{header.name, header.value});
  return result;
}

} // namespace

ProviderChatBuildResult BuildProviderChatRequest(
    const ProviderProfileDraft &profile,
    const std::vector<ProviderChatMessage> &messages)
{
  return BuildRequest(profile, messages, nullptr);
}

ProviderChatBuildResult BuildProviderAgentRequest(
    const ProviderProfileDraft &profile,
    const std::vector<ProviderChatMessage> &transcript_messages,
    const ProviderChatAgentOptions &options)
{
  return BuildRequest(profile, transcript_messages, &options);
}

} // namespace ida_agent::ai
