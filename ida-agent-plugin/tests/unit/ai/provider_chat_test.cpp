#include "ai/provider_chat.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace
{

using namespace ida_agent::ai;
using Json = nlohmann::json;

void Require(bool condition, const char *message)
{
  if ( !condition )
    throw std::runtime_error(message);
}

std::string LowerAscii(std::string value)
{
  std::transform(
      value.begin(), value.end(), value.begin(),
      [](unsigned char character)
      {
        return character >= 'A' && character <= 'Z'
            ? static_cast<char>(character - 'A' + 'a')
            : static_cast<char>(character);
      });
  return value;
}

const HttpHeader *FindHeader(
    const StreamRequest &request,
    std::string_view lowered_name)
{
  const auto found = std::find_if(
      request.headers.begin(), request.headers.end(),
      [lowered_name](const HttpHeader &header)
      {
        return LowerAscii(header.name) == lowered_name;
      });
  return found == request.headers.end() ? nullptr : &*found;
}

ProviderProfileDraft MakeProfile(
    ProviderProtocol protocol,
    OpenAIApiMode mode = OpenAIApiMode::Responses)
{
  ProviderProfileDraft profile;
  profile.id = "provider-chat-test";
  profile.settings = DraftForPreset(
      protocol == ProviderProtocol::Claude
          ? ProviderPreset::Claude
          : ProviderPreset::OpenAI);
  profile.settings.protocol = protocol;
  profile.settings.openai_api_mode = mode;
  profile.settings.model = "chat-model";
  profile.settings.api_key = "profile-secret-key";
  profile.models.push_back(
      ProviderModelDraft{"chat-model", true, "", 200000, 10000});
  return profile;
}

ProviderChatDecodeResult Decode(
    ProviderChatCodec codec,
    std::string data)
{
  SseEvent event;
  event.data = std::move(data);
  return DecodeProviderChatEvent(codec, event);
}

ProviderChatAgentOptions AgentOptions()
{
  ProviderChatAgentOptions options;
  options.system_prompt = "trusted system";
  options.tools.push_back({
      "lookup", "Lookup a symbol.",
      {{"type", "object"},
       {"additionalProperties", false},
       {"properties", {{"name", {{"type", "string"}}}}},
       {"required", Json::array({"name"})}},
  });
  ProviderAgentExchange exchange;
  exchange.assistant_text = "Checking.";
  exchange.calls.push_back({"call-1", "lookup", R"({"name":"main"})"});
  exchange.results.push_back(
      {"call-1", "lookup", true, R"({"address":"0x401000"})", {}});
  options.exchanges.push_back(std::move(exchange));
  return options;
}

void TestOpenAIResponsesRequest()
{
  ProviderProfileDraft profile = MakeProfile(ProviderProtocol::OpenAI);
  profile.settings.base_url = "  https://openai.example/v1///  ";
  profile.custom_headers = {
      {"Authorization", "Custom preferred-token", true},
      {"User-Agent", "Provider Chat Test Agent", true},
      {"X-Test", "sent", true},
  };
  profile.proxy.mode = ProviderProxyMode::Http;
  profile.proxy.host = "[2001:db8::42]";
  profile.proxy.port = 8080;
  profile.proxy.username = "proxy-user";
  profile.proxy.password = "proxy-secret";
  profile.proxy.bypass_local = false;
  profile.models.front().reasoning_effort = ProviderReasoningEffort::High;
  profile.models.front().reasoning_summary = ProviderReasoningSummary::Detailed;
  const std::vector<ProviderChatMessage> history{
      {ProviderChatRole::Assistant, "orphan"},
      {ProviderChatRole::User, "first"},
      {ProviderChatRole::Assistant, "reply"},
      {ProviderChatRole::User, "latest"},
      {ProviderChatRole::Assistant, ""},
  };
  const std::vector<ProviderChatMessage> original = history;

  const ProviderChatBuildResult result =
      BuildProviderChatRequest(profile, history);
  Require(!result.error, "OpenAI Responses request failed");
  Require(result.codec == ProviderChatCodec::OpenAIResponses, "Responses codec mismatch");
  Require(result.request.method == HttpMethod::Post, "Responses method mismatch");
  Require(result.request.url == "https://openai.example/v1/responses", "Responses path mismatch");
  Require(result.request.user_agent == "Provider Chat Test Agent", "custom UA mismatch");
  Require(
      FindHeader(result.request, "authorization") != nullptr
          && FindHeader(result.request, "authorization")->value == "Custom preferred-token",
      "custom auth did not take precedence");
  Require(
      FindHeader(result.request, "content-type") != nullptr
          && FindHeader(result.request, "content-type")->value == "application/json",
      "JSON content type missing");
  Require(FindHeader(result.request, "x-test") != nullptr, "custom header missing");
  Require(result.request.proxy.mode == HttpProxyMode::Http, "HTTP proxy mode mismatch");
  Require(result.request.proxy.host == "2001:db8::42", "proxy host mismatch");
  Require(result.request.proxy.password == "proxy-secret", "proxy password mismatch");
  Require(result.request.body.size() <= MaxProviderRequestBodyBytes, "payload limit exceeded");
  Require(result.messages.size() == 3, "history filtering mismatch");
  Require(result.messages.front().role == ProviderChatRole::User, "orphan assistant retained");
  Require(history.size() == original.size() && history.front().text == original.front().text,
          "caller history was modified");

  const Json body = Json::parse(result.request.body);
  Require(body.at("model") == "chat-model", "Responses model mismatch");
  Require(body.at("stream") == true && body.at("store") == false, "Responses flags mismatch");
  Require(body.at("max_output_tokens") == 10000, "Responses output limit mismatch");
  Require(body.at("input").size() == 3, "Responses input mismatch");
  Require(body.at("input").at(2).at("content") == "latest", "history order mismatch");
  Require(body.at("reasoning").at("effort") == "high"
              && body.at("reasoning").at("summary") == "detailed"
              && result.show_reasoning,
          "Responses reasoning configuration mismatch");
  Require(result.context_length == 200000 && result.input_token_budget == 185904,
          "Responses budget mismatch");
}

void TestOpenAIChatRequestAndCrop()
{
  ProviderProfileDraft profile = MakeProfile(
      ProviderProtocol::OpenAI,
      OpenAIApiMode::ChatCompletions);
  profile.settings.base_url = "https://chat.example/v1";
  profile.models.front().context_length = 4120;
  profile.models.front().max_output_tokens = 10;
  profile.models.front().reasoning_effort = ProviderReasoningEffort::Low;
  profile.models.front().reasoning_summary = ProviderReasoningSummary::Auto;
  const std::vector<ProviderChatMessage> history{
      {ProviderChatRole::User, "old-user"},
      {ProviderChatRole::Assistant, "old-assistant"},
      {ProviderChatRole::User, "last"},
  };
  const ProviderChatBuildResult result =
      BuildProviderChatRequest(profile, history);
  Require(!result.error, "Chat Completions request failed");
  Require(result.codec == ProviderChatCodec::OpenAIChatCompletions,
          "Chat Completions codec mismatch");
  Require(result.request.url == "https://chat.example/v1/chat/completions",
          "Chat Completions path mismatch");
  Require(result.messages.size() == 1 && result.messages.front().text == "last",
          "latest user crop guarantee failed");
  Require(result.input_token_budget == 14 && result.estimated_input_tokens == 9,
          "crop token estimate mismatch");
  const Json body = Json::parse(result.request.body);
  Require(body.at("max_completion_tokens") == 10, "completion output field mismatch");
  Require(!body.contains("store") && !body.contains("max_output_tokens"),
          "Responses-only fields leaked");
  Require(body.at("reasoning_effort") == "low"
              && !body.contains("reasoning") && result.show_reasoning,
          "Chat reasoning configuration mismatch");
  Require(
      FindHeader(result.request, "authorization")->value ==
          "Bearer profile-secret-key",
      "automatic OpenAI auth mismatch");
}

void TestBudgetBoundaryAndOutputClamp()
{
  ProviderProfileDraft profile = MakeProfile(ProviderProtocol::OpenAI);
  profile.settings.base_url = "https://budget.example/v1";
  profile.models.front().context_length = 4115;
  profile.models.front().max_output_tokens = 10;
  ProviderChatBuildResult result = BuildProviderChatRequest(
      profile,
      {{ProviderChatRole::User, "x"}});
  Require(!result.error && result.input_token_budget == 9,
          "exact last-user budget was rejected");
  Require(result.show_reasoning
              && !Json::parse(result.request.body).contains("reasoning"),
          "visible reasoning default changed the Responses request");
  Require(result.estimated_input_tokens == 9, "exact budget estimate mismatch");

  profile.models.front().context_length = 4114;
  result = BuildProviderChatRequest(
      profile,
      {{ProviderChatRole::User, "x"}});
  Require(result.error, "over-budget last user was accepted");
  Require(result.safe_message == ProviderChatConfigurationErrorMessage,
          "over-budget error was not local configuration failure");
  Require(result.request.body.empty() && result.messages.empty(),
          "over-budget request retained wire data");
  Require(result.estimated_input_tokens == 9,
          "over-budget last-user estimate was not retained");

  profile.models.front().context_length = 1'000'000;
  profile.models.front().max_output_tokens = 300'000;
  result = BuildProviderChatRequest(
      profile,
      {{ProviderChatRole::User, "clamp"}});
  Require(!result.error, "clamped output request failed");
  Require(result.max_output_tokens == MaxProviderChatOutputTokens,
          "result output token limit was not clamped");
  Require(
      result.input_token_budget
          == 1'000'000ULL - MaxProviderChatOutputTokens - ProviderChatReservedTokens,
      "clamped output budget mismatch");
  Require(Json::parse(result.request.body).at("max_output_tokens")
              == MaxProviderChatOutputTokens,
          "wire output token limit was not clamped");
}

void TestClaudeRequestAndSafeFailure()
{
  ProviderProfileDraft profile = MakeProfile(ProviderProtocol::Claude);
  profile.settings.base_url = "http://claude.example/v1";
  profile.proxy.mode = ProviderProxyMode::Direct;
  const ProviderChatBuildResult result = BuildProviderChatRequest(
      profile,
      {{ProviderChatRole::User, "hello"}});
  Require(!result.error, "Claude request failed");
  Require(result.codec == ProviderChatCodec::ClaudeMessages, "Claude codec mismatch");
  Require(result.request.url == "http://claude.example/v1/messages", "Claude path mismatch");
  Require(result.request.proxy.mode == HttpProxyMode::Direct, "direct proxy mismatch");
  Require(
      FindHeader(result.request, "x-api-key") != nullptr
          && FindHeader(result.request, "x-api-key")->value == "profile-secret-key",
      "Claude auth mismatch");
  Require(
      FindHeader(result.request, "anthropic-version") != nullptr
          && FindHeader(result.request, "anthropic-version")->value == "2023-06-01",
      "Claude version missing");
  const Json body = Json::parse(result.request.body);
  Require(body.at("max_tokens") == 10000, "Claude output field mismatch");
  Require(!body.contains("max_completion_tokens"), "OpenAI output field leaked");

  profile.models.front().enabled = false;
  const ProviderChatBuildResult failed = BuildProviderChatRequest(
      profile,
      {{ProviderChatRole::User, "hello"}});
  Require(failed.error, "disabled selected model was accepted");
  Require(failed.safe_message == ProviderChatConfigurationErrorMessage,
          "configuration safe message mismatch");
  Require(failed.safe_message.find("profile-secret-key") == std::string::npos,
          "secret leaked into safe error");

  profile.models.front().enabled = true;
  profile.models.front().context_length = 1000000000;
  profile.models.front().max_output_tokens = 1;
  const ProviderChatBuildResult oversized = BuildProviderChatRequest(
      profile,
      {{ProviderChatRole::User, std::string(MaxProviderRequestBodyBytes, 'x')}});
  Require(oversized.error && oversized.request.body.empty(),
          "oversized request payload was retained");
}

void TestAgentRequestWires()
{
  const std::vector<ProviderChatMessage> transcript{
      {ProviderChatRole::User, "inspect"},
  };
  ProviderChatAgentOptions options = AgentOptions();

  ProviderChatBuildResult result = BuildProviderAgentRequest(
      MakeProfile(ProviderProtocol::OpenAI), transcript, options);
  Require(!result.error, "Responses agent request failed");
  Json body = Json::parse(result.request.body);
  Require(body.at("instructions") == "trusted system", "Responses instructions mismatch");
  Require(body.at("tools").at(0).at("type") == "function"
              && body.at("tools").at(0).at("strict") == true,
          "Responses tools mismatch");
  Require(body.at("tool_choice") == "auto"
              && body.at("parallel_tool_calls") == false,
          "Responses tool policy mismatch");
  Require(body.at("input").at(2).at("type") == "function_call"
              && body.at("input").at(3).at("type") == "function_call_output",
          "Responses exchange wire mismatch");
  Require(body.at("store") == false, "Responses store flag lost");

  result = BuildProviderAgentRequest(
      MakeProfile(ProviderProtocol::OpenAI, OpenAIApiMode::ChatCompletions),
      transcript, options);
  Require(!result.error, "Chat agent request failed");
  body = Json::parse(result.request.body);
  Require(body.at("messages").at(0).at("role") == "system"
              && body.at("messages").at(1).at("role") == "user",
          "Chat system placement mismatch");
  Require(body.at("tools").at(0).at("function").at("strict") == true,
          "Chat tool wrapper mismatch");
  Require(body.at("messages").at(2).at("tool_calls").at(0).at("id") == "call-1"
              && body.at("messages").at(3).at("role") == "tool",
          "Chat exchange wire mismatch");

  options.exchanges.front().results.front().success = false;
  options.exchanges.front().results.front().output = "must-not-leak";
  options.exchanges.front().results.front().safe_message = "Tool failed safely.";
  result = BuildProviderAgentRequest(
      MakeProfile(ProviderProtocol::Claude), transcript, options);
  Require(!result.error, "Claude agent request failed");
  body = Json::parse(result.request.body);
  Require(body.at("system") == "trusted system", "Claude system mismatch");
  Require(body.at("tools").at(0).at("input_schema").at("type") == "object",
          "Claude schema mismatch");
  Require(body.at("messages").at(1).at("content").at(1).at("input").is_object(),
          "Claude arguments were not parsed");
  const Json &tool_result = body.at("messages").at(2).at("content").at(0);
  Require(tool_result.at("is_error") == true
              && tool_result.at("content") == "Tool failed safely.",
          "Claude safe failure mismatch");
  Require(result.request.body.find("must-not-leak") == std::string::npos,
          "failed tool output leaked");
}

void TestEmptyAgentOptionsPreserveChatWire()
{
  const std::vector<ProviderChatMessage> transcript{
      {ProviderChatRole::User, "plain"},
  };
  const ProviderChatAgentOptions options;
  for ( const auto mode : {OpenAIApiMode::Responses,
                            OpenAIApiMode::ChatCompletions} )
  {
    const ProviderProfileDraft profile = MakeProfile(ProviderProtocol::OpenAI, mode);
    const auto chat = BuildProviderChatRequest(profile, transcript);
    const auto agent = BuildProviderAgentRequest(profile, transcript, options);
    Require(!chat.error && !agent.error && chat.request.body == agent.request.body,
            "empty OpenAI agent options changed chat wire");
  }
  const ProviderProfileDraft claude = MakeProfile(ProviderProtocol::Claude);
  const auto chat = BuildProviderChatRequest(claude, transcript);
  const auto agent = BuildProviderAgentRequest(claude, transcript, options);
  Require(!chat.error && !agent.error && chat.request.body == agent.request.body,
          "empty Claude agent options changed chat wire");
}

void TestAgentRequestLimits()
{
  const auto profile = MakeProfile(ProviderProtocol::OpenAI);
  const std::vector<ProviderChatMessage> transcript{
      {ProviderChatRole::User, "inspect"},
  };
  ProviderChatAgentOptions options = AgentOptions();
  options.exchanges.front().calls.front().arguments_json = "not-json";
  Require(BuildProviderAgentRequest(profile, transcript, options).error,
          "invalid arguments were encoded");

  options = AgentOptions();
  options.tools.front().name = "ida_file_mutate";
  options.exchanges.front().calls.front().name = "ida_file_mutate";
  options.exchanges.front().results.front().name = "ida_file_mutate";
  options.exchanges.front().calls.front().arguments_json = Json{{"path","large.txt"},
      {"mode","overwrite"},{"content",std::string(128 * 1024, '\"')}}.dump();
  Require(options.exchanges.front().calls.front().arguments_json.size()
          > MaxAgentToolArgumentsBytes
      && options.exchanges.front().calls.front().arguments_json.size()
          <= MaxAgentFileToolArgumentsBytes
      && !BuildProviderAgentRequest(profile, transcript, options).error,
      "bounded file mutation arguments were rejected");

  options = AgentOptions();
  options.tools.front().name = "ida_file_read";
  options.exchanges.front().calls.front().name = "ida_file_read";
  options.exchanges.front().results.front().name = "ida_file_read";
  options.exchanges.front().results.front().output = Json{{"path","large.txt"},
      {"content",std::string(128 * 1024, '\"')},{"bytesRead",128 * 1024},
      {"hasMore",false},{"nextOffset",nullptr}}.dump();
  Require(options.exchanges.front().results.front().output.size() > MaxAgentToolResultBytes
      && options.exchanges.front().results.front().output.size() <= MaxAgentFileToolResultBytes
      && !BuildProviderAgentRequest(profile, transcript, options).error,
      "bounded file read result was rejected");

  options = AgentOptions();
  options.exchanges.front().results.front().call_id = "wrong";
  Require(BuildProviderAgentRequest(profile, transcript, options).error,
          "mismatched result id was accepted");

  options = AgentOptions();
  options.system_prompt.assign(MaxProviderSystemPromptBytes + 1, 's');
  Require(BuildProviderAgentRequest(profile, transcript, options).error,
          "system prompt limit was ignored");

  options = AgentOptions();
  for ( int index = 1; index < 5; ++index )
  {
    const std::string id = "call-" + std::to_string(index + 1);
    options.exchanges.front().calls.push_back({id, "lookup", "{}"});
    options.exchanges.front().results.push_back(
        {id, "lookup", true, "{}", {}});
  }
  Require(!BuildProviderAgentRequest(profile, transcript, options).error,
          "multi-call agent exchange was rejected by a call-count limit");

  ProviderProfileDraft small = profile;
  small.models.front().context_length = 4120;
  small.models.front().max_output_tokens = 10;
  options = AgentOptions();
  Require(BuildProviderAgentRequest(small, transcript, options).error,
          "required agent context was cropped");
}

void TestRequestBodyLimitsAndLargeHistory()
{
  Require(MaxProviderRequestBodyBytes < StreamHardMaxPayloadBytes,
          "provider request body limit reached the transport hard limit");

  ProviderProfileDraft profile = MakeProfile(ProviderProtocol::OpenAI);
  profile.models.front().context_length = 2'000'000;
  profile.models.front().max_output_tokens = 1;
  const ProviderChatBuildResult result = BuildProviderChatRequest(
      profile,
      {{ProviderChatRole::User, std::string(2 * 1024 * 1024, 'x')}});
  Require(!result.error, "history above the old 1 MiB limit was rejected");
  Require(result.request.body.size() > MaxProviderAgentFixedPayloadBytes
              && result.request.body.size() <= MaxProviderRequestBodyBytes,
          "large history did not use the independent request body budget");
  Require(result.messages.size() == 1,
          "large in-budget history was unexpectedly cropped");
}

void TestByteCropForAllCodecs()
{
  const std::string oversized_wire_history(
      MaxProviderRequestBodyBytes / 6 + 4096, '\x01');
  std::vector<ProviderProfileDraft> profiles{
      MakeProfile(ProviderProtocol::OpenAI, OpenAIApiMode::Responses),
      MakeProfile(ProviderProtocol::OpenAI, OpenAIApiMode::ChatCompletions),
      MakeProfile(ProviderProtocol::Claude),
  };
  for ( ProviderProfileDraft &profile : profiles )
  {
    profile.models.front().context_length = 2'000'000;
    profile.models.front().max_output_tokens = 1;
    const ProviderChatBuildResult result = BuildProviderChatRequest(
        profile,
        {{ProviderChatRole::User, oversized_wire_history},
         {ProviderChatRole::Assistant, "old reply"},
         {ProviderChatRole::User, "latest"}});
    Require(!result.error, "byte crop failed for a provider codec");
    Require(result.messages.size() == 1
                && result.messages.front().role == ProviderChatRole::User
                && result.messages.front().text == "latest",
            "byte crop did not retain only the latest user message");
    Require(result.request.body.size() <= MaxProviderRequestBodyBytes,
            "byte-cropped provider body exceeded 8 MiB");
  }
}

void TestAgentFixedPayloadAndByteCrop()
{
  ProviderProfileDraft profile = MakeProfile(ProviderProtocol::OpenAI);
  profile.models.front().context_length = 2'000'000;
  profile.models.front().max_output_tokens = 1;
  ProviderChatAgentOptions options = AgentOptions();
  options.system_prompt.assign(MaxProviderSystemPromptBytes, 's');
  options.tools.front().parameters["padding"] = std::string(300 * 1024, 'p');
  options.exchanges.front().results.front().output.assign(240 * 1024, 'r');

  const std::string long_history(
      MaxProviderRequestBodyBytes / 6 + 4096, '\x01');
  ProviderChatBuildResult result = BuildProviderAgentRequest(
      profile,
      {{ProviderChatRole::User, long_history},
      {ProviderChatRole::User, "latest agent request"}},
      options);
  Require(!result.error, "large agent fixed payload prevented history crop");
  Require(result.messages.size() == 1
              && result.messages.front().text == "latest agent request",
          "agent byte crop lost the latest user request");
  Require(result.request.body.size() <= MaxProviderRequestBodyBytes,
          "byte-cropped agent body exceeded 8 MiB");

  options = AgentOptions();
  options.tools.front().description.assign(
      MaxProviderAgentFixedPayloadBytes - 512, 'd');
  result = BuildProviderAgentRequest(
      profile, {{ProviderChatRole::User, "latest"}}, options);
  Require(result.error && result.request.body.empty(),
          "independent 1 MiB agent fixed payload budget was enlarged");
}

void TestUtf8AwareTokenEstimate()
{
  ProviderProfileDraft profile = MakeProfile(ProviderProtocol::OpenAI);
  const ProviderChatBuildResult ascii = BuildProviderChatRequest(
      profile, {{ProviderChatRole::User, "abcdefghijkl"}});
  const ProviderChatBuildResult cjk = BuildProviderChatRequest(
      profile,
      {{ProviderChatRole::User,
        "\xE4\xB8\xAD\xE4\xB8\xAD\xE4\xB8\xAD\xE4\xB8\xAD"}});
  const ProviderChatBuildResult emoji = BuildProviderChatRequest(
      profile,
      {{ProviderChatRole::User,
        "\xF0\x9F\x98\x80\xF0\x9F\x98\x80"
        "\xF0\x9F\x98\x80\xF0\x9F\x98\x80"}});
  Require(!ascii.error && !cjk.error && !emoji.error,
          "UTF-8 token estimate request failed");
  Require(ascii.estimated_input_tokens
              == ProviderChatMessageOverheadTokens + 3,
          "ASCII token estimate changed unexpectedly");
  Require(cjk.estimated_input_tokens
              == ProviderChatMessageOverheadTokens + 4
              && cjk.estimated_input_tokens > ascii.estimated_input_tokens,
          "CJK token estimate still used raw bytes divided by four");
  Require(emoji.estimated_input_tokens
              == ProviderChatMessageOverheadTokens + 4,
          "emoji code points were not counted as tokens");
}

void TestInvalidUtf8UserIsConfigurationError()
{
  ProviderChatBuildResult result;
  try
  {
    result = BuildProviderChatRequest(
        MakeProfile(ProviderProtocol::OpenAI),
        {{ProviderChatRole::User, std::string("\xC3\x28", 2)}});
  }
  catch ( const std::exception & )
  {
    throw std::runtime_error("invalid UTF-8 escaped provider request building");
  }
  Require(result.error && result.request.body.empty(),
          "invalid UTF-8 user content was not rejected locally");
}

void TestResponsesDecode()
{
  ProviderChatDecodeResult result = Decode(
      ProviderChatCodec::OpenAIResponses,
      R"({"type":"response.output_text.delta","delta":"abc"})");
  Require(result.text_delta == "abc" && !result.completed, "Responses delta mismatch");
  result = Decode(
      ProviderChatCodec::OpenAIResponses,
      R"({"type":"response.reasoning_summary_text.delta","delta":"secret"})");
  Require(result.text_delta.empty() && result.reasoning_delta == "secret"
              && !result.error,
          "Responses reasoning delta mismatch");
  result = Decode(ProviderChatCodec::OpenAIResponses,
                  R"({"type":"response.completed"})");
  Require(result.completed && !result.error, "Responses completion mismatch");
  result = Decode(ProviderChatCodec::OpenAIResponses,
                  R"({"type":"response.failed","error":{"message":"secret-body"}})");
  Require(result.error && result.completed, "Responses provider error mismatch");
  Require(result.safe_message.find("secret-body") == std::string::npos,
          "Responses error body leaked");
  result = Decode(ProviderChatCodec::OpenAIResponses,
      R"({"type":"response.output_item.added","output_index":1,"item":{"type":"function_call","call_id":"call-1","name":"lookup","arguments":""}})");
  Require(result.updates.size() == 1
              && result.updates.front().index == 1
              && result.updates.front().id_snapshot == "call-1"
              && !result.updates.front().done,
          "Responses tool initialization mismatch");
  result = Decode(ProviderChatCodec::OpenAIResponses,
      R"({"type":"response.function_call_arguments.delta","output_index":1,"delta":"{\"name\":"})");
  Require(result.updates.front().arguments_delta == R"({"name":)",
          "Responses arguments fragment mismatch");
  result = Decode(ProviderChatCodec::OpenAIResponses,
      R"({"type":"response.output_item.done","output_index":1,"item":{"type":"function_call","call_id":"call-1","name":"lookup","arguments":"{\"name\":\"main\"}"}})");
  Require(result.updates.front().done
              && result.updates.front().arguments_snapshot == R"({"name":"main"})",
          "Responses tool snapshot mismatch");
  result = Decode(ProviderChatCodec::OpenAIResponses,
                  R"({"type":"response.output_text.delta","delta":7})");
  Require(result.error && result.safe_message == ProviderChatProtocolErrorMessage,
          "Responses field type error accepted");
  Require(Decode(ProviderChatCodec::OpenAIResponses, "not-json").error,
          "Responses malformed JSON accepted");
}

void TestChatCompletionsDecode()
{
  ProviderChatDecodeResult result = Decode(
      ProviderChatCodec::OpenAIChatCompletions,
      R"({"choices":[{"delta":{"content":"part"},"finish_reason":"stop"}]})");
  Require(result.text_delta == "part" && result.completed,
          "Chat text plus completion mismatch");
  result = Decode(
      ProviderChatCodec::OpenAIChatCompletions,
      R"({"choices":[{"delta":{"reasoning_content":"secret"},"finish_reason":null}]})");
  Require(result.text_delta.empty() && result.reasoning_delta == "secret"
              && !result.error,
          "Chat reasoning delta mismatch");
  result = Decode(ProviderChatCodec::OpenAIChatCompletions, "[DONE]");
  Require(result.completed && !result.error, "Chat DONE mismatch");
  result = Decode(
      ProviderChatCodec::OpenAIChatCompletions,
      R"({"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call-","type":"function","function":{"name":"look","arguments":"{\"name\":"}},{"index":1,"id":"call-2","type":"function","function":{"name":"lookup","arguments":"{}"}}]},"finish_reason":null}]})");
  Require(result.updates.size() == 2
              && result.updates.at(0).id_delta == "call-"
              && result.updates.at(1).index == 1,
          "Chat multi-call fragments mismatch");
  result = Decode(
      ProviderChatCodec::OpenAIChatCompletions,
      R"({"choices":[{"delta":{},"finish_reason":"tool_calls"}]})");
  Require(result.completed && !result.error,
          "Chat tool_calls finish reason was rejected");
  result = Decode(
      ProviderChatCodec::OpenAIChatCompletions,
      R"({"choices":[{"delta":{},"finish_reason":"function_call"}]})");
  Require(result.completed && !result.error,
          "Chat function_call finish reason was rejected");
  result = Decode(ProviderChatCodec::OpenAIChatCompletions,
                  R"({"error":{"message":"provider-secret"}})");
  Require(result.error && result.safe_message.find("provider-secret") == std::string::npos,
          "Chat provider error leaked");
  Require(Decode(ProviderChatCodec::OpenAIChatCompletions,
                 R"({"choices":"bad"})").error,
          "Chat field type error accepted");
  Require(Decode(ProviderChatCodec::OpenAIChatCompletions, "{").error,
          "Chat malformed JSON accepted");
}

void TestClaudeDecode()
{
  ProviderChatDecodeResult result = Decode(
      ProviderChatCodec::ClaudeMessages,
      R"({"type":"content_block_delta","delta":{"type":"text_delta","text":"claude"}})");
  Require(result.text_delta == "claude", "Claude delta mismatch");
  result = Decode(
      ProviderChatCodec::ClaudeMessages,
      R"({"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"secret"}})");
  Require(result.text_delta.empty() && result.reasoning_delta == "secret"
              && !result.error,
          "Claude thinking delta mismatch");
  result = Decode(ProviderChatCodec::ClaudeMessages, R"({"type":"message_stop"})");
  Require(result.completed && !result.error, "Claude completion mismatch");
  result = Decode(
      ProviderChatCodec::ClaudeMessages,
      R"({"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"tool-1","name":"lookup","input":{}}})");
  Require(result.updates.size() == 1
              && result.updates.front().id_snapshot == "tool-1"
              && !result.updates.front().arguments_snapshot.has_value()
              && result.updates.front().empty_object_start,
          "Claude tool use mismatch");
  result = Decode(
      ProviderChatCodec::ClaudeMessages,
      R"({"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"name\":\"main\"}"}})");
  Require(result.updates.front().arguments_delta == R"({"name":"main"})",
          "Claude input fragment mismatch");
  result = Decode(ProviderChatCodec::ClaudeMessages,
      R"({"type":"content_block_stop","index":2})");
  Require(result.updates.front().done, "Claude block stop mismatch");
  result = Decode(ProviderChatCodec::ClaudeMessages,
                  R"({"type":"error","error":{"message":"claude-secret"}})");
  Require(result.error && result.safe_message.find("claude-secret") == std::string::npos,
          "Claude error leaked");
  result = Decode(ProviderChatCodec::ClaudeMessages, R"({"type":"ping"})");
  Require(!result.error && !result.completed && result.text_delta.empty(),
          "Claude ping was not ignored");
  Require(Decode(ProviderChatCodec::ClaudeMessages,
                 R"({"type":"content_block_delta","delta":3})").error,
          "Claude field type error accepted");
  Require(Decode(ProviderChatCodec::ClaudeMessages, "invalid").error,
          "Claude malformed JSON accepted");
}

} // namespace

int main()
{
  TestOpenAIResponsesRequest();
  TestOpenAIChatRequestAndCrop();
  TestBudgetBoundaryAndOutputClamp();
  TestClaudeRequestAndSafeFailure();
  TestAgentRequestWires();
  TestEmptyAgentOptionsPreserveChatWire();
  TestAgentRequestLimits();
  TestRequestBodyLimitsAndLargeHistory();
  TestByteCropForAllCodecs();
  TestAgentFixedPayloadAndByteCrop();
  TestUtf8AwareTokenEstimate();
  TestInvalidUtf8UserIsConfigurationError();
  TestResponsesDecode();
  TestChatCompletionsDecode();
  TestClaudeDecode();
  return 0;
}
