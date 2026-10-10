#include "ai/provider_client.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

void Require(bool condition, const char *message)
{
  if ( !condition )
    throw std::runtime_error(message);
}

const ida_agent::ai::ProviderHeaderDraft *FindHeader(
    const ida_agent::ai::ProviderListModelsRequest &request,
    std::string_view lowered_name)
{
  const auto found = std::find_if(
      request.headers.begin(),
      request.headers.end(),
      [lowered_name](const ida_agent::ai::ProviderHeaderDraft &header)
      {
        std::string name = header.name;
        std::transform(
            name.begin(),
            name.end(),
            name.begin(),
            [](unsigned char character)
            {
              return character >= 'A' && character <= 'Z'
                  ? static_cast<char>(character - 'A' + 'a')
                  : static_cast<char>(character);
            });
        return name == lowered_name;
      });
  return found == request.headers.end() ? nullptr : &*found;
}

std::size_t CountHeader(
    const ida_agent::ai::ProviderListModelsRequest &request,
    std::string_view lowered_name)
{
  return static_cast<std::size_t>(std::count_if(
      request.headers.begin(),
      request.headers.end(),
      [lowered_name](const ida_agent::ai::ProviderHeaderDraft &header)
      {
        std::string name = header.name;
        std::transform(name.begin(), name.end(), name.begin(), [](unsigned char character)
        {
          return character >= 'A' && character <= 'Z'
              ? static_cast<char>(character - 'A' + 'a')
              : static_cast<char>(character);
        });
        return name == lowered_name;
      }));
}

ida_agent::ai::ProviderProfileDraft MakeProfile(
    ida_agent::ai::ProviderSettingsDraft settings,
    std::vector<ida_agent::ai::ProviderHeaderDraft> headers = {})
{
  ida_agent::ai::ProviderProfileDraft profile;
  profile.settings = std::move(settings);
  profile.custom_headers = std::move(headers);
  return profile;
}

} // namespace

int main()
{
  using namespace ida_agent::ai;

  ProviderSettingsDraft openai = DraftForPreset(ProviderPreset::OpenAI);
  auto request = BuildListModelsRequest(MakeProfile(openai));
  Require(request.has_value(), "default OpenAI request was rejected");
  Require(
      request->url == "https://api.openai.com/v1/models",
      "OpenAI models URL mismatch");
  Require(
      request->user_agent == DefaultBrowserUserAgent(),
      "default User-Agent mismatch");
  Require(FindHeader(*request, "user-agent") == nullptr, "User-Agent was duplicated as a header");

  openai.base_url = "  https://provider.example///  ";
  request = BuildListModelsRequest(MakeProfile(openai));
  Require(request.has_value(), "trailing-slash URL was rejected");
  Require(request->url == "https://provider.example/models", "trailing slashes were not normalized");

  openai.api_key = "unit-test-openai-key";
  request = BuildListModelsRequest(MakeProfile(
      openai,
      {
          {"user-agent", "Unit Test Agent", true},
          {"X-Disabled", "not-sent", false},
          {"Authorization", "disabled-token", false},
          {"X-Custom", "custom-value", true},
      }));
  Require(request.has_value(), "custom OpenAI request was rejected");
  Require(request->user_agent == "Unit Test Agent", "custom User-Agent was not selected");
  Require(FindHeader(*request, "x-disabled") == nullptr, "disabled header was sent");
  Require(
      FindHeader(*request, "x-custom") != nullptr
          && FindHeader(*request, "x-custom")->value == "custom-value",
      "custom header was omitted or changed");
  Require(CountHeader(*request, "authorization") == 1, "disabled auth suppressed automatic auth");
  const ProviderHeaderDraft *authorization = FindHeader(*request, "authorization");
  Require(authorization != nullptr, "OpenAI Authorization was not generated");
  Require(
      authorization->value == "Bearer unit-test-openai-key",
      "OpenAI Authorization value mismatch");

  request = BuildListModelsRequest(MakeProfile(
      openai,
      {
          {"AUTHORIZATION", "Custom unit-test-token", true},
          {"authorization", "duplicate-token", true},
      }));
  Require(request.has_value(), "custom Authorization request was rejected");
  Require(CountHeader(*request, "authorization") == 1, "Authorization was not de-duplicated");
  Require(
      FindHeader(*request, "authorization")->value == "Custom unit-test-token",
      "custom Authorization was replaced");

  ProviderSettingsDraft claude = DraftForPreset(ProviderPreset::Claude);
  claude.api_key = "unit-test-claude-key";
  request = BuildListModelsRequest(MakeProfile(claude));
  Require(request.has_value(), "Claude request was rejected");
  Require(FindHeader(*request, "x-api-key") != nullptr, "Claude x-api-key was not generated");
  Require(
      FindHeader(*request, "anthropic-version") != nullptr
          && FindHeader(*request, "anthropic-version")->value == "2023-06-01",
      "Claude version header was not generated");

  request = BuildListModelsRequest(MakeProfile(
      claude,
      {
          {"Authorization", "Bearer custom-claude-token", true},
          {"Anthropic-Version", "unit-test-version", true},
      }));
  Require(request.has_value(), "custom Claude request was rejected");
  Require(FindHeader(*request, "x-api-key") == nullptr, "Claude key duplicated custom auth");
  Require(CountHeader(*request, "anthropic-version") == 1, "Claude version was duplicated");
  Require(
      FindHeader(*request, "anthropic-version")->value == "unit-test-version",
      "custom Claude version was replaced");

  ProviderProfileDraft proxied = MakeProfile(openai);
  proxied.proxy.mode = ProviderProxyMode::Http;
  proxied.proxy.host = "[2001:db8::20]";
  proxied.proxy.port = 8080;
  proxied.proxy.username = "proxy-user";
  proxied.proxy.password = "proxy-password";
  proxied.proxy.bypass_local = false;
  request = BuildListModelsRequest(proxied);
  Require(request.has_value(), "HTTP proxy request was rejected");
  Require(
      FormatHttpProxyEndpoint(request->proxy) == "[2001:db8::20]:8080",
      "IPv6 HTTP proxy endpoint format mismatch");
  proxied.proxy.host = "changed.example";
  proxied.proxy.password = "changed-password";
  Require(request->proxy.host == "2001:db8::20", "request did not snapshot proxy host");
  Require(request->proxy.password == "proxy-password", "request did not snapshot proxy credentials");
  const std::optional<HttpRequest> http_request = ToHttpRequest(*request);
  Require(http_request.has_value(), "provider request did not convert to HTTP request");
  Require(http_request->method == HttpMethod::Get, "provider HTTP method mismatch");
  Require(
      http_request->max_response_bytes == MaxProviderResponseBytes,
      "provider HTTP response limit mismatch");
  Require(http_request->proxy.mode == HttpProxyMode::Http, "provider proxy mode was not mapped");
  Require(http_request->proxy.host == "2001:db8::20", "provider proxy host was not mapped");

  ProviderProfileDraft direct = MakeProfile(openai);
  direct.proxy.mode = ProviderProxyMode::Direct;
  Require(BuildListModelsRequest(direct).has_value(), "direct proxy mode was rejected");
  ProviderProfileDraft system = MakeProfile(openai);
  Require(BuildListModelsRequest(system).has_value(), "system proxy mode was rejected");
  ProviderProfileDraft invalid_proxy = MakeProfile(openai);
  invalid_proxy.proxy.mode = ProviderProxyMode::Http;
  invalid_proxy.proxy.host = "https://proxy.example";
  invalid_proxy.proxy.port = 443;
  Require(!BuildListModelsRequest(invalid_proxy).has_value(), "TLS proxy endpoint was accepted");

  ProviderDiscoveryResult result = ParseListModelsResponse(
      ProviderProtocol::OpenAI,
      200,
      R"({"object":"list","data":[{"id":"z-model","owned_by":"test"},{"id":"a-model"},{"id":"z-model"}]})");
  Require(result.status == ProviderDiscoveryStatus::Success, "OpenAI response was not successful");
  Require(result.http_status == 200, "success HTTP status mismatch");
  Require(result.models.size() == 2, "duplicate models were not removed");
  Require(result.models[0].id == "a-model" && result.models[1].id == "z-model", "models were not sorted");
  Require(
      result.models[0].capabilities.empty()
          && result.models[0].context_length == DefaultModelContextLength
          && result.models[0].max_output_tokens == DefaultModelMaxOutputTokens,
      "default model metadata mismatch");

  result = ParseListModelsResponse(
      ProviderProtocol::Claude,
      200,
      R"({"data":[{"id":" claude-test-model ","display_name":"Test"}]})");
  Require(result.status == ProviderDiscoveryStatus::Success, "Anthropic response was not successful");
  Require(result.models.size() == 1 && result.models[0].id == "claude-test-model", "Anthropic model mismatch");

  result = ParseListModelsResponse(ProviderProtocol::OpenAI, 204, R"({"data":[]})");
  Require(result.status == ProviderDiscoveryStatus::Success && result.models.empty(), "empty list was not successful");

  for ( const std::string &invalid : {
            std::string("not-json"),
            std::string(R"({})"),
            std::string(R"({"data":[{}]})"),
            std::string(R"({"data":[{"id":5}]})"),
            std::string(R"({"data":[{"id":" "}]})"),
            std::string("{\"data\":[{\"id\":\"bad\\nmodel\"}]}"),
        })
  {
    result = ParseListModelsResponse(ProviderProtocol::OpenAI, 200, invalid);
    Require(result.status == ProviderDiscoveryStatus::InvalidResponse, "invalid response was accepted");
  }

  nlohmann::json too_many;
  too_many["data"] = nlohmann::json::array();
  for ( std::size_t index = 0; index <= MaxDiscoveredProviderModels; ++index )
    too_many["data"].push_back({{"id", "model-" + std::to_string(index)}});
  result = ParseListModelsResponse(ProviderProtocol::Claude, 200, too_many.dump());
  Require(result.status == ProviderDiscoveryStatus::InvalidResponse, "model limit was not enforced");
  Require(result.models.empty(), "over-limit response returned models");

  const std::string oversized_response(MaxProviderResponseBytes + 1, 'x');
  result = ParseListModelsResponse(ProviderProtocol::OpenAI, 200, oversized_response);
  Require(result.status == ProviderDiscoveryStatus::InvalidResponse, "response size limit was not enforced");

  result = ParseListModelsResponse(ProviderProtocol::OpenAI, 404, "ignored");
  Require(
      result.status == ProviderDiscoveryStatus::ReachableButModelDiscoveryUnsupported,
      "404 was not classified as unsupported discovery");
  Require(result.http_status == 404, "unsupported HTTP status mismatch");
  result = ParseListModelsResponse(ProviderProtocol::OpenAI, 500, "ignored");
  Require(result.status == ProviderDiscoveryStatus::HttpError, "500 was not classified as HTTP error");

  HttpClient forget_transport;
  forget_transport.Shutdown();
  ProviderClient forget_client(forget_transport);
  const ProviderClient::RequestId forgotten_request =
      forget_client.SubmitListModels(MakeProfile(openai));
  forget_client.CancelAndForget(forgotten_request);
  forget_client.CancelAndForget(forgotten_request);
  Require(
      !forget_client.TryTakeResult(forgotten_request).has_value(),
      "forgotten provider result remained available");
  forget_client.CancelAndForget(0);
  forget_client.Shutdown();

  HttpClient transport;
  ProviderClient client(transport);
  client.Shutdown();
  client.Shutdown();
  transport.Shutdown();
  const ProviderClient::RequestId stopped_request =
      client.SubmitListModels(MakeProfile(openai));
  const std::optional<ProviderDiscoveryResult> stopped_result =
      client.TryTakeResult(stopped_request);
  Require(stopped_result.has_value(), "stopped client did not produce a result");
  Require(
      stopped_result->status == ProviderDiscoveryStatus::Cancelled,
      "stopped client accepted a request");

  return 0;
}
