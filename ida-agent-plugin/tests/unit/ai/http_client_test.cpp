#include "ai/http_client.hpp"

#include <stdexcept>
#include <string>

namespace
{

void Require(bool condition, const char *message)
{
  if ( !condition )
    throw std::runtime_error(message);
}

ida_agent::ai::HttpRequest MakeRequest()
{
  ida_agent::ai::HttpRequest request;
  request.url = "https://provider.example/v1/models?limit=10";
  request.user_agent = "ida-agent-http-test";
  request.headers.push_back({"Accept", "application/json"});
  return request;
}

} // namespace

int main()
{
  using namespace ida_agent::ai;

  HttpRequest request = MakeRequest();
  Require(!ValidateHttpRequest(request).has_value(), "valid GET request was rejected");

  request.method = HttpMethod::Post;
  request.body = R"({"model":"unit-test"})";
  request.headers.push_back({"Content-Type", "application/json"});
  Require(!ValidateHttpRequest(request).has_value(), "valid POST request was rejected");

  HttpRequest invalid = MakeRequest();
  invalid.url = "file:///unit-test";
  Require(ValidateHttpRequest(invalid).has_value(), "non-HTTP URL was accepted");
  invalid = MakeRequest();
  invalid.headers.push_back({"Bad\r\nHeader", "secret-value"});
  Require(ValidateHttpRequest(invalid).has_value(), "invalid header was accepted");
  invalid = MakeRequest();
  invalid.headers.push_back({"Content-Length", "1"});
  Require(ValidateHttpRequest(invalid).has_value(), "transport-managed header was accepted");
  invalid = MakeRequest();
  invalid.max_response_bytes = HttpHardMaxResponseBytes + 1;
  Require(ValidateHttpRequest(invalid).has_value(), "response hard cap was not enforced");
  invalid = MakeRequest();
  invalid.proxy.mode = HttpProxyMode::Http;
  invalid.proxy.host = "https://proxy.example";
  invalid.proxy.port = 8080;
  Require(ValidateHttpRequest(invalid).has_value(), "proxy URL was accepted as a host");

  HttpClient client;
  invalid = MakeRequest();
  invalid.user_agent.clear();
  invalid.headers.push_back({"Authorization", "unit-test-secret"});
  const HttpClient::RequestId invalid_id = client.Submit(std::move(invalid));
  const std::optional<HttpResponse> invalid_result = client.TryTakeResult(invalid_id);
  Require(invalid_result.has_value(), "invalid request result was not immediate");
  Require(
      invalid_result->status == HttpResponseStatus::InvalidRequest,
      "invalid request status mismatch");
  Require(
      invalid_result->message.find("unit-test-secret") == std::string::npos,
      "invalid request diagnostic leaked a header value");

  invalid = MakeRequest();
  invalid.user_agent.clear();
  const HttpClient::RequestId forgotten_invalid_id = client.Submit(std::move(invalid));
  client.CancelAndForget(forgotten_invalid_id);
  client.CancelAndForget(forgotten_invalid_id);
  Require(
      !client.TryTakeResult(forgotten_invalid_id).has_value(),
      "forgotten invalid result remained available");
  client.CancelAndForget(0);

  HttpClient queued_client;
  queued_client.PauseWorkerForTesting();
  const HttpClient::RequestId queued_id = queued_client.Submit(MakeRequest());
  queued_client.CancelAndForget(queued_id);
  queued_client.CancelAndForget(queued_id);
  Require(
      !queued_client.TryTakeResult(queued_id).has_value(),
      "forgotten queued request produced a result");
  queued_client.Shutdown();
  queued_client.Shutdown();

  client.Shutdown();
  client.Shutdown();
  const HttpClient::RequestId stopped_id = client.Submit(MakeRequest());
  const std::optional<HttpResponse> stopped_result = client.TryTakeResult(stopped_id);
  Require(stopped_result.has_value(), "stopped worker did not return a result");
  Require(
      stopped_result->status == HttpResponseStatus::Cancelled,
      "stopped worker did not cancel submission");
  const HttpClient::RequestId forgotten_stopped_id = client.Submit(MakeRequest());
  client.CancelAndForget(forgotten_stopped_id);
  Require(
      !client.TryTakeResult(forgotten_stopped_id).has_value(),
      "forgotten immediate shutdown result remained available");
}
