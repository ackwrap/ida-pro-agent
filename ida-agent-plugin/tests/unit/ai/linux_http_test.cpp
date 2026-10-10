#include "ai/http_client.hpp"
#include "ai/provider_client.hpp"
#include <chrono>
#include <cstdlib>
#include <stdexcept>
#include <thread>

using namespace ida_agent::ai;
using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;
namespace
{
void Require(bool condition, const char *message)
{
  if (!condition) throw std::runtime_error(message);
}
HttpResponse Wait(HttpClient &client, HttpClient::RequestId id)
{
  const auto deadline = Clock::now() + 8s;
  while (Clock::now() < deadline)
  {
    if (auto result = client.TryTakeResult(id)) return *result;
    std::this_thread::sleep_for(5ms);
  }
  throw std::runtime_error("HTTP result timed out");
}
HttpRequest Request(const std::string &url)
{
  HttpRequest request;
  request.url = url;
  request.user_agent = "ida-linux-http-test";
  request.proxy.mode = HttpProxyMode::Direct;
  request.connect_timeout_ms = 1000;
  request.receive_timeout_ms = 1000;
  return request;
}
void RequireSafe(const HttpResponse &response)
{
  Require(response.body.empty() && response.message.find("test-secret") == std::string::npos
      && response.message.find("localhost") == std::string::npos,
      "network failure leaked request data");
}
}

int main(int argc, char **argv)
{
  Require(argc == 6, "test endpoints are required");
  const std::string mode = argv[1], http = argv[2], https = argv[3], stall_tls = argv[5];
  const auto proxy_port = static_cast<std::uint16_t>(std::stoi(argv[4]));
  HttpClient client;
  if (mode == "system-proxy")
  {
    std::string unreachable = http;
    unreachable.replace(unreachable.find("127.0.0.1"), 9, "127.0.0.2");
    auto request = Request(unreachable + "/v1/models");
    request.proxy.mode = HttpProxyMode::System;
    const auto response = Wait(client, client.Submit(request));
    Require(response.status == HttpResponseStatus::Success && response.http_status == 200,
        "system proxy was not used");
    request.proxy.mode = HttpProxyMode::Direct;
    const auto direct = Wait(client, client.Submit(request));
    Require(direct.status == HttpResponseStatus::NetworkError, "direct mode used environment proxy");
    return 0;
  }
  auto request = Request(https + "/echo");
  auto response = Wait(client, client.Submit(request));
  if (mode == "trusted-tls")
  {
    if (response.status != HttpResponseStatus::Success || response.body != "ok")
      throw std::runtime_error("trusted TLS failed: " + response.message);
    auto wrong_host = request;
    wrong_host.url.replace(wrong_host.url.find("localhost"), 9, "127.0.0.1");
    const auto rejected = Wait(client, client.Submit(wrong_host));
    Require(rejected.status == HttpResponseStatus::NetworkError, "TLS hostname verification disabled");
    RequireSafe(rejected);
    request.proxy = {HttpProxyMode::Http, "127.0.0.1", proxy_port, "proxy-user", "test-secret-proxy", false};
    request.url.replace(request.url.find("localhost"), 9, "provider.invalid");
    request.headers.push_back({"Authorization", "Bearer test-secret-origin"});
    const auto tunneled = Wait(client, client.Submit(request));
    Require(tunneled.status == HttpResponseStatus::Success && tunneled.body == "ok", "authenticated CONNECT failed");
    return 0;
  }
  Require(response.status == HttpResponseStatus::NetworkError, "untrusted TLS certificate accepted");
  RequireSafe(response);
  request = Request(http + "/echo");
  response = Wait(client, client.Submit(request));
  Require(response.status == HttpResponseStatus::Success && response.http_status == 200 && response.body == "ok",
      "GET response mismatch");
  request.method = HttpMethod::Post;
  request.body = std::string("binary\0body", 11);
  request.headers = {{"Content-Type", "application/octet-stream"}, {"X-Test", "test-secret-origin"}};
  response = Wait(client, client.Submit(request));
  Require(response.body == request.body, "POST binary body mismatch");
  request = Request(http + "/redirect");
  request.headers = {{"Authorization", "Bearer test-secret-origin"}};
  response = Wait(client, client.Submit(request));
  Require(response.status == HttpResponseStatus::Success && response.http_status == 302, "redirect was followed");
  request = Request(http + "/status");
  response = Wait(client, client.Submit(request));
  Require(response.status == HttpResponseStatus::Success && response.http_status == 401 && response.body == "denied",
      "HTTP error status/body was discarded");
  request = Request(http + "/large");
  request.max_response_bytes = 128;
  response = Wait(client, client.Submit(request));
  Require(response.status == HttpResponseStatus::ResponseTooLarge && response.http_status == 200,
      "response size limit or HTTP status failed");
  RequireSafe(response);
  for (const auto *path : {"/stall-headers", "/stall-body"})
  {
    request = Request(http + path);
    request.receive_timeout_ms = 150;
    const auto started = Clock::now();
    response = Wait(client, client.Submit(request));
    Require(response.status == HttpResponseStatus::NetworkError && Clock::now() - started < 1500ms,
        "receive timeout was not enforced");
    RequireSafe(response);
  }
  request = Request(http + "/trickle");
  // The fixture sends for over two seconds, with a tenfold margin between
  // packet cadence and idle timeout to tolerate shared-runner scheduling.
  request.receive_timeout_ms = 1000;
  response = Wait(client, client.Submit(request));
  if (response.status != HttpResponseStatus::Success || response.body != std::string(24, 'x'))
    throw std::runtime_error("active HTTP trickle failed: " + response.message);
  request = Request(http + "/upload-stall");
  request.method = HttpMethod::Post;
  request.body.assign(32 * 1024 * 1024, 'x');
  request.send_timeout_ms = 150;
  request.receive_timeout_ms = 5000;
  response = Wait(client, client.Submit(request));
  Require(response.status == HttpResponseStatus::NetworkError && response.message.find("send timeout") != std::string::npos,
      "send timeout was not enforced");
  request = Request(stall_tls);
  request.connect_timeout_ms = 150;
  const auto connecting = Clock::now();
  response = Wait(client, client.Submit(request));
  Require(response.status == HttpResponseStatus::NetworkError && Clock::now() - connecting < 1500ms,
      "TLS connection timeout was not enforced");
  request = Request(http + "/cancel");
  request.receive_timeout_ms = 5000;
  auto id = client.Submit(request);
  std::this_thread::sleep_for(80ms);
  auto started = Clock::now();
  client.Cancel(id);
  Require(Wait(client, id).status == HttpResponseStatus::Cancelled && Clock::now() - started < 1s,
      "active cancellation was not responsive");
  id = client.Submit(request);
  std::this_thread::sleep_for(80ms);
  client.CancelAndForget(id);
  Require(Wait(client, client.Submit(Request(http + "/echo"))).body == "ok", "cancel-and-forget blocked the next request");
  Require(!client.TryTakeResult(id), "forgotten result reappeared");
  request = Request("http://provider.invalid/v1/models");
  request.proxy = {HttpProxyMode::Http, "127.0.0.1", proxy_port, "proxy-user", "test-secret-proxy", false};
  response = Wait(client, client.Submit(request));
  if (response.http_status != 200)
    throw std::runtime_error("authenticated HTTP proxy failed: status=" + std::to_string(response.http_status)
        + " " + response.message);
  request.url = http + "/echo";
  request.proxy.password = "wrong-proxy-password";
  response = Wait(client, client.Submit(request));
  Require(response.status == HttpResponseStatus::NetworkError || response.http_status == 407,
      "proxy authentication failure fell back to a direct connection");
  request.url = "http://provider.invalid/v1/models";
  response = Wait(client, client.Submit(request));
  Require(response.status == HttpResponseStatus::NetworkError || response.http_status == 407,
      "proxy accepted incorrect credentials");
#ifdef __APPLE__
  request.url = http + "/echo";
  request.proxy.bypass_local = true;
  Require(Wait(client, client.Submit(request)).body == "ok", "explicit local bypass failed");
#endif
  ProviderClient provider(client);
  auto profile = CreateProviderManagerDraft().profiles.front();
  profile.settings.base_url = http + "/v1";
  profile.settings.api_key = "test-secret-origin";
  profile.proxy.mode = ProviderProxyMode::Direct;
  const auto discovery = provider.SubmitListModels(profile);
  const auto deadline = Clock::now() + 3s;
  bool discovered = false;
  while (Clock::now() < deadline)
  {
    if (auto models = provider.TryTakeResult(discovery))
    {
      Require(models->status == ProviderDiscoveryStatus::Success && models->models.size() == 1
          && models->models.front().id == "local-model", "provider discovery failed");
      discovered = true;
      break;
    }
    std::this_thread::sleep_for(5ms);
  }
  Require(discovered, "provider discovery timed out");
  client.Submit(Request(http + "/shutdown"));
  std::this_thread::sleep_for(80ms);
  started = Clock::now();
  client.Shutdown();
  Require(Clock::now() - started < 1s, "shutdown did not cancel active I/O");
}
