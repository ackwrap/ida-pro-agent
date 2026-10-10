#pragma once

#include "ai/network_types.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ida_agent::ai
{

constexpr std::size_t HttpHardMaxResponseBytes = 64 * 1024 * 1024;

struct HttpRequest
{
  HttpMethod method = HttpMethod::Get;
  std::string url;
  std::string user_agent;
  std::vector<HttpHeader> headers;
  std::string body;
  std::uint32_t connect_timeout_ms = 10000;
  std::uint32_t send_timeout_ms = 30000;
  std::uint32_t receive_timeout_ms = 30000;
  std::size_t max_response_bytes = 4 * 1024 * 1024;
  HttpProxyConfig proxy;
};

enum class HttpResponseStatus
{
  Success,
  NetworkError,
  Cancelled,
  ResponseTooLarge,
  InvalidRequest,
};

struct HttpResponse
{
  HttpResponseStatus status = HttpResponseStatus::InvalidRequest;
  std::uint32_t http_status = 0;
  std::string body;
  std::string message;
};

// Returns a safe diagnostic that never includes request data, or nullopt when
// the request can be submitted.
std::optional<std::string> ValidateHttpRequest(const HttpRequest &request);

class HttpClient final
{
public:
  using RequestId = std::uint64_t;

  HttpClient();
  ~HttpClient();

  HttpClient(const HttpClient &) = delete;
  HttpClient &operator=(const HttpClient &) = delete;

  RequestId Submit(HttpRequest request);
  std::optional<HttpResponse> TryTakeResult(RequestId request_id);
  void Cancel(RequestId request_id);
  void CancelAndForget(RequestId request_id);
  void Shutdown();

#ifdef IDA_AGENT_HTTP_CLIENT_TESTING
  void PauseWorkerForTesting();
#endif

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace ida_agent::ai
