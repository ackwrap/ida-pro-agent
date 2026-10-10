#pragma once

#include "ai/http_client.hpp"
#include "ai/provider_settings_model.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ida_agent::ai
{

constexpr std::size_t MaxProviderResponseBytes = 4 * 1024 * 1024;
constexpr std::size_t MaxDiscoveredProviderModels = 256;

enum class ProviderDiscoveryStatus
{
  Success,
  ReachableButModelDiscoveryUnsupported,
  HttpError,
  NetworkError,
  InvalidResponse,
  Cancelled,
};

struct ProviderDiscoveryResult
{
  ProviderDiscoveryStatus status = ProviderDiscoveryStatus::InvalidResponse;
  std::string message;
  std::uint32_t http_status = 0;
  std::vector<ProviderModelDraft> models;
};

struct ProviderListModelsRequest
{
  ProviderProtocol protocol = ProviderProtocol::OpenAI;
  std::string url;
  std::string user_agent;
  std::vector<ProviderHeaderDraft> headers;
  ProviderProxyDraft proxy;
};

std::optional<ProviderListModelsRequest> BuildListModelsRequest(
    const ProviderProfileDraft &profile);
std::optional<HttpRequest> ToHttpRequest(
    const ProviderListModelsRequest &request);
std::string FormatHttpProxyEndpoint(const ProviderProxyDraft &proxy);

ProviderDiscoveryResult ParseListModelsResponse(
    ProviderProtocol protocol,
    std::uint32_t http_status,
    std::string_view response_body);

class ProviderClient final
{
public:
  using RequestId = HttpClient::RequestId;

  // Convenience constructor owning a private transport. Prefer injection when
  // provider discovery and chat share one HttpClient.
  ProviderClient();
  explicit ProviderClient(HttpClient &http_client);
  ~ProviderClient();

  ProviderClient(const ProviderClient &) = delete;
  ProviderClient &operator=(const ProviderClient &) = delete;

  RequestId SubmitListModels(
      const ProviderProfileDraft &profile);
  std::optional<ProviderDiscoveryResult> TryTakeResult(RequestId request_id);
  void Cancel(RequestId request_id);
  void CancelAndForget(RequestId request_id);
  void Shutdown();

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace ida_agent::ai
