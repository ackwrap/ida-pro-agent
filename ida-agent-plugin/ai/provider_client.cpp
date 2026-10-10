#include "ai/provider_client.hpp"

#include "ai/provider_request.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ida_agent::ai
{
namespace
{

constexpr std::size_t MaxModelIdLength = 256;

void TrimSpaces(std::string &value)
{
  const std::size_t first = value.find_first_not_of(' ');
  if ( first == std::string::npos )
  {
    value.clear();
    return;
  }
  const std::size_t last = value.find_last_not_of(' ');
  value = value.substr(first, last - first + 1);
}

bool HasControlCharacter(std::string_view value)
{
  return std::any_of(
      value.begin(),
      value.end(),
      [](unsigned char character)
      {
        return character < 0x20 || character == 0x7f;
      });
}

ProviderDiscoveryResult MakeResult(
    ProviderDiscoveryStatus status,
    std::string message,
    std::uint32_t http_status = 0)
{
  ProviderDiscoveryResult result;
  result.status = status;
  result.message = std::move(message);
  result.http_status = http_status;
  return result;
}

ProviderDiscoveryResult CancelledResult()
{
  return MakeResult(
      ProviderDiscoveryStatus::Cancelled,
      "Provider request was cancelled.");
}

ProviderDiscoveryResult MapHttpResponse(
    ProviderProtocol protocol,
    HttpResponse response)
{
  switch ( response.status )
  {
    case HttpResponseStatus::Success:
      return ParseListModelsResponse(
          protocol,
          response.http_status,
          response.body);
    case HttpResponseStatus::NetworkError:
      return MakeResult(
          ProviderDiscoveryStatus::NetworkError,
          std::move(response.message),
          response.http_status);
    case HttpResponseStatus::Cancelled:
      return CancelledResult();
    case HttpResponseStatus::ResponseTooLarge:
      return MakeResult(
          ProviderDiscoveryStatus::InvalidResponse,
          "Provider response exceeds the size limit.",
          response.http_status);
    case HttpResponseStatus::InvalidRequest:
      return MakeResult(
          ProviderDiscoveryStatus::InvalidResponse,
          "Provider request configuration is invalid.");
  }
  return MakeResult(
      ProviderDiscoveryStatus::InvalidResponse,
      "Provider response processing failed.");
}

} // namespace

std::optional<ProviderListModelsRequest> BuildListModelsRequest(
    const ProviderProfileDraft &profile)
{
  const std::optional<ProviderRequestParts> parts =
      BuildProviderRequestParts(profile, false);
  if ( !parts.has_value() )
    return std::nullopt;

  ProviderListModelsRequest request;
  request.protocol = parts->settings.protocol;
  request.url = parts->settings.base_url + "/models";
  request.user_agent = parts->user_agent;
  request.headers = parts->headers;
  request.proxy = parts->proxy;
  return request;
}

std::optional<HttpRequest> ToHttpRequest(
    const ProviderListModelsRequest &request)
{
  HttpRequest http_request;
  http_request.method = HttpMethod::Get;
  http_request.url = request.url;
  http_request.user_agent = request.user_agent;
  http_request.max_response_bytes = MaxProviderResponseBytes;
  http_request.headers.reserve(request.headers.size());
  for ( const ProviderHeaderDraft &header : request.headers )
    http_request.headers.push_back(HttpHeader{header.name, header.value});

  const std::optional<HttpProxyConfig> proxy =
      BuildHttpProxyConfig(request.proxy);
  if ( !proxy.has_value() )
    return std::nullopt;
  http_request.proxy = *proxy;
  if ( ValidateHttpRequest(http_request).has_value() )
    return std::nullopt;
  return http_request;
}

std::string FormatHttpProxyEndpoint(const ProviderProxyDraft &proxy)
{
  ProviderProxyDraft normalized = proxy;
  NormalizeProviderProxyDraft(normalized);
  if ( normalized.mode != ProviderProxyMode::Http
      || !IsValidProviderProxyDraft(normalized) )
  {
    return {};
  }
  const bool ipv6 = normalized.host.find(':') != std::string::npos;
  return (ipv6 ? "[" + normalized.host + "]" : normalized.host)
      + ":" + std::to_string(normalized.port);
}

ProviderDiscoveryResult ParseListModelsResponse(
    ProviderProtocol protocol,
    std::uint32_t http_status,
    std::string_view response_body)
{
  if ( http_status == 404 || http_status == 405 || http_status == 501 )
  {
    return MakeResult(
        ProviderDiscoveryStatus::ReachableButModelDiscoveryUnsupported,
        "Provider is reachable but does not support model discovery.",
        http_status);
  }
  if ( http_status < 200 || http_status >= 300 )
  {
    return MakeResult(
        ProviderDiscoveryStatus::HttpError,
        "Provider returned HTTP status " + std::to_string(http_status) + ".",
        http_status);
  }
  if ( protocol != ProviderProtocol::OpenAI && protocol != ProviderProtocol::Claude )
  {
    return MakeResult(
        ProviderDiscoveryStatus::InvalidResponse,
        "Provider response protocol is invalid.",
        http_status);
  }
  if ( response_body.size() > MaxProviderResponseBytes )
  {
    return MakeResult(
        ProviderDiscoveryStatus::InvalidResponse,
        "Provider response exceeds the size limit.",
        http_status);
  }

  const nlohmann::json document = nlohmann::json::parse(
      response_body.begin(),
      response_body.end(),
      nullptr,
      false);
  if ( document.is_discarded()
      || !document.is_object()
      || !document.contains("data")
      || !document.at("data").is_array() )
  {
    return MakeResult(
        ProviderDiscoveryStatus::InvalidResponse,
        "Provider returned an invalid model list response.",
        http_status);
  }

  std::set<std::string> model_ids;
  for ( const nlohmann::json &item : document.at("data") )
  {
    if ( !item.is_object()
        || !item.contains("id")
        || !item.at("id").is_string() )
    {
      return MakeResult(
          ProviderDiscoveryStatus::InvalidResponse,
          "Provider returned an invalid model entry.",
          http_status);
    }
    std::string id = item.at("id").get<std::string>();
    TrimSpaces(id);
    if ( id.empty()
        || id.size() > MaxModelIdLength
        || HasControlCharacter(id) )
    {
      return MakeResult(
          ProviderDiscoveryStatus::InvalidResponse,
          "Provider returned an invalid model identifier.",
          http_status);
    }
    model_ids.insert(std::move(id));
    if ( model_ids.size() > MaxDiscoveredProviderModels )
    {
      return MakeResult(
          ProviderDiscoveryStatus::InvalidResponse,
          "Provider returned too many models.",
          http_status);
    }
  }

  ProviderDiscoveryResult result = MakeResult(
      ProviderDiscoveryStatus::Success,
      "Model discovery succeeded.",
      http_status);
  result.models.reserve(model_ids.size());
  for ( const std::string &id : model_ids )
  {
    result.models.push_back(ProviderModelDraft{
        id,
        true,
        "",
        DefaultModelContextLength,
        DefaultModelMaxOutputTokens});
  }
  return result;
}

struct ProviderClient::Impl final
{
  Impl()
      : owned_http_client_(std::make_unique<HttpClient>()),
        http_client_(owned_http_client_.get())
  {
  }

  explicit Impl(HttpClient &http_client) : http_client_(&http_client) {}

  ~Impl()
  {
    Shutdown();
  }

  RequestId SubmitListModels(const ProviderProfileDraft &profile)
  {
    const std::optional<ProviderListModelsRequest> provider_request =
        BuildListModelsRequest(profile);
    std::optional<HttpRequest> http_request;
    if ( provider_request.has_value() )
      http_request = ToHttpRequest(*provider_request);

    const ProviderProtocol protocol = provider_request.has_value()
        ? provider_request->protocol
        : profile.settings.protocol;
    const RequestId request_id = http_client_->Submit(
        http_request.has_value() ? std::move(*http_request) : HttpRequest{});

    bool cancel = false;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      pending_.emplace(request_id, protocol);
      cancel = stopping_;
    }
    if ( cancel )
      http_client_->Cancel(request_id);
    return request_id;
  }

  std::optional<ProviderDiscoveryResult> TryTakeResult(RequestId request_id)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto pending = pending_.find(request_id);
    if ( pending == pending_.end() )
      return std::nullopt;
    std::optional<HttpResponse> response = http_client_->TryTakeResult(request_id);
    if ( !response.has_value() )
      return std::nullopt;
    const ProviderProtocol protocol = pending->second;
    pending_.erase(pending);
    return MapHttpResponse(protocol, std::move(*response));
  }

  void Cancel(RequestId request_id)
  {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if ( pending_.find(request_id) == pending_.end() )
        return;
    }
    http_client_->Cancel(request_id);
  }

  void CancelAndForget(RequestId request_id)
  {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      pending_.erase(request_id);
    }
    http_client_->CancelAndForget(request_id);
  }

  void Shutdown()
  {
    std::vector<RequestId> pending_ids;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if ( stopping_ )
        return;
      stopping_ = true;
      pending_ids.reserve(pending_.size());
      for ( const auto &entry : pending_ )
        pending_ids.push_back(entry.first);
    }
    for ( const RequestId request_id : pending_ids )
      http_client_->Cancel(request_id);
    if ( owned_http_client_ != nullptr )
      owned_http_client_->Shutdown();
  }

  std::unique_ptr<HttpClient> owned_http_client_;
  HttpClient *http_client_ = nullptr;
  std::mutex mutex_;
  std::unordered_map<RequestId, ProviderProtocol> pending_;
  bool stopping_ = false;
};

ProviderClient::ProviderClient() : impl_(std::make_unique<Impl>()) {}

ProviderClient::ProviderClient(HttpClient &http_client)
    : impl_(std::make_unique<Impl>(http_client))
{
}

ProviderClient::~ProviderClient()
{
  Shutdown();
}

ProviderClient::RequestId ProviderClient::SubmitListModels(
    const ProviderProfileDraft &profile)
{
  return impl_->SubmitListModels(profile);
}

std::optional<ProviderDiscoveryResult> ProviderClient::TryTakeResult(
    RequestId request_id)
{
  return impl_->TryTakeResult(request_id);
}

void ProviderClient::Cancel(RequestId request_id)
{
  impl_->Cancel(request_id);
}

void ProviderClient::CancelAndForget(RequestId request_id)
{
  impl_->CancelAndForget(request_id);
}

void ProviderClient::Shutdown()
{
  if ( impl_ != nullptr )
    impl_->Shutdown();
}

} // namespace ida_agent::ai
