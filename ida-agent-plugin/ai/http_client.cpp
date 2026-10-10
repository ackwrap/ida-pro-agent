#include "http_client_internal.hpp"
#include "ai/http_client.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winhttp.h>

#elif defined(__APPLE__)
#include "ai/macos_url_session.hpp"
#include "ai/utf8.hpp"
#else
#include "ai/url_linux.hpp"
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <limits>
#include <mutex>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace ida_agent::ai
{
namespace http_detail
{

constexpr std::size_t MaxHeaders = 256;

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

bool HasWhitespace(std::string_view value)
{
  return std::any_of(
      value.begin(),
      value.end(),
      [](unsigned char character)
      {
        return character == ' ' || character == '\t' || character == '\n'
            || character == '\r' || character == '\f' || character == '\v';
      });
}

bool IsHttpToken(std::string_view value)
{
  if ( value.empty() )
    return false;
  return std::all_of(
      value.begin(),
      value.end(),
      [](unsigned char character)
      {
        const bool alpha_numeric = (character >= 'a' && character <= 'z')
            || (character >= 'A' && character <= 'Z')
            || (character >= '0' && character <= '9');
        constexpr std::string_view punctuation = "!#$%&'*+-.^_`|~";
        return alpha_numeric
            || punctuation.find(static_cast<char>(character)) != std::string_view::npos;
      });
}

std::string LowerAscii(std::string_view value)
{
  std::string lowered(value);
  std::transform(
      lowered.begin(),
      lowered.end(),
      lowered.begin(),
      [](unsigned char character)
      {
        return character >= 'A' && character <= 'Z'
            ? static_cast<char>(character - 'A' + 'a')
            : static_cast<char>(character);
      });
  return lowered;
}

bool IsForbiddenHeader(std::string_view name)
{
  constexpr std::array<std::string_view, 5> forbidden{{
      "host",
      "content-length",
      "transfer-encoding",
      "connection",
      "proxy-authorization",
  }};
  const std::string lowered = LowerAscii(name);
  return std::find(forbidden.begin(), forbidden.end(), lowered) != forbidden.end();
}

#ifdef _WIN32
std::wstring Utf8ToWide(std::string_view value)
{
  if ( value.empty()
      || value.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()) )
  {
    return {};
  }
  const int input_size = static_cast<int>(value.size());
  const int output_size = MultiByteToWideChar(
      CP_UTF8,
      MB_ERR_INVALID_CHARS,
      value.data(),
      input_size,
      nullptr,
      0);
  if ( output_size <= 0 )
    return {};
  std::wstring converted(static_cast<std::size_t>(output_size), L'\0');
  if ( MultiByteToWideChar(
           CP_UTF8,
           MB_ERR_INVALID_CHARS,
           value.data(),
           input_size,
           converted.data(),
           output_size)
      != output_size )
  {
    return {};
  }
  return converted;
}

#endif

bool ValidNetworkText(std::string_view text)
{
#ifdef _WIN32
  return !Utf8ToWide(text).empty();
#else
  return !text.empty() && ValidUtf8(text);
#endif
}

bool IsValidProxyHost(std::string_view host)
{
  return !host.empty()
      && !HasControlCharacter(host)
      && !HasWhitespace(host)
      && host.find('/') == std::string_view::npos
      && host.find('\\') == std::string_view::npos
      && host.find('@') == std::string_view::npos
      && host.find('[') == std::string_view::npos
      && host.find(']') == std::string_view::npos;
}

#ifdef _WIN32
std::wstring FormatProxyEndpoint(const HttpProxyConfig &proxy)
{
  const bool ipv6 = proxy.host.find(':') != std::string::npos;
  return Utf8ToWide(
      (ipv6 ? "[" + proxy.host + "]" : proxy.host)
      + ":" + std::to_string(proxy.port));
}

#endif

HttpResponse MakeResponse(
    HttpResponseStatus status,
    std::string message,
    std::uint32_t http_status)
{
  HttpResponse response;
  response.status = status;
  response.http_status = http_status;
  response.message = std::move(message);
  return response;
}

HttpResponse CancelledResponse()
{
  return MakeResponse(HttpResponseStatus::Cancelled, "HTTP request was cancelled.");
}

HttpResponse NetworkError(std::string_view operation)
{
  return MakeResponse(
      HttpResponseStatus::NetworkError,
      "HTTP request failed during " + std::string(operation) + ".");
}


} // namespace http_detail

using namespace http_detail;

std::optional<std::string> ValidateHttpRequest(const HttpRequest &request)
{
  if ( request.method != HttpMethod::Get && request.method != HttpMethod::Post )
    return "HTTP request method is invalid.";
  if ( request.method == HttpMethod::Get && !request.body.empty() )
    return "HTTP GET request body is invalid.";
  if ( request.body.size() > static_cast<std::size_t>((std::numeric_limits<std::uint32_t>::max)()) )
    return "HTTP request body is too large.";
  if ( request.user_agent.empty()
      || HasControlCharacter(request.user_agent)
      || !ValidNetworkText(request.user_agent) )
  {
    return "HTTP request user agent is invalid.";
  }
  if ( request.url.empty()
      || request.url.find('#') != std::string::npos
      || request.url.size() > static_cast<std::size_t>((std::numeric_limits<std::uint32_t>::max)()) )
  {
    return "HTTP request URL is invalid.";
  }

#ifdef _WIN32
  const std::wstring wide_url = Utf8ToWide(request.url);
  URL_COMPONENTS components{};
  components.dwStructSize = sizeof(components);
  components.dwSchemeLength = static_cast<DWORD>(-1);
  components.dwHostNameLength = static_cast<DWORD>(-1);
  components.dwUserNameLength = static_cast<DWORD>(-1);
  components.dwPasswordLength = static_cast<DWORD>(-1);
  if ( wide_url.empty()
      || !WinHttpCrackUrl(
          wide_url.c_str(),
          static_cast<DWORD>(wide_url.size()),
          0,
          &components)
      || components.dwHostNameLength == 0
      || components.dwUserNameLength != 0
      || components.dwPasswordLength != 0
      || (components.nScheme != INTERNET_SCHEME_HTTP
          && components.nScheme != INTERNET_SCHEME_HTTPS) )
  {
    return "HTTP request URL is invalid.";
  }

#else
#ifdef __APPLE__
  if (!ValidMacHttpUrl(request.url)) return "HTTP request URL is invalid.";
#else
  if (!ValidLinuxHttpUrl(request.url)) return "HTTP request URL is invalid.";
#endif
#endif

  if ( request.headers.size() > MaxHeaders )
    return "HTTP request has too many headers.";
  for ( const HttpHeader &header : request.headers )
  {
    if ( !IsHttpToken(header.name)
        || IsForbiddenHeader(header.name)
        || HasControlCharacter(header.value)
        || !ValidNetworkText(header.name)
        || (!header.value.empty() && !ValidNetworkText(header.value)) )
    {
      return "HTTP request headers are invalid.";
    }
  }

  constexpr std::uint32_t MaxTimeoutMs = static_cast<std::uint32_t>((std::numeric_limits<int>::max)());
  if ( request.connect_timeout_ms == 0
      || request.send_timeout_ms == 0
      || request.receive_timeout_ms == 0
      || request.connect_timeout_ms > MaxTimeoutMs
      || request.send_timeout_ms > MaxTimeoutMs
      || request.receive_timeout_ms > MaxTimeoutMs )
  {
    return "HTTP request timeout is invalid.";
  }
  if ( request.max_response_bytes == 0
      || request.max_response_bytes > HttpHardMaxResponseBytes )
  {
    return "HTTP response size limit is invalid.";
  }

  if ( request.proxy.mode == HttpProxyMode::System
      || request.proxy.mode == HttpProxyMode::Direct )
  {
    if ( !request.proxy.host.empty()
        || request.proxy.port != 0
        || !request.proxy.username.empty()
        || !request.proxy.password.empty() )
    {
      return "HTTP proxy configuration is invalid.";
    }
  }
  else if ( request.proxy.mode == HttpProxyMode::Http )
  {
    if ( !IsValidProxyHost(request.proxy.host)
        || request.proxy.port == 0
        || (!request.proxy.password.empty() && request.proxy.username.empty())
        || HasControlCharacter(request.proxy.username)
        || HasControlCharacter(request.proxy.password)
        || (!request.proxy.username.empty() && !ValidNetworkText(request.proxy.username))
        || (!request.proxy.password.empty() && !ValidNetworkText(request.proxy.password))
        || !ValidNetworkText(request.proxy.host) )
    {
      return "HTTP proxy configuration is invalid.";
    }
  }
  else
  {
    return "HTTP proxy configuration is invalid.";
  }
  return std::nullopt;
}

struct HttpClient::Impl final
{
  struct WorkItem
  {
    RequestId request_id = 0;
    HttpRequest request;
  };

  Impl() : worker_([this] { WorkerMain(); }) {}
  ~Impl() { Shutdown(); }

  RequestId Submit(HttpRequest request)
  {
    const std::optional<std::string> validation_error = ValidateHttpRequest(request);
    std::lock_guard<std::mutex> lock(mutex_);
    const RequestId request_id = NextRequestId();
    if ( validation_error.has_value() )
    {
      results_.emplace(
          request_id,
          MakeResponse(HttpResponseStatus::InvalidRequest, *validation_error));
    }
    else if ( stopping_ )
    {
      results_.emplace(request_id, CancelledResponse());
    }
    else
    {
      queue_.push_back(WorkItem{request_id, std::move(request)});
      ready_.notify_one();
    }
    return request_id;
  }

  std::optional<HttpResponse> TryTakeResult(RequestId request_id)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto found = results_.find(request_id);
    if ( found == results_.end() )
      return std::nullopt;
    HttpResponse response = std::move(found->second);
    results_.erase(found);
    return response;
  }

  void Cancel(RequestId request_id)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if ( stopping_ || results_.find(request_id) != results_.end() )
      return;
    const auto queued = std::find_if(
        queue_.begin(),
        queue_.end(),
        [request_id](const WorkItem &item)
        {
          return item.request_id == request_id;
        });
    if ( queued != queue_.end() )
    {
      queue_.erase(queued);
      results_.emplace(request_id, CancelledResponse());
      return;
    }
    if ( active_request_id_ == request_id )
    {
      cancelled_.insert(request_id);
#ifdef _WIN32
      CancelSynchronousIo(worker_.native_handle());
#endif
    }
  }

  void CancelAndForget(RequestId request_id)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    results_.erase(request_id);
    const auto queued = std::find_if(
        queue_.begin(),
        queue_.end(),
        [request_id](const WorkItem &item)
        {
          return item.request_id == request_id;
        });
    if ( queued != queue_.end() )
    {
      queue_.erase(queued);
      return;
    }
    if ( active_request_id_ == request_id )
    {
      abandoned_.insert(request_id);
      cancelled_.insert(request_id);
#ifdef _WIN32
      CancelSynchronousIo(worker_.native_handle());
#endif
    }
  }

  void Shutdown()
  {
    std::lock_guard<std::mutex> shutdown_lock(shutdown_mutex_);
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if ( !stopping_ )
      {
        stopping_ = true;
        for ( const WorkItem &item : queue_ )
          results_.emplace(item.request_id, CancelledResponse());
        queue_.clear();
        if ( active_request_id_ != 0 )
        {
          cancelled_.insert(active_request_id_);
#ifdef _WIN32
          CancelSynchronousIo(worker_.native_handle());
#endif
        }
        ready_.notify_all();
      }
    }
    if ( worker_.joinable() )
      worker_.join();
  }

#ifdef IDA_AGENT_HTTP_CLIENT_TESTING
  void PauseWorkerForTesting()
  {
    std::lock_guard<std::mutex> lock(mutex_);
    worker_paused_ = true;
  }
#endif

private:
  RequestId NextRequestId()
  {
    RequestId request_id = next_request_id_++;
    if ( request_id == 0 )
      request_id = next_request_id_++;
    return request_id;
  }

  bool IsCancelled(RequestId request_id)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    return stopping_ || cancelled_.find(request_id) != cancelled_.end();
  }

  void WorkerMain()
  {
    while ( true )
    {
      WorkItem item;
      {
        std::unique_lock<std::mutex> lock(mutex_);
        ready_.wait(lock, [this]
        {
#ifdef IDA_AGENT_HTTP_CLIENT_TESTING
          return stopping_ || (!worker_paused_ && !queue_.empty());
#else
          return stopping_ || !queue_.empty();
#endif
        });
        if ( stopping_ && queue_.empty() )
          return;
        item = std::move(queue_.front());
        queue_.pop_front();
        active_request_id_ = item.request_id;
      }

      HttpResponse response;
      try
      {
#ifdef _WIN32
        response = ExecuteWinHttp(
#elif defined(__APPLE__)
        response = ExecuteMacHttp(
#else
        response = ExecuteCurlHttp(
#endif
            item.request,
            [this, request_id = item.request_id]
            {
              return IsCancelled(request_id);
            });
      }
      catch ( ... )
      {
        response = NetworkError("response processing");
      }

      {
        std::lock_guard<std::mutex> lock(mutex_);
        const bool cancelled = cancelled_.erase(item.request_id) != 0;
        const bool abandoned = abandoned_.erase(item.request_id) != 0;
        if ( stopping_ || cancelled )
          response = CancelledResponse();
        active_request_id_ = 0;
        if ( !abandoned )
          results_.emplace(item.request_id, std::move(response));
      }
    }
  }

  std::mutex mutex_;
  std::mutex shutdown_mutex_;
  std::condition_variable ready_;
  std::deque<WorkItem> queue_;
  std::unordered_map<RequestId, HttpResponse> results_;
  std::unordered_set<RequestId> cancelled_;
  std::unordered_set<RequestId> abandoned_;
  RequestId next_request_id_ = 1;
  RequestId active_request_id_ = 0;
  bool stopping_ = false;
#ifdef IDA_AGENT_HTTP_CLIENT_TESTING
  bool worker_paused_ = false;
#endif
  std::thread worker_;
};

HttpClient::HttpClient() : impl_(std::make_unique<Impl>()) {}

HttpClient::~HttpClient()
{
  Shutdown();
}

HttpClient::RequestId HttpClient::Submit(HttpRequest request)
{
  return impl_->Submit(std::move(request));
}

std::optional<HttpResponse> HttpClient::TryTakeResult(RequestId request_id)
{
  return impl_->TryTakeResult(request_id);
}

void HttpClient::Cancel(RequestId request_id)
{
  impl_->Cancel(request_id);
}

void HttpClient::CancelAndForget(RequestId request_id)
{
  impl_->CancelAndForget(request_id);
}

#ifdef IDA_AGENT_HTTP_CLIENT_TESTING
void HttpClient::PauseWorkerForTesting()
{
  impl_->PauseWorkerForTesting();
}
#endif

void HttpClient::Shutdown()
{
  if ( impl_ != nullptr )
    impl_->Shutdown();
}

} // namespace ida_agent::ai
