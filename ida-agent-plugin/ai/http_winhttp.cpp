#include "ai/http_client.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winhttp.h>

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

#include "http_client_internal.hpp"

namespace ida_agent::ai::http_detail
{
DWORD SelectProxyAuthScheme(DWORD supported_schemes)
{
  for ( const DWORD scheme : {
            WINHTTP_AUTH_SCHEME_NEGOTIATE,
            WINHTTP_AUTH_SCHEME_NTLM,
            WINHTTP_AUTH_SCHEME_DIGEST,
            WINHTTP_AUTH_SCHEME_BASIC} )
  {
    if ( (supported_schemes & scheme) != 0 )
      return scheme;
  }
  return 0;
}

class InternetHandle final
{
public:
  explicit InternetHandle(HINTERNET handle = nullptr) : handle_(handle) {}
  ~InternetHandle()
  {
    if ( handle_ != nullptr )
      WinHttpCloseHandle(handle_);
  }

  InternetHandle(const InternetHandle &) = delete;
  InternetHandle &operator=(const InternetHandle &) = delete;

  HINTERNET get() const noexcept { return handle_; }
  explicit operator bool() const noexcept { return handle_ != nullptr; }
  void reset(HINTERNET replacement = nullptr) noexcept
  {
    if ( handle_ != nullptr )
      WinHttpCloseHandle(handle_);
    handle_ = replacement;
  }

private:
  HINTERNET handle_ = nullptr;
};

enum class AsyncCompletion : unsigned char
{
  None,
  SendComplete,
  HeadersAvailable,
  DataAvailable,
  ReadComplete,
  Error,
};

struct AsyncWinHttpState final
{
  AsyncWinHttpState() : event(CreateEventW(nullptr, FALSE, FALSE, nullptr)) {}

  void AddRef() noexcept { references.fetch_add(1, std::memory_order_relaxed); }
  void Release() noexcept
  {
    if ( references.fetch_sub(1, std::memory_order_acq_rel) == 1 )
      delete this;
  }
  void Begin() noexcept
  {
    error.store(ERROR_SUCCESS, std::memory_order_relaxed);
    value.store(0, std::memory_order_relaxed);
    completion.store(AsyncCompletion::None, std::memory_order_release);
  }

  std::atomic<unsigned long> references{1};
  HANDLE event = nullptr;
  std::atomic<AsyncCompletion> completion{AsyncCompletion::None};
  std::atomic<DWORD> error{ERROR_SUCCESS};
  std::atomic<DWORD> value{0};
  std::string request_body;
  std::array<char, 16 * 1024> read_buffer{};

private:
  ~AsyncWinHttpState()
  {
    if ( event != nullptr )
      CloseHandle(event);
  }
};

class AsyncStateOwner final
{
public:
  AsyncStateOwner() : state_(new AsyncWinHttpState) {}
  ~AsyncStateOwner() { state_->Release(); }
  AsyncWinHttpState *get() const noexcept { return state_; }

private:
  AsyncWinHttpState *state_ = nullptr;
};

void CALLBACK WinHttpStatusCallback(
    HINTERNET,
    DWORD_PTR context,
    DWORD status,
    void *status_information,
    DWORD status_information_length)
{
  auto *state = reinterpret_cast<AsyncWinHttpState *>(context);
  if ( state == nullptr )
    return;

  AsyncCompletion completion = AsyncCompletion::None;
  switch ( status )
  {
    case WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE:
      completion = AsyncCompletion::SendComplete;
      break;
    case WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE:
      completion = AsyncCompletion::HeadersAvailable;
      break;
    case WINHTTP_CALLBACK_STATUS_DATA_AVAILABLE:
      if ( status_information != nullptr
          && status_information_length == sizeof(DWORD) )
      {
        state->value.store(
            *static_cast<const DWORD *>(status_information),
            std::memory_order_relaxed);
      }
      completion = AsyncCompletion::DataAvailable;
      break;
    case WINHTTP_CALLBACK_STATUS_READ_COMPLETE:
      state->value.store(status_information_length, std::memory_order_relaxed);
      completion = AsyncCompletion::ReadComplete;
      break;
    case WINHTTP_CALLBACK_STATUS_REQUEST_ERROR:
      if ( status_information != nullptr
          && status_information_length == sizeof(WINHTTP_ASYNC_RESULT) )
      {
        state->error.store(
            static_cast<const WINHTTP_ASYNC_RESULT *>(status_information)->dwError,
            std::memory_order_relaxed);
      }
      completion = AsyncCompletion::Error;
      break;
    case WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING:
      state->Release();
      return;
    default:
      return;
  }
  state->completion.store(completion, std::memory_order_release);
  SetEvent(state->event);
}

enum class AsyncWaitResult
{
  Completed,
  Failed,
  Cancelled,
};

template <typename IsCancelled>
AsyncWaitResult WaitForAsyncCompletion(
    AsyncWinHttpState &state,
    AsyncCompletion expected,
    InternetHandle &request,
    IsCancelled is_cancelled,
    DWORD &error)
{
  while ( true )
  {
    if ( is_cancelled() )
    {
      request.reset();
      return AsyncWaitResult::Cancelled;
    }
    const DWORD wait = WaitForSingleObject(state.event, 25);
    if ( wait == WAIT_TIMEOUT )
      continue;
    if ( wait != WAIT_OBJECT_0 )
    {
      error = GetLastError();
      return AsyncWaitResult::Failed;
    }
    const AsyncCompletion completion = state.completion.load(std::memory_order_acquire);
    if ( completion == expected )
      return AsyncWaitResult::Completed;
    if ( completion == AsyncCompletion::Error )
    {
      error = state.error.load(std::memory_order_relaxed);
      return AsyncWaitResult::Failed;
    }
  }
}

bool AsyncOperationStarted(BOOL result, DWORD &error)
{
  if ( result )
    return true;
  error = GetLastError();
  return error == ERROR_IO_PENDING;
}

HttpResponse ExecuteWinHttp(const HttpRequest &request, const std::function<bool()> &is_cancelled)
{
  const auto cancelled_or_network_error = [&](std::string_view operation, DWORD error)
  {
    return is_cancelled() || error == ERROR_OPERATION_ABORTED
        ? CancelledResponse()
        : NetworkError(operation);
  };

  if ( is_cancelled() )
    return CancelledResponse();

  const std::wstring wide_url = Utf8ToWide(request.url);
  const std::wstring wide_user_agent = Utf8ToWide(request.user_agent);
  URL_COMPONENTS components{};
  components.dwStructSize = sizeof(components);
  components.dwSchemeLength = static_cast<DWORD>(-1);
  components.dwHostNameLength = static_cast<DWORD>(-1);
  components.dwUrlPathLength = static_cast<DWORD>(-1);
  components.dwExtraInfoLength = static_cast<DWORD>(-1);
  if ( wide_url.empty()
      || wide_user_agent.empty()
      || !WinHttpCrackUrl(
          wide_url.c_str(),
          static_cast<DWORD>(wide_url.size()),
          0,
          &components) )
  {
    return MakeResponse(HttpResponseStatus::InvalidRequest, "HTTP request URL is invalid.");
  }

  const std::wstring host(
      components.lpszHostName,
      static_cast<std::size_t>(components.dwHostNameLength));
  std::wstring path(
      components.lpszUrlPath,
      static_cast<std::size_t>(components.dwUrlPathLength));
  if ( components.dwExtraInfoLength != 0 )
  {
    path.append(
        components.lpszExtraInfo,
        static_cast<std::size_t>(components.dwExtraInfoLength));
  }
  if ( path.empty() )
    path = L"/";

  DWORD access_type = WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY;
  std::wstring proxy_name;
  std::wstring proxy_bypass;
  if ( request.proxy.mode == HttpProxyMode::Direct )
  {
    access_type = WINHTTP_ACCESS_TYPE_NO_PROXY;
  }
  else if ( request.proxy.mode == HttpProxyMode::Http )
  {
    access_type = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
    proxy_name = FormatProxyEndpoint(request.proxy);
    if ( request.proxy.bypass_local )
      proxy_bypass = L"<local>;localhost;127.*;[::1]";
  }

  const std::wstring proxy_username = request.proxy.username.empty()
      ? std::wstring{}
      : Utf8ToWide(request.proxy.username);
  const std::wstring proxy_password = request.proxy.password.empty()
      ? std::wstring{}
      : Utf8ToWide(request.proxy.password);

  InternetHandle session(WinHttpOpen(
      wide_user_agent.c_str(),
      access_type,
      proxy_name.empty() ? WINHTTP_NO_PROXY_NAME : proxy_name.c_str(),
      proxy_bypass.empty() ? WINHTTP_NO_PROXY_BYPASS : proxy_bypass.c_str(),
      WINHTTP_FLAG_ASYNC));
  if ( !session )
    return cancelled_or_network_error("session setup", GetLastError());
  if ( !WinHttpSetTimeouts(
           session.get(),
           static_cast<int>(request.connect_timeout_ms),
           static_cast<int>(request.connect_timeout_ms),
           static_cast<int>(request.send_timeout_ms),
           static_cast<int>(request.receive_timeout_ms)) )
  {
    return cancelled_or_network_error("timeout setup", GetLastError());
  }

  InternetHandle connection(WinHttpConnect(
      session.get(),
      host.c_str(),
      components.nPort,
      0));
  if ( !connection )
    return cancelled_or_network_error("connection setup", GetLastError());

  const wchar_t *method = request.method == HttpMethod::Post ? L"POST" : L"GET";
  const DWORD request_flags = components.nScheme == INTERNET_SCHEME_HTTPS
      ? WINHTTP_FLAG_SECURE
      : 0;
  AsyncStateOwner async_state_owner;
  AsyncWinHttpState *const async_state = async_state_owner.get();
  if ( async_state->event == nullptr )
    return NetworkError("request setup");
  async_state->request_body = request.body;
  InternetHandle http_request(WinHttpOpenRequest(
      connection.get(),
      method,
      path.c_str(),
      nullptr,
      WINHTTP_NO_REFERER,
      WINHTTP_DEFAULT_ACCEPT_TYPES,
      request_flags));
  if ( !http_request )
    return cancelled_or_network_error("request setup", GetLastError());

  DWORD_PTR callback_context = reinterpret_cast<DWORD_PTR>(async_state);
  if ( !WinHttpSetOption(
           http_request.get(),
           WINHTTP_OPTION_CONTEXT_VALUE,
           &callback_context,
           sizeof(callback_context))
      || WinHttpSetStatusCallback(
          http_request.get(),
          WinHttpStatusCallback,
          WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE
              | WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE
              | WINHTTP_CALLBACK_STATUS_DATA_AVAILABLE
              | WINHTTP_CALLBACK_STATUS_READ_COMPLETE
              | WINHTTP_CALLBACK_STATUS_REQUEST_ERROR
              | WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING,
          0) == WINHTTP_INVALID_STATUS_CALLBACK )
  {
    return cancelled_or_network_error("request callback setup", GetLastError());
  }
  async_state->AddRef();

  DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
  if ( !WinHttpSetOption(
           http_request.get(),
           WINHTTP_OPTION_REDIRECT_POLICY,
           &redirect_policy,
           sizeof(redirect_policy)) )
  {
    return cancelled_or_network_error("redirect setup", GetLastError());
  }

  for ( const HttpHeader &header : request.headers )
  {
    const std::wstring name = Utf8ToWide(header.name);
    const std::wstring value = header.value.empty()
        ? std::wstring{}
        : Utf8ToWide(header.value);
    const std::wstring line = name + L": " + value;
    if ( !WinHttpAddRequestHeaders(
             http_request.get(),
             line.c_str(),
             static_cast<DWORD>(line.size()),
             WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE) )
    {
      return cancelled_or_network_error("header setup", GetLastError());
    }
  }

  DWORD status_code = 0;
  for ( int attempt = 0; attempt < 2; ++attempt )
  {
    if ( is_cancelled() )
      return CancelledResponse();
    void *body = async_state->request_body.empty()
        ? WINHTTP_NO_REQUEST_DATA
        : async_state->request_body.data();
    const DWORD body_size = static_cast<DWORD>(async_state->request_body.size());
    DWORD async_error = ERROR_SUCCESS;
    async_state->Begin();
    if ( !AsyncOperationStarted(
             WinHttpSendRequest(
                 http_request.get(),
                 WINHTTP_NO_ADDITIONAL_HEADERS,
                 0,
                 body,
                 body_size,
                 body_size,
                 callback_context),
             async_error) )
    {
      return cancelled_or_network_error("send", async_error);
    }
    const AsyncWaitResult send_result = WaitForAsyncCompletion(
        *async_state,
        AsyncCompletion::SendComplete,
        http_request,
        is_cancelled,
        async_error);
    if ( send_result == AsyncWaitResult::Cancelled )
      return CancelledResponse();
    if ( send_result == AsyncWaitResult::Failed )
      return cancelled_or_network_error("send", async_error);

    async_state->Begin();
    if ( !AsyncOperationStarted(
             WinHttpReceiveResponse(http_request.get(), nullptr),
             async_error) )
    {
      return cancelled_or_network_error("receive", async_error);
    }
    const AsyncWaitResult receive_result = WaitForAsyncCompletion(
        *async_state,
        AsyncCompletion::HeadersAvailable,
        http_request,
        is_cancelled,
        async_error);
    if ( receive_result == AsyncWaitResult::Cancelled )
      return CancelledResponse();
    if ( receive_result == AsyncWaitResult::Failed )
      return cancelled_or_network_error("receive", async_error);

    DWORD status_size = sizeof(status_code);
    if ( !WinHttpQueryHeaders(
             http_request.get(),
             WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
             WINHTTP_HEADER_NAME_BY_INDEX,
             &status_code,
             &status_size,
             WINHTTP_NO_HEADER_INDEX) )
    {
      return cancelled_or_network_error("status read", GetLastError());
    }
    if ( status_code != 407 || attempt != 0 || proxy_username.empty() )
      break;

    DWORD supported_schemes = 0;
    DWORD first_scheme = 0;
    DWORD authentication_target = 0;
    if ( !WinHttpQueryAuthSchemes(
             http_request.get(),
             &supported_schemes,
             &first_scheme,
             &authentication_target)
        || authentication_target != WINHTTP_AUTH_TARGET_PROXY )
    {
      break;
    }
    const DWORD selected_scheme = SelectProxyAuthScheme(supported_schemes);
    if ( selected_scheme == 0 )
      break;
    if ( !WinHttpSetCredentials(
             http_request.get(),
             WINHTTP_AUTH_TARGET_PROXY,
             selected_scheme,
             proxy_username.c_str(),
             proxy_password.c_str(),
             nullptr) )
    {
      return cancelled_or_network_error(
          "proxy authentication setup",
          GetLastError());
    }
  }

  HttpResponse response = MakeResponse(
      HttpResponseStatus::Success,
      "HTTP request completed.",
      status_code);
  response.body.reserve((std::min)(request.max_response_bytes, std::size_t{16 * 1024}));
  while ( true )
  {
    if ( is_cancelled() )
      return CancelledResponse();
    DWORD async_error = ERROR_SUCCESS;
    async_state->Begin();
    if ( !AsyncOperationStarted(
             WinHttpQueryDataAvailable(http_request.get(), nullptr),
             async_error) )
    {
      return cancelled_or_network_error("response read", async_error);
    }
    const AsyncWaitResult available_result = WaitForAsyncCompletion(
        *async_state,
        AsyncCompletion::DataAvailable,
        http_request,
        is_cancelled,
        async_error);
    if ( available_result == AsyncWaitResult::Cancelled )
      return CancelledResponse();
    if ( available_result == AsyncWaitResult::Failed )
      return cancelled_or_network_error("response read", async_error);
    const DWORD available = async_state->value.load(std::memory_order_relaxed);
    if ( available == 0 )
      break;
    if ( available > request.max_response_bytes - response.body.size() )
    {
      return MakeResponse(
          HttpResponseStatus::ResponseTooLarge,
          "HTTP response exceeds the size limit.",
          status_code);
    }

    if ( is_cancelled() )
      return CancelledResponse();
    const DWORD requested = static_cast<DWORD>((std::min)(
        static_cast<std::size_t>(available),
        async_state->read_buffer.size()));
    async_state->Begin();
    if ( !AsyncOperationStarted(
             WinHttpReadData(
                 http_request.get(),
                 async_state->read_buffer.data(),
                 requested,
                 nullptr),
             async_error) )
    {
      return cancelled_or_network_error("response read", async_error);
    }
    const AsyncWaitResult read_result = WaitForAsyncCompletion(
        *async_state,
        AsyncCompletion::ReadComplete,
        http_request,
        is_cancelled,
        async_error);
    if ( read_result == AsyncWaitResult::Cancelled )
      return CancelledResponse();
    if ( read_result == AsyncWaitResult::Failed )
      return cancelled_or_network_error("response read", async_error);
    const DWORD downloaded = async_state->value.load(std::memory_order_relaxed);
    if ( downloaded == 0 )
      return NetworkError("response read");
    response.body.append(async_state->read_buffer.data(), downloaded);
  }
  return response;
}

}
