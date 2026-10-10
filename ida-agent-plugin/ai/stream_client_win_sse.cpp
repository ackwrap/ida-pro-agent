#include "ai/stream_client_win_internal.hpp"

#include "ai/network_diagnostics.hpp"
#include "ai/stream_client_win_async.hpp"
#include "ai/stream_client_win_sse_diagnostics.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <utility>
#include <vector>

namespace ida_agent::ai
{
namespace stream_client_win_internal
{

std::string LowerAscii(std::string_view value)
{
  std::string lowered(value);
  std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char character)
  {
    return character >= 'A' && character <= 'Z'
        ? static_cast<char>(character - 'A' + 'a')
        : static_cast<char>(character);
  });
  return lowered;
}

std::wstring FormatProxyEndpoint(const HttpProxyConfig &proxy)
{
  const bool ipv6 = proxy.host.find(':') != std::string::npos;
  return Utf8ToWide(
      (ipv6 ? "[" + proxy.host + "]" : proxy.host)
      + ":" + std::to_string(proxy.port));
}

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

namespace
{

bool HasSseContentType(HINTERNET request)
{
  DWORD bytes = 0;
  if ( WinHttpQueryHeaders(
           request,
           WINHTTP_QUERY_CONTENT_TYPE,
           WINHTTP_HEADER_NAME_BY_INDEX,
           nullptr,
           &bytes,
           WINHTTP_NO_HEADER_INDEX) )
  {
    return false;
  }
  if ( GetLastError() != ERROR_INSUFFICIENT_BUFFER
      || bytes == 0
      || bytes > (StreamHardMaxHeaderValueBytes + 1) * sizeof(wchar_t) )
  {
    return false;
  }
  std::vector<wchar_t> buffer(bytes / sizeof(wchar_t) + 1, L'\0');
  if ( !WinHttpQueryHeaders(
           request,
           WINHTTP_QUERY_CONTENT_TYPE,
           WINHTTP_HEADER_NAME_BY_INDEX,
           buffer.data(),
           &bytes,
           WINHTTP_NO_HEADER_INDEX) )
  {
    return false;
  }
  std::wstring_view value(buffer.data());
  const std::size_t semicolon = value.find(L';');
  value = value.substr(0, semicolon);
  while ( !value.empty() && (value.front() == L' ' || value.front() == L'\t') )
    value.remove_prefix(1);
  while ( !value.empty() && (value.back() == L' ' || value.back() == L'\t') )
    value.remove_suffix(1);
  constexpr std::wstring_view expected = L"text/event-stream";
  if ( value.size() != expected.size() )
    return false;
  for ( std::size_t index = 0; index < value.size(); ++index )
  {
    wchar_t character = value[index];
    if ( character >= L'A' && character <= L'Z' )
      character = static_cast<wchar_t>(character - L'A' + L'a');
    if ( character != expected[index] )
      return false;
  }
  return true;
}

} // namespace
} // namespace stream_client_win_internal

using namespace stream_client_win_internal;

bool StreamClient::Impl::AddHeaders(HINTERNET request_handle, const State &state)
{
  for ( const HttpHeader &header : state.request.headers )
  {
    const std::wstring name = Utf8ToWide(header.name);
    const std::wstring value = header.value.empty()
        ? std::wstring{}
        : Utf8ToWide(header.value);
    if ( name.empty() || (!header.value.empty() && value.empty()) )
      return false;
    const std::wstring line = name + L": " + value;
    if ( !WinHttpAddRequestHeaders(
             request_handle,
             line.c_str(),
             static_cast<DWORD>(line.size()),
             WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE) )
    {
      return false;
    }
  }
  if ( state.kind == StreamKind::Sse )
  {
    constexpr wchar_t fixed_headers[] =
        L"Accept: text/event-stream\r\nCache-Control: no-cache";
    if ( !WinHttpAddRequestHeaders(
             request_handle,
             fixed_headers,
             static_cast<DWORD>(-1),
             WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE) )
    {
      return false;
    }
  }
  return true;
}

bool StreamClient::Impl::OpenHttpRequest(
    State &state,
    RequestHandles &handles,
    const std::optional<std::chrono::steady_clock::time_point> &deadline,
    std::string &error)
{
  std::string mapped_url = state.request.url;
  if ( state.kind == StreamKind::WebSocket )
  {
    const std::string lowered_prefix = LowerAscii(
        mapped_url.substr(0, (std::min)(mapped_url.size(), std::size_t{6})));
    if ( lowered_prefix.rfind("wss://", 0) == 0 )
      mapped_url.replace(0, 6, "https://");
    else if ( lowered_prefix.rfind("ws://", 0) == 0 )
      mapped_url.replace(0, 5, "http://");
    else
    {
      error = "Stream request URL is invalid.";
      return false;
    }
  }
  const std::wstring wide_url = Utf8ToWide(mapped_url);
  const std::wstring wide_user_agent = Utf8ToWide(state.request.user_agent);
  URL_COMPONENTS components{};
  components.dwStructSize = sizeof(components);
  components.dwSchemeLength = static_cast<DWORD>(-1);
  components.dwHostNameLength = static_cast<DWORD>(-1);
  components.dwUrlPathLength = static_cast<DWORD>(-1);
  components.dwExtraInfoLength = static_cast<DWORD>(-1);
  if ( wide_url.empty() || wide_user_agent.empty()
      || !WinHttpCrackUrl(
          wide_url.c_str(),
          static_cast<DWORD>(wide_url.size()),
          0,
          &components) )
  {
    error = "Stream request URL is invalid.";
    return false;
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
  if ( state.request.proxy.mode == HttpProxyMode::Direct )
    access_type = WINHTTP_ACCESS_TYPE_NO_PROXY;
  else if ( state.request.proxy.mode == HttpProxyMode::Http )
  {
    access_type = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
    proxy_name = FormatProxyEndpoint(state.request.proxy);
    if ( state.request.proxy.bypass_local )
      proxy_bypass = L"<local>;localhost;127.*;[::1]";
  }

  handles.session.reset(WinHttpOpen(
      wide_user_agent.c_str(),
      access_type,
      proxy_name.empty() ? WINHTTP_NO_PROXY_NAME : proxy_name.c_str(),
      proxy_bypass.empty() ? WINHTTP_NO_PROXY_BYPASS : proxy_bypass.c_str(),
      state.kind == StreamKind::Sse ? WINHTTP_FLAG_ASYNC : 0));
  if ( !handles.session )
  {
    error = "Stream connection setup failed.";
    return false;
  }
  if ( !WinHttpSetTimeouts(
           handles.session.get(),
           static_cast<int>(state.request.connect_timeout_ms),
           static_cast<int>(state.request.connect_timeout_ms),
           static_cast<int>(state.request.send_timeout_ms),
           RemainingReceiveTimeout(state, deadline)) )
  {
    error = "Stream timeout setup failed.";
    return false;
  }
  handles.connection.reset(WinHttpConnect(
      handles.session.get(),
      host.c_str(),
      components.nPort,
      0));
  if ( !handles.connection )
  {
    error = "Stream connection setup failed.";
    return false;
  }
  const wchar_t *method = state.request.method == HttpMethod::Post ? L"POST" : L"GET";
  const DWORD flags = components.nScheme == INTERNET_SCHEME_HTTPS
      ? WINHTTP_FLAG_SECURE
      : 0;
  handles.request.reset(WinHttpOpenRequest(
      handles.connection.get(),
      method,
      path.c_str(),
      nullptr,
      WINHTTP_NO_REFERER,
      WINHTTP_DEFAULT_ACCEPT_TYPES,
      flags));
  if ( !handles.request )
  {
    error = "Stream request setup failed.";
    return false;
  }
  DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
  if ( !WinHttpSetOption(
           handles.request.get(),
           WINHTTP_OPTION_REDIRECT_POLICY,
           &redirect_policy,
           sizeof(redirect_policy)) )
  {
    error = "Stream redirect policy setup failed.";
    return false;
  }
  if ( state.kind == StreamKind::WebSocket
      && !WinHttpSetOption(
          handles.request.get(),
          WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET,
          nullptr,
          0) )
  {
    error = "WebSocket upgrade setup failed.";
    return false;
  }
  if ( !AddHeaders(handles.request.get(), state) )
  {
    error = "Stream header setup failed.";
    return false;
  }

  if ( state.kind == StreamKind::Sse )
  {
    handles.async = std::make_shared<WinHttpAsyncRequest>();
    if ( !handles.async->Attach(handles.request.get(), state.request.body, error) )
      return false;
  }
  const auto abort = [&]() -> std::optional<std::string>
  {
    if ( IsCancelled(state) || IsCloseRequested(state) )
      return "Stream operation was interrupted.";
    if ( DeadlineExpired(deadline) )
      return "Stream overall timeout expired.";
    return std::nullopt;
  };

  const std::wstring proxy_username = state.request.proxy.username.empty()
      ? std::wstring{}
      : Utf8ToWide(state.request.proxy.username);
  const std::wstring proxy_password = state.request.proxy.password.empty()
      ? std::wstring{}
      : Utf8ToWide(state.request.proxy.password);
  for ( int attempt = 0; attempt < 2; ++attempt )
  {
    if ( IsCancelled(state) || IsCloseRequested(state) )
    {
      error = "Stream operation was interrupted.";
      return false;
    }
    void *body = state.request.body.empty()
        ? WINHTTP_NO_REQUEST_DATA
        : const_cast<char *>(state.request.body.data());
    const DWORD body_size = static_cast<DWORD>(state.request.body.size());
    if ( handles.async != nullptr )
    {
      if ( !handles.async->Send(handles.request.get(), abort, error)
          || !handles.async->Receive(handles.request.get(), abort, error) )
        return false;
    }
    else if ( !WinHttpSendRequest(
             handles.request.get(),
             WINHTTP_NO_ADDITIONAL_HEADERS,
             0,
             body,
             body_size,
             body_size,
             0)
        || !WinHttpReceiveResponse(handles.request.get(), nullptr) )
    {
      error = DeadlineExpired(deadline)
          ? "Stream overall timeout expired."
          : "Stream handshake failed.";
      return false;
    }
    DWORD status_size = sizeof(handles.status_code);
    if ( !WinHttpQueryHeaders(
             handles.request.get(),
             WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
             WINHTTP_HEADER_NAME_BY_INDEX,
             &handles.status_code,
             &status_size,
             WINHTTP_NO_HEADER_INDEX) )
    {
      error = "Stream response status read failed.";
      return false;
    }
    if ( handles.status_code != 407 || attempt != 0 || proxy_username.empty() )
      break;
    DWORD supported_schemes = 0;
    DWORD first_scheme = 0;
    DWORD authentication_target = 0;
    if ( !WinHttpQueryAuthSchemes(
             handles.request.get(),
             &supported_schemes,
             &first_scheme,
             &authentication_target)
        || authentication_target != WINHTTP_AUTH_TARGET_PROXY )
    {
      break;
    }
    const DWORD selected_scheme = SelectProxyAuthScheme(supported_schemes);
    if ( selected_scheme == 0
        || !WinHttpSetCredentials(
            handles.request.get(),
            WINHTTP_AUTH_TARGET_PROXY,
            selected_scheme,
            proxy_username.c_str(),
            proxy_password.c_str(),
            nullptr) )
    {
      error = "Stream proxy authentication failed.";
      return false;
    }
  }
  return true;
}

std::string StreamClient::Impl::ReadErrorBody(
    State &state,
    RequestHandles &handles,
    const std::optional<std::chrono::steady_clock::time_point> &deadline)
{
  std::array<char, 16 * 1024> buffer{};
  std::string body;
  body.reserve(ErrorBodyReadLimit);
  const auto abort = [&]() -> std::optional<std::string>
  {
    if ( IsCancelled(state) )
      return "Stream was cancelled.";
    if ( DeadlineExpired(deadline) )
      return "Stream overall timeout expired.";
    return std::nullopt;
  };
  while ( true )
  {
    if ( IsCancelled(state) || DeadlineExpired(deadline) )
      return body;
    int receive_timeout = RemainingReceiveTimeout(state, deadline);
    WinHttpSetOption(
        handles.request.get(),
        WINHTTP_OPTION_RECEIVE_TIMEOUT,
        &receive_timeout,
        sizeof(receive_timeout));
    std::string_view bytes;
    std::string error;
    if ( handles.async != nullptr )
    {
      if ( !handles.async->Read(handles.request.get(), abort, bytes, error) )
        return body;
    }
    else
    {
      DWORD read = 0;
      if ( !WinHttpReadData(handles.request.get(), buffer.data(),
               static_cast<DWORD>(buffer.size()), &read) )
        return body;
      bytes = std::string_view(buffer.data(), read);
    }
    if ( bytes.empty() )
    {
      return body;
    }
    AppendAiNetworkResponseLog(
        state.id,
        bytes);
    const std::size_t retained = (std::min)(
        bytes.size(),
        ErrorBodyReadLimit - body.size());
    body.append(bytes.data(), retained);
  }
}

void StreamClient::Impl::RunSse(
    State &state,
    const std::optional<std::chrono::steady_clock::time_point> &deadline)
{
  SseTimeline timeline(state.id, state.request);
  RequestHandles handles;
  std::string error;
  if ( !OpenHttpRequest(state, handles, deadline, error) )
  {
    if ( IsCancelled(state) )
    {
      timeline.Terminal("cancelled", error);
      QueueTerminal(state, MakeControlEvent(StreamEventKind::Cancelled, "Stream was cancelled."));
    }
    else
    {
      timeline.Terminal("open_error", error);
      QueueTerminal(state, MakeControlEvent(StreamEventKind::Error, std::move(error)));
    }
    return;
  }
  StreamEvent opened;
  opened.kind = StreamEventKind::Opened;
  opened.http_status = handles.status_code;
  timeline.Status(handles.status_code);
  if ( !QueueEvent(state, std::move(opened)) )
  {
    timeline.Terminal("opened_queue_rejected", {}, handles.status_code);
    return;
  }
  if ( handles.status_code < 200 || handles.status_code >= 300 )
  {
    const std::string body = ReadErrorBody(
        state, handles, deadline);
    if ( IsCancelled(state) )
    {
      timeline.Terminal("cancelled");
      QueueTerminal(
          state,
          MakeControlEvent(StreamEventKind::Cancelled, "Stream was cancelled."));
      return;
    }
    if ( DeadlineExpired(deadline) )
    {
      timeline.Terminal("overall_timeout");
      QueueTerminal(
          state,
          MakeControlEvent(StreamEventKind::Error, "Stream overall timeout expired."));
      return;
    }
    std::string detail = SanitizeAiNetworkErrorBody(body);
    timeline.Terminal("http_error", detail, handles.status_code);
    StreamEvent rejected = MakeControlEvent(
        StreamEventKind::Error,
        std::move(detail));
    rejected.http_status = handles.status_code;
    QueueTerminal(state, std::move(rejected));
    return;
  }
  if ( !HasSseContentType(handles.request.get()) )
  {
    const std::string body = ReadErrorBody(
        state, handles, deadline);
    if ( IsCancelled(state) )
    {
      timeline.Terminal("cancelled");
      QueueTerminal(
          state,
          MakeControlEvent(StreamEventKind::Cancelled, "Stream was cancelled."));
      return;
    }
    if ( DeadlineExpired(deadline) )
    {
      timeline.Terminal("overall_timeout");
      QueueTerminal(
          state,
          MakeControlEvent(StreamEventKind::Error, "Stream overall timeout expired."));
      return;
    }
    timeline.Terminal(
        "content_type_error",
        SanitizeAiNetworkErrorBody(body),
        handles.status_code);
    StreamEvent rejected = MakeControlEvent(
        StreamEventKind::Error,
        "SSE response content type is invalid.");
    rejected.http_status = handles.status_code;
    QueueTerminal(state, std::move(rejected));
    return;
  }

  const std::size_t scratch_limit = (std::min)(
      SseHardMaxScratchBytes,
      state.request.max_event_bytes + SseHardMaxLineBytes);
  SseParser parser(SseParserLimits{
      (std::min)(SseHardMaxLineBytes, std::size_t{64 * 1024}),
      state.request.max_event_bytes,
      scratch_limit,
  });
  const auto abort = [&]() -> std::optional<std::string>
  {
    if ( IsCancelled(state) )
      return "Stream was cancelled.";
    if ( DeadlineExpired(deadline) )
      return "Stream overall timeout expired.";
    if ( timeline.IdleElapsedMs() >= state.request.idle_timeout_ms )
      return "SSE idle timeout expired.";
    return std::nullopt;
  };
  while ( true )
  {
    if ( IsCancelled(state) )
    {
      timeline.Terminal("cancelled");
      QueueTerminal(state, MakeControlEvent(StreamEventKind::Cancelled, "Stream was cancelled."));
      return;
    }
    if ( DeadlineExpired(deadline) )
    {
      timeline.Terminal("overall_timeout");
      QueueTerminal(state, MakeControlEvent(StreamEventKind::Error, "Stream overall timeout expired."));
      return;
    }
    const auto idle_elapsed = timeline.IdleElapsedMs();
    const auto idle_remaining = static_cast<long long>(state.request.idle_timeout_ms)
        - idle_elapsed;
    if ( idle_remaining <= 0 )
    {
      constexpr std::string_view message = "SSE idle timeout expired.";
      timeline.Terminal("idle_timeout", message);
      QueueTerminal(
          state,
          MakeControlEvent(StreamEventKind::Error, std::string(message)));
      return;
    }
    int receive_timeout = (std::min)(
        RemainingReceiveTimeout(state, deadline),
        static_cast<int>((std::min)(idle_remaining, static_cast<long long>((std::numeric_limits<int>::max)()))));
    WinHttpSetOption(
        handles.request.get(),
        WINHTTP_OPTION_RECEIVE_TIMEOUT,
        &receive_timeout,
        sizeof(receive_timeout));
    std::string_view bytes;
    std::string read_error;
    if ( !handles.async->Read(handles.request.get(), abort, bytes, read_error) )
    {
      const DWORD receive_error = handles.async->LastError();
      if ( IsCancelled(state) )
      {
        timeline.Terminal("cancelled");
        QueueTerminal(state, MakeControlEvent(StreamEventKind::Cancelled, "Stream was cancelled."));
      }
      else if ( DeadlineExpired(deadline) )
      {
        timeline.Terminal("overall_timeout");
        QueueTerminal(state, MakeControlEvent(StreamEventKind::Error, "Stream overall timeout expired."));
      }
      else if ( receive_error == ERROR_WINHTTP_TIMEOUT )
      {
        timeline.OperationError(
            "sse.receive.wait",
            handles.async->LastOperation(),
            receive_error,
            QueryHttp2StreamError(handles.request.get()));
        constexpr std::string_view message = "SSE idle timeout expired.";
        timeline.Terminal("idle_timeout", message);
        QueueTerminal(state, MakeControlEvent(StreamEventKind::Error, std::string(message)));
      }
      else
      {
        const std::optional<DWORD> stream_error =
            QueryHttp2StreamError(handles.request.get());
        if ( receive_error != ERROR_SUCCESS )
        {
          read_error = FormatWinHttpSseError(handles.async->LastOperation(), receive_error, stream_error);
          timeline.OperationError(
              "sse.receive.error", handles.async->LastOperation(), receive_error, stream_error);
        }
        timeline.Terminal("read_error", read_error);
        QueueTerminal(state, MakeControlEvent(StreamEventKind::Error, read_error));
      }
      return;
    }
    if ( !bytes.empty() )
    {
      timeline.Read(bytes.size());
      AppendAiNetworkResponseLog(state.id, bytes);
    }
    SseParseResult parsed = bytes.empty()
        ? parser.Finish()
        : parser.Feed(bytes);
    if ( parsed.status == SseParseStatus::Error )
    {
      timeline.Terminal("parse_error", parsed.message);
      QueueTerminal(state, MakeControlEvent(StreamEventKind::Error, parsed.message));
      return;
    }
    timeline.Parsed(parsed.events.size());
    for ( SseEvent &sse : parsed.events )
    {
      StreamEvent event;
      event.kind = StreamEventKind::Sse;
      event.sse = std::move(sse);
      if ( !QueueEvent(state, std::move(event)) )
      {
        timeline.Terminal("event_queue_rejected");
        return;
      }
    }
    if ( bytes.empty() )
    {
      timeline.Terminal("closed");
      QueueTerminal(state, MakeControlEvent(StreamEventKind::Closed, "SSE stream closed."));
      return;
    }
  }
}

} // namespace ida_agent::ai
