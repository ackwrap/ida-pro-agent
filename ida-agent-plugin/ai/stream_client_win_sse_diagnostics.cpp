#include "ai/stream_client_win_sse_diagnostics.hpp"

#include "ai/network_diagnostics.hpp"

namespace ida_agent::ai::stream_client_win_internal
{

const char *WinHttpErrorSymbol(DWORD error) noexcept
{
  switch ( error )
  {
    case ERROR_SUCCESS: return "ERROR_SUCCESS";
    case ERROR_OPERATION_ABORTED: return "ERROR_OPERATION_ABORTED";
    case ERROR_WINHTTP_OUT_OF_HANDLES: return "ERROR_WINHTTP_OUT_OF_HANDLES";
    case ERROR_WINHTTP_TIMEOUT: return "ERROR_WINHTTP_TIMEOUT";
    case ERROR_WINHTTP_INTERNAL_ERROR: return "ERROR_WINHTTP_INTERNAL_ERROR";
    case ERROR_WINHTTP_INVALID_URL: return "ERROR_WINHTTP_INVALID_URL";
    case ERROR_WINHTTP_UNRECOGNIZED_SCHEME: return "ERROR_WINHTTP_UNRECOGNIZED_SCHEME";
    case ERROR_WINHTTP_NAME_NOT_RESOLVED: return "ERROR_WINHTTP_NAME_NOT_RESOLVED";
    case ERROR_WINHTTP_INVALID_OPTION: return "ERROR_WINHTTP_INVALID_OPTION";
    case ERROR_WINHTTP_OPTION_NOT_SETTABLE: return "ERROR_WINHTTP_OPTION_NOT_SETTABLE";
    case ERROR_WINHTTP_SHUTDOWN: return "ERROR_WINHTTP_SHUTDOWN";
    case ERROR_WINHTTP_LOGIN_FAILURE: return "ERROR_WINHTTP_LOGIN_FAILURE";
    case ERROR_WINHTTP_OPERATION_CANCELLED: return "ERROR_WINHTTP_OPERATION_CANCELLED";
    case ERROR_WINHTTP_INCORRECT_HANDLE_TYPE: return "ERROR_WINHTTP_INCORRECT_HANDLE_TYPE";
    case ERROR_WINHTTP_INCORRECT_HANDLE_STATE: return "ERROR_WINHTTP_INCORRECT_HANDLE_STATE";
    case ERROR_WINHTTP_CANNOT_CONNECT: return "ERROR_WINHTTP_CANNOT_CONNECT";
    case ERROR_WINHTTP_CONNECTION_ERROR: return "ERROR_WINHTTP_CONNECTION_ERROR";
    case ERROR_WINHTTP_RESEND_REQUEST: return "ERROR_WINHTTP_RESEND_REQUEST";
    case ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED: return "ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED";
    case ERROR_WINHTTP_SECURE_FAILURE: return "ERROR_WINHTTP_SECURE_FAILURE";
    default: return "ERROR_WINHTTP_UNKNOWN";
  }
}

std::string FormatWinHttpSseError(
    std::string_view operation,
    DWORD error,
    std::optional<DWORD> http2_stream_error)
{
  std::string message(operation);
  message += " failed with ";
  message += WinHttpErrorSymbol(error);
  message += " (" + std::to_string(error) + ")";
  if ( http2_stream_error.has_value() )
  {
    message += "; HTTP/2 RST_STREAM code="
        + std::to_string(*http2_stream_error);
  }
  message.push_back('.');
  return message;
}

std::optional<DWORD> QueryHttp2StreamError(HINTERNET request) noexcept
{
#if defined(WINHTTP_OPTION_STREAM_ERROR_CODE)
  DWORD stream_error = 0;
  DWORD size = sizeof(stream_error);
  if ( WinHttpQueryOption(
           request,
           WINHTTP_OPTION_STREAM_ERROR_CODE,
           &stream_error,
           &size) )
  {
    return stream_error;
  }
#else
  (void)request;
#endif
  return std::nullopt;
}

SseTimeline::SseTimeline(
    StreamClient::StreamId stream_id,
    const StreamRequest &request)
    : stream_id_(stream_id), started_(Clock::now()), last_activity_(started_)
{
  BeginAiNetworkExchangeLog(StreamKind::Sse, request, stream_id_);
  LogAiNetworkDiagnostic(
      "sse.open.begin",
      std::string("method=")
          + (request.method == HttpMethod::Post ? "POST" : "GET")
          + " bodyBytes=" + std::to_string(request.body.size())
          + " elapsedMs=0 idleElapsedMs=0 responseBytes=0 sseEvents=0",
      0,
      stream_id_);
}

void SseTimeline::Status(std::uint32_t status) const
{
  LogAiNetworkResponseStatus(stream_id_, status);
  LogAiNetworkDiagnostic("sse.open.status", Metrics(), status, stream_id_);
}

void SseTimeline::Read(std::size_t bytes)
{
  response_bytes_ += bytes;
  last_activity_ = Clock::now();
  LogAiNetworkDiagnostic(
      "sse.read",
      "chunkBytes=" + std::to_string(bytes) + " " + Metrics(),
      0,
      stream_id_);
}

void SseTimeline::Parsed(std::size_t count)
{
  parsed_events_ += count;
  LogAiNetworkDiagnostic(
      "sse.parsed",
      "batchEvents=" + std::to_string(count) + " " + Metrics(),
      0,
      stream_id_);
}

void SseTimeline::OperationError(
    std::string_view phase,
    std::string_view operation,
    DWORD error,
    const std::optional<DWORD> &http2_stream_error) const
{
  LogAiNetworkDiagnostic(
      phase,
      FormatWinHttpSseError(operation, error, http2_stream_error)
          + " " + Metrics(),
      0,
      stream_id_);
}

void SseTimeline::Terminal(
    std::string_view reason,
    std::string_view detail,
    std::uint32_t status) const
{
  std::string terminal = "reason=" + std::string(reason) + " " + Metrics();
  if ( !detail.empty() )
    terminal += " error=" + std::string(detail);
  LogAiNetworkDiagnostic("sse.terminal", terminal, status, stream_id_);
  EndAiNetworkExchangeLog(stream_id_);
}

long long SseTimeline::IdleElapsedMs() const
{
  return std::chrono::duration_cast<std::chrono::milliseconds>(
      Clock::now() - last_activity_).count();
}

std::string SseTimeline::Metrics() const
{
  const auto now = Clock::now();
  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      now - started_).count();
  const auto idle = std::chrono::duration_cast<std::chrono::milliseconds>(
      now - last_activity_).count();
  return "elapsedMs=" + std::to_string(elapsed)
      + " idleElapsedMs=" + std::to_string(idle)
      + " responseBytes=" + std::to_string(response_bytes_)
      + " sseEvents=" + std::to_string(parsed_events_);
}

} // namespace ida_agent::ai::stream_client_win_internal
