#include "ai/file_log.hpp"
#include "ai/network_request_logger.hpp"
#include "ai/stream_client.hpp"
#include "ai/network_diagnostics.hpp"
#ifdef _WIN32
#include "ai/stream_client_win_internal.hpp"
#else
#include <unistd.h>
#endif

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace
{

void Require(bool condition, const char *message)
{
  if ( !condition )
    throw std::runtime_error(message);
}

ida_agent::ai::StreamRequest MakeSseRequest()
{
  ida_agent::ai::StreamRequest request;
  request.url = "https://provider.invalid/v1/events";
  request.user_agent = "ida-agent-stream-test";
  return request;
}

ida_agent::ai::StreamRequest MakeWebSocketRequest(std::string url = "wss://provider.invalid/socket")
{
  ida_agent::ai::StreamRequest request;
  request.url = std::move(url);
  request.user_agent = "ida-agent-stream-test";
  return request;
}

ida_agent::ai::StreamEvent WaitForTerminal(
    ida_agent::ai::StreamClient &client,
    ida_agent::ai::StreamClient::StreamId id)
{
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while ( std::chrono::steady_clock::now() < deadline )
  {
    if ( std::optional<ida_agent::ai::StreamEvent> event = client.TryTakeEvent(id) )
    {
      if ( event->kind == ida_agent::ai::StreamEventKind::Closed
          || event->kind == ida_agent::ai::StreamEventKind::Error
          || event->kind == ida_agent::ai::StreamEventKind::Cancelled )
      {
        return std::move(*event);
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  throw std::runtime_error("stream did not terminate");
}

} // namespace

int main()
{
  using namespace ida_agent::ai;

  const std::filesystem::path log_root =
      std::filesystem::canonical(std::filesystem::temp_directory_path())
#ifdef _WIN32
      / (L"ida-agent-network-log-" + std::to_wstring(GetCurrentProcessId()));
#else
      / ("ida-agent-network-log-" + std::to_string(getpid()));
#endif
  std::filesystem::remove_all(log_root);
  {
    NetworkRequestLogger logger(log_root);
    logger.Configure(true);
    logger.Begin(7, "session/one", "request-content");
    logger.ResponseStatus(7, 429);
    logger.AppendResponse(7, "response-");
    logger.AppendResponse(7, "content");
    logger.End(7);
    logger.Begin(8, "session:one", "other-request");
    logger.ResponseStatus(8, 200);
    logger.AppendResponse(8, "other-response");
    logger.End(8);
    logger.Begin(9, std::string(65, 'x'), "rejected-request");
    logger.Configure(false);
  }
  const std::filesystem::path network_log =
      log_root / L"session-session~2Fone.log";
  std::ifstream network_input(network_log, std::ios::binary);
  const std::string network_text{
      std::istreambuf_iterator<char>(network_input),
      std::istreambuf_iterator<char>()};
  Require(network_text.find("request-content") != std::string::npos
              && network_text.find("status=429") != std::string::npos
              && network_text.find("response-content") != std::string::npos
              && network_text.find("other-request") == std::string::npos
              && network_text.find("response.end") != std::string::npos,
          "session network log content mismatch");
  network_input.close();
  const std::filesystem::path other_network_log =
      log_root / L"session-session~3Aone.log";
  std::ifstream other_network_input(other_network_log, std::ios::binary);
  const std::string other_network_text{
      std::istreambuf_iterator<char>(other_network_input),
      std::istreambuf_iterator<char>()};
  Require(other_network_text.find("other-request") != std::string::npos
              && other_network_text.find("other-response") != std::string::npos
              && other_network_text.find("request-content") == std::string::npos,
          "encoded session network logs collided");
  other_network_input.close();
  std::size_t session_log_count = 0;
  for ( const auto &entry : std::filesystem::directory_iterator(log_root) )
    session_log_count += entry.is_regular_file() ? 1 : 0;
  Require(session_log_count == 2, "invalid session id created a network log");

  const std::filesystem::path concurrent_path = log_root / L"concurrent.log";
  {
    FileLog concurrent_log(concurrent_path);
    std::vector<std::thread> writers;
    for ( int writer = 0; writer < 4; ++writer )
    {
      writers.emplace_back([writer, &concurrent_log]()
      {
        for ( int line = 0; line < 100; ++line )
        {
          concurrent_log.Append(
              "writer=" + std::to_string(writer) + " line="
              + std::to_string(line) + "\n");
        }
      });
    }
    for ( std::thread &writer : writers )
      writer.join();
    concurrent_log.Flush();
  }
  std::ifstream concurrent_input(concurrent_path, std::ios::binary);
  const std::string concurrent_text{
      std::istreambuf_iterator<char>(concurrent_input),
      std::istreambuf_iterator<char>()};
  Require(std::count(concurrent_text.begin(), concurrent_text.end(), '\n') == 400,
          "concurrent file log lost or merged records");
  concurrent_input.close();
#ifndef _WIN32
  Require((std::filesystem::status(concurrent_path).permissions() & std::filesystem::perms::all)
              == (std::filesystem::perms::owner_read | std::filesystem::perms::owner_write),
          "Linux log file is not private");
  Require((std::filesystem::status(log_root).permissions() & std::filesystem::perms::all)
              == std::filesystem::perms::owner_all, "Linux log directory is not private");
  const auto linked_log = log_root / "linked.log";
  std::filesystem::create_symlink(concurrent_path, linked_log);
  {
    FileLog rejected(linked_log);
    rejected.Append("must-not-be-written");
    rejected.Flush();
  }
  Require(std::filesystem::file_size(concurrent_path) == concurrent_text.size(),
          "Linux logger followed a symlink");
#endif
  std::filesystem::remove_all(log_root);

  const std::string diagnostic = SanitizeAiNetworkErrorBody(
      R"({"error":{"type":"invalid_request_error","code":"bad_request","param":"reasoning.summary","message":"Unsupported field; Bearer secret-token sk-secret api_key: another-secret"}})");
  Require(diagnostic.find("invalid_request_error") != std::string::npos
              && diagnostic.find("reasoning.summary") != std::string::npos,
          "network diagnostic fields were not retained");
  Require(diagnostic.find("secret-token") == std::string::npos
              && diagnostic.find("sk-secret") == std::string::npos
              && diagnostic.find("another-secret") == std::string::npos,
          "network diagnostic leaked a credential marker");
  Require(
      SanitizeAiNetworkErrorBody("raw-secret-body")
          == "message=raw-secret-body",
      "non-JSON network body detail was lost");
#ifdef _WIN32
  const std::string handle_state_error =
      stream_client_win_internal::FormatWinHttpSseError(
          "WinHttpQueryDataAvailable",
          ERROR_WINHTTP_INCORRECT_HANDLE_STATE);
  Require(
      handle_state_error
          == "WinHttpQueryDataAvailable failed with "
             "ERROR_WINHTTP_INCORRECT_HANDLE_STATE (12019).",
      "WinHTTP incorrect handle state message mismatch");
  Require(
      stream_client_win_internal::FormatWinHttpSseError(
          "WinHttpReadData", ERROR_WINHTTP_CONNECTION_ERROR, 8)
          == "WinHttpReadData failed with ERROR_WINHTTP_CONNECTION_ERROR "
             "(12030); HTTP/2 RST_STREAM code=8.",
      "WinHTTP HTTP/2 stream error message mismatch");
#endif

  StreamRequest request = MakeSseRequest();
  Require(!ValidateStreamRequest(StreamKind::Sse, request), "valid SSE GET was rejected");
  request.method = HttpMethod::Post;
  request.body = "{}";
  Require(!ValidateStreamRequest(StreamKind::Sse, request), "valid SSE POST was rejected");
  request = MakeSseRequest();
  request.url = "http://example.invalid/events";
  Require(
      !ValidateStreamRequest(StreamKind::Sse, request),
      "public HTTP SSE was rejected");
  request.url = "http://127.0.0.1:8765/events";
  Require(
      !ValidateStreamRequest(StreamKind::Sse, request),
      "system proxy mode was rejected for HTTP SSE");
  request.proxy.mode = HttpProxyMode::Direct;
  Require(!ValidateStreamRequest(StreamKind::Sse, request), "direct loopback SSE was rejected");
  request.headers.push_back({"Authorization", "unit-test-secret"});
  Require(
      !ValidateStreamRequest(StreamKind::Sse, request),
      "credentials over HTTP SSE were rejected");
  request.headers.clear();
  request.proxy.mode = HttpProxyMode::Http;
  request.proxy.host = "127.0.0.1";
  request.proxy.port = 8080;
  request.proxy.username = "proxy-user";
  Require(
      !ValidateStreamRequest(StreamKind::Sse, request),
      "proxy credentials over HTTP SSE were rejected");

  StreamRequest websocket = MakeWebSocketRequest();
  Require(!ValidateStreamRequest(StreamKind::WebSocket, websocket), "valid WSS was rejected");
  websocket = MakeWebSocketRequest("ws://127.0.0.1:8765/socket");
  Require(
      !ValidateStreamRequest(StreamKind::WebSocket, websocket),
      "system proxy mode was rejected for WS");
  websocket.proxy.mode = HttpProxyMode::Direct;
  Require(!ValidateStreamRequest(StreamKind::WebSocket, websocket), "direct loopback WS was rejected");
  websocket.url = "ws://example.invalid/socket";
  Require(!ValidateStreamRequest(StreamKind::WebSocket, websocket), "public WS was rejected");
  websocket = MakeWebSocketRequest("ws://localhost:8765/socket");
  websocket.headers.push_back({"Authorization", "unit-test-secret"});
  Require(!ValidateStreamRequest(StreamKind::WebSocket, websocket), "credentials over WS were rejected");
  websocket.headers = {{"X-API-Key", "unit-test-secret"}};
  Require(!ValidateStreamRequest(StreamKind::WebSocket, websocket), "API key over WS was rejected");
  websocket.headers.clear();
  websocket.proxy.mode = HttpProxyMode::Http;
  websocket.proxy.host = "127.0.0.1";
  websocket.proxy.port = 8080;
  websocket.proxy.username = "proxy-user";
  Require(!ValidateStreamRequest(StreamKind::WebSocket, websocket), "proxy credentials over WS were rejected");

  for ( const bool bypass_local : {false, true} )
  {
    StreamRequest named_sse = MakeSseRequest();
    named_sse.url = "http://127.0.0.1:8765/events";
    named_sse.proxy.mode = HttpProxyMode::Http;
    named_sse.proxy.host = "127.0.0.1";
    named_sse.proxy.port = 8080;
    named_sse.proxy.bypass_local = bypass_local;
    Require(
        !ValidateStreamRequest(StreamKind::Sse, named_sse),
        "named proxy mode was rejected for HTTP SSE");

    StreamRequest named_ws = MakeWebSocketRequest("ws://127.0.0.1:8765/socket");
    named_ws.proxy.mode = HttpProxyMode::Http;
    named_ws.proxy.host = "127.0.0.1";
    named_ws.proxy.port = 8080;
    named_ws.proxy.bypass_local = bypass_local;
    Require(
        !ValidateStreamRequest(StreamKind::WebSocket, named_ws),
        "named proxy mode was rejected for WS");
  }

  for ( const char *name : {
            "Host",
            "Content-Length",
            "Transfer-Encoding",
            "Connection",
            "Upgrade",
            "Proxy-Authorization",
            "Sec-WebSocket-Protocol"} )
  {
    StreamRequest invalid = MakeSseRequest();
    invalid.headers.push_back({name, "value"});
    Require(ValidateStreamRequest(StreamKind::Sse, invalid).has_value(), "reserved header was accepted");
  }
  StreamRequest invalid = MakeSseRequest();
  invalid.url = "wss://provider.invalid/socket";
  Require(ValidateStreamRequest(StreamKind::Sse, invalid).has_value(), "WSS URL was accepted for SSE");
  invalid = MakeWebSocketRequest("https://provider.invalid/socket");
  Require(ValidateStreamRequest(StreamKind::WebSocket, invalid).has_value(), "HTTPS URL was accepted for WebSocket");
  invalid = MakeSseRequest();
  invalid.max_event_bytes = 0;
  Require(ValidateStreamRequest(StreamKind::Sse, invalid).has_value(), "zero event limit was accepted");
  invalid = MakeSseRequest();
  invalid.max_queued_bytes = invalid.max_event_bytes - 1;
  Require(ValidateStreamRequest(StreamKind::Sse, invalid).has_value(), "undersized event queue was accepted");
  invalid = MakeSseRequest();
  invalid.method = HttpMethod::Post;
  invalid.body.assign(StreamHardMaxPayloadBytes + 1, 'x');
  Require(ValidateStreamRequest(StreamKind::Sse, invalid).has_value(), "oversized body was accepted");
  invalid = MakeSseRequest();
  invalid.headers.push_back({std::string(StreamHardMaxHeaderNameBytes + 1, 'x'), "value"});
  Require(ValidateStreamRequest(StreamKind::Sse, invalid).has_value(), "oversized header name was accepted");
  invalid = MakeSseRequest();
  invalid.headers.push_back({"X-Test", std::string(StreamHardMaxHeaderValueBytes + 1, 'x')});
  Require(ValidateStreamRequest(StreamKind::Sse, invalid).has_value(), "oversized header value was accepted");
  invalid = MakeSseRequest();
  for ( int index = 0; index < 5; ++index )
    invalid.headers.push_back({"X-Block-" + std::to_string(index), std::string(60 * 1024, 'x')});
  Require(ValidateStreamRequest(StreamKind::Sse, invalid).has_value(), "oversized header total was accepted");

  StreamClient immediate;
  Require(immediate.Retire(0xFFFFFFFFULL), "unknown stream retirement failed");
  invalid = MakeSseRequest();
  invalid.user_agent.clear();
  invalid.headers.push_back({"Authorization", "unit-test-secret"});
  const StreamClient::StreamId invalid_id = immediate.OpenSse(std::move(invalid));
  Require(!immediate.Retire(invalid_id), "unconsumed terminal stream was retired");
  const std::optional<StreamEvent> invalid_event = immediate.TryTakeEvent(invalid_id);
  Require(invalid_event && invalid_event->kind == StreamEventKind::Error, "invalid open was not immediate");
  Require(
      invalid_event->message.find("unit-test-secret") == std::string::npos,
      "validation diagnostic leaked a secret");
  Require(immediate.Retire(invalid_id), "consumed immediate terminal was not retired");

#ifdef IDA_AGENT_STREAM_CLIENT_TESTING
  immediate.SetWorkerExitDelayForTesting(150);
#endif
  StreamRequest cancellable = MakeSseRequest();
  cancellable.url = "http://127.0.0.1:9/events";
  cancellable.proxy.mode = HttpProxyMode::Direct;
  const StreamClient::StreamId cancel_id = immediate.OpenSse(std::move(cancellable));
  Require(!immediate.Retire(cancel_id), "active stream was retired");
  immediate.Cancel(cancel_id);
  const StreamEvent cancelled = WaitForTerminal(immediate, cancel_id);
  Require(cancelled.kind == StreamEventKind::Cancelled, "immediate cancellation status mismatch");
  Require(!immediate.Retire(cancel_id), "terminal stream retired before worker completion");
  const auto retire_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while ( !immediate.Retire(cancel_id)
      && std::chrono::steady_clock::now() < retire_deadline )
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  Require(immediate.Retire(cancel_id), "terminal stream was not eventually retired");

  immediate.Shutdown();
  immediate.Shutdown();
  const StreamClient::StreamId stopped_id = immediate.OpenSse(MakeSseRequest());
  const std::optional<StreamEvent> stopped = immediate.TryTakeEvent(stopped_id);
  Require(stopped && stopped->kind == StreamEventKind::Cancelled, "stopped client accepted OpenSse");
  const StreamClient::StreamId stopped_ws = immediate.OpenWebSocket(MakeWebSocketRequest());
  const std::optional<StreamEvent> stopped_ws_event = immediate.TryTakeEvent(stopped_ws);
  Require(
      stopped_ws_event && stopped_ws_event->kind == StreamEventKind::Cancelled,
      "stopped client accepted OpenWebSocket");

  StreamClient tracked;
  StreamRequest tracked_invalid = MakeSseRequest();
  tracked_invalid.user_agent.clear();
  std::vector<StreamClient::StreamId> tracked_ids;
  for ( std::size_t index = 0; index < StreamMaxTracked; ++index )
  {
    const StreamClient::StreamId id = tracked.OpenSse(tracked_invalid);
    Require(id != 0, "tracked stream limit was reached early");
    tracked_ids.push_back(id);
  }
  Require(tracked.OpenSse(tracked_invalid) == 0, "tracked stream hard limit was not enforced");
  const std::optional<StreamEvent> released = tracked.TryTakeEvent(tracked_ids.front());
  Require(released && released->kind == StreamEventKind::Error, "tracked terminal event was missing");
  Require(tracked.OpenSse(tracked_invalid) != 0, "consuming a terminal record did not release capacity");
  return 0;
}
