#include "ai/stream_client_linux_internal.hpp"
#include "ai/macos_url_session.hpp"
#include "ai/network_diagnostics.hpp"
#include <algorithm>

namespace ida_agent::ai
{
using namespace stream_client_linux_internal;
namespace
{
using Clock = std::chrono::steady_clock;
HttpRequest NativeRequest(const StreamRequest &source)
{
  HttpRequest request;
  request.method = source.method;
  request.url = source.url;
  request.user_agent = source.user_agent;
  request.headers = source.headers;
  request.body = source.body;
  request.proxy = source.proxy;
  request.connect_timeout_ms = source.connect_timeout_ms;
  request.send_timeout_ms = source.send_timeout_ms;
  request.receive_timeout_ms = source.idle_timeout_ms;
  return request;
}
struct ExchangeLog
{
  std::uint64_t id;
  ~ExchangeLog() { EndAiNetworkExchangeLog(id); }
};
bool Elapsed(Clock::time_point since, std::uint32_t milliseconds)
{ return Clock::now() - since >= std::chrono::milliseconds(milliseconds); }
}

void StreamClient::Impl::RunSse(State &state, const std::optional<Clock::time_point> &deadline)
{
  MacUrlSession session(NativeRequest(state.request), false);
  SseParser parser({64 * 1024, state.request.max_event_bytes,
      std::min(SseHardMaxScratchBytes, state.request.max_event_bytes + SseHardMaxLineBytes)});
  BeginAiNetworkExchangeLog(StreamKind::Sse, state.request, state.id);
  ExchangeLog log{state.id};
  auto started = Clock::now(), activity = started, send_started = started;
  bool opened = false, connected = false, sending = !state.request.body.empty();
  std::uint32_t status = 0;
  std::string error_body;
  auto fail = [&](std::string message) {
    auto event = MakeControlEvent(StreamEventKind::Error, std::move(message));
    event.http_status = status;
    QueueTerminal(state, std::move(event));
  };
  auto deliver = [&](SseParseResult result) {
    for (auto &value : result.events)
    {
      StreamEvent event;
      event.kind = StreamEventKind::Sse;
      event.sse = std::move(value);
      if (!QueueEvent(state, std::move(event))) return false;
    }
    if (result.status == SseParseStatus::Error) { fail(result.message); return false; }
    return true;
  };
  for (;;)
  {
    if (IsCancelled(state))
    { QueueTerminal(state, MakeControlEvent(StreamEventKind::Cancelled, "Stream was cancelled.")); return; }
    if (DeadlineExpired(deadline)) { fail("Stream overall timeout expired."); return; }
    if (auto native = session.Poll())
    {
      activity = Clock::now();
      switch (native->kind)
      {
      case MacNetworkEventKind::Response:
        status = native->status;
        connected = true;
        sending = false;
        LogAiNetworkResponseStatus(state.id, status);
        if (status >= 200 && status < 300)
        {
          if (native->data != "text/event-stream") { fail("SSE response content type is invalid."); return; }
          StreamEvent event;
          event.kind = StreamEventKind::Opened;
          event.http_status = status;
          if (!QueueEvent(state, std::move(event))) return;
          opened = true;
        }
        break;
      case MacNetworkEventKind::Sent:
        if (!connected) send_started = activity;
        connected = true;
        sending = native->bytes_sent < state.request.body.size();
        break;
      case MacNetworkEventKind::Data:
        AppendAiNetworkResponseLog(state.id, native->data);
        if (opened) { if (!deliver(parser.Feed(native->data))) return; }
        else error_body.append(native->data, 0, std::min<std::size_t>(native->data.size(), 64 * 1024 - error_body.size()));
        break;
      case MacNetworkEventKind::Complete:
        if (!opened) fail(status ? SanitizeAiNetworkErrorBody(error_body) : "SSE response headers are invalid.");
        else if (deliver(parser.Finish())) QueueTerminal(state, MakeControlEvent(StreamEventKind::Closed));
        return;
      case MacNetworkEventKind::Error:
        fail(native->data);
        return;
      default:
        fail("Unexpected SSE transport event.");
        return;
      }
      continue;
    }
    if (!connected && Elapsed(started, state.request.connect_timeout_ms))
    { fail("SSE connection timeout expired."); return; }
    if (sending && Elapsed(send_started, state.request.send_timeout_ms))
    { fail("SSE send timeout expired."); return; }
    // URLSession enforces receive idle time using network activity, including
    // bytes it has not yet delivered to the delegate.
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
}

void StreamClient::Impl::RunWebSocket(State &state, const std::optional<Clock::time_point> &deadline)
{
  MacUrlSession session(NativeRequest(state.request), true, state.request.max_message_bytes);
  BeginAiNetworkExchangeLog(StreamKind::WebSocket, state.request, state.id);
  ExchangeLog log{state.id};
  auto started = Clock::now(), activity = started, send_started = started, close_started = started;
  bool opened = false, sending = false, closing = false;
  std::size_t pending_bytes = 0;
  auto fail = [&](std::string message) {
    QueueTerminal(state, MakeControlEvent(StreamEventKind::Error, std::move(message)));
  };
  for (;;)
  {
    if (IsCancelled(state))
    { QueueTerminal(state, MakeControlEvent(StreamEventKind::Cancelled, "Stream was cancelled.")); return; }
    if (DeadlineExpired(deadline)) { fail("Stream overall timeout expired."); return; }
    if (auto native = session.Poll())
    {
      activity = Clock::now();
      switch (native->kind)
      {
      case MacNetworkEventKind::Response:
      {
        opened = true;
        { std::lock_guard<std::mutex> lock(state.mutex); state.websocket_open = true; }
        StreamEvent event;
        event.kind = StreamEventKind::Opened;
        event.http_status = native->status;
        LogAiNetworkResponseStatus(state.id, native->status);
        if (!QueueEvent(state, std::move(event))) return;
        break;
      }
      case MacNetworkEventKind::Text:
      case MacNetworkEventKind::Binary:
      {
        if (native->data.size() > state.request.max_message_bytes)
        { fail("WebSocket message exceeds the size limit."); return; }
        StreamEvent event;
        event.kind = native->kind == MacNetworkEventKind::Text
            ? StreamEventKind::WebSocketText : StreamEventKind::WebSocketBinary;
        AppendAiNetworkResponseLog(state.id, native->data);
        event.payload = std::move(native->data);
        if (!QueueEvent(state, std::move(event))) return;
        break;
      }
      case MacNetworkEventKind::Sent:
      {
        std::lock_guard<std::mutex> lock(state.mutex);
        state.send_bytes -= std::min(state.send_bytes, pending_bytes);
        pending_bytes = 0;
        sending = false;
        break;
      }
      case MacNetworkEventKind::Closed:
      {
        if (native->close_code != 1000 && native->close_code != 1001 && native->close_code < 3000)
        { fail("WebSocket protocol or transport failed."); return; }
        StreamEvent event;
        event.kind = StreamEventKind::Closed;
        event.close_code = native->close_code;
        QueueTerminal(state, std::move(event));
        return;
      }
      case MacNetworkEventKind::Error:
        fail(native->data);
        return;
      default:
        fail("Unexpected WebSocket transport event.");
        return;
      }
    }
    bool request_close = false;
    std::uint16_t close_code = 1000;
    std::optional<OutgoingMessage> outgoing;
    {
      std::lock_guard<std::mutex> lock(state.mutex);
      request_close = state.close_requested;
      close_code = state.close_code;
      if (opened && !sending && !request_close && !state.send_queue.empty())
      {
        outgoing = std::move(state.send_queue.front());
        state.send_queue.pop_front();
      }
    }
    if (outgoing)
    {
      if (!session.Send(outgoing->text, outgoing->payload)) { fail("WebSocket send failed."); return; }
      pending_bytes = outgoing->payload.size();
      sending = true;
      send_started = Clock::now();
    }
    if (request_close && opened && !closing)
    { session.Close(close_code); closing = true; close_started = Clock::now(); }
    if (!opened && Elapsed(started, state.request.connect_timeout_ms))
    { fail("WebSocket connection timeout expired."); return; }
    if (sending && Elapsed(send_started, state.request.send_timeout_ms))
    { fail("WebSocket send timeout expired."); return; }
    if (closing && Elapsed(close_started, state.request.send_timeout_ms))
    { fail("WebSocket close handshake timeout expired."); return; }
    if (opened && Elapsed(activity, state.request.idle_timeout_ms))
    { fail("WebSocket idle timeout expired."); return; }
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
}
}
