#include "ai/stream_client_linux_internal.hpp"
#include "ai/stream_curl_linux.hpp"
#include "ai/utf8.hpp"
#include <algorithm>
#include <array>
#include <cerrno>
#include <limits>
#include <poll.h>

namespace ida_agent::ai
{
using namespace stream_client_linux_internal;
namespace
{
struct Handshake
{
  std::size_t bytes = 0;
  Clock::time_point received = Clock::now();
};
std::size_t Header(char *, std::size_t size, std::size_t count, void *context) noexcept
{
  auto &handshake = *static_cast<Handshake *>(context);
  if (size && count > std::numeric_limits<std::size_t>::max() / size) return 0;
  const auto bytes = size * count;
  if (bytes > StreamHardMaxHeaderBytes - handshake.bytes) return 0;
  handshake.bytes += bytes;
  handshake.received = Clock::now();
  return bytes;
}
std::size_t RejectBody(char *, std::size_t, std::size_t, void *) noexcept { return 0; }
}

void StreamClient::Impl::RunWebSocket(State &state, const std::optional<Clock::time_point> &deadline)
{
  CurlStream connection(state.request, true);
  auto *easy = connection.easy.get();
  Handshake handshake;
  Set(easy, CURLOPT_CONNECT_ONLY, 2L);
  // Handle PING explicitly: keep idle activity observable and flush PONG even
  // when a peer waits for it before sending the next message fragment.
  Set(easy, CURLOPT_WS_OPTIONS, CURLWS_NOAUTOPONG);
  Set(easy, CURLOPT_HEADERFUNCTION, &Header);
  Set(easy, CURLOPT_HEADERDATA, &handshake);
  Set(easy, CURLOPT_WRITEFUNCTION, &RejectBody);
  connection.Start();
  long status = 0;
  auto fail = [&](const char *message)
  {
    auto event = MakeControlEvent(StreamEventKind::Error, message);
    event.http_status = static_cast<std::uint32_t>(status);
    QueueTerminal(state, std::move(event));
  };
  auto interrupted = [&]
  {
    if (IsCancelled(state))
    {
      QueueTerminal(state, MakeControlEvent(StreamEventKind::Cancelled, "Stream was cancelled."));
      return true;
    }
    if (DeadlineExpired(deadline)) { fail("Stream overall timeout expired."); return true; }
    return false;
  };
  while (true)
  {
    if (interrupted()) return;
    if (auto completed = connection.Perform())
    {
      curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &status);
      if (*completed != CURLE_OK || status != 101)
      {
        fail(("WebSocket handshake failed (curl=" + std::to_string(*completed)
            + ", HTTP=" + std::to_string(status) + ").").c_str());
        return;
      }
      break;
    }
    curl_off_t pretransfer = 0;
    curl_easy_getinfo(easy, CURLINFO_PRETRANSFER_TIME_T, &pretransfer);
    if (pretransfer > 0 && Clock::now() - handshake.received >= std::chrono::milliseconds(state.request.idle_timeout_ms))
    { fail("WebSocket handshake timeout expired."); return; }
    connection.Poll();
  }
  {
    std::lock_guard<std::mutex> lock(state.mutex);
    state.websocket_open = true;
  }
  StreamEvent opened;
  opened.kind = StreamEventKind::Opened;
  opened.http_status = 101;
  if (!QueueEvent(state, std::move(opened))) return;
  curl_socket_t socket = CURL_SOCKET_BAD;
  if (curl_easy_getinfo(easy, CURLINFO_ACTIVESOCKET, &socket) != CURLE_OK || socket == CURL_SOCKET_BAD)
  { fail("WebSocket socket is unavailable."); return; }

  std::optional<OutgoingMessage> outgoing;
  std::size_t sent_offset = 0;
  std::size_t frame_end = 0;
  bool frame_active = false;
  std::string incoming, control, close_payload;
  std::optional<std::string> pong;
  std::size_t pong_offset = 0;
  Clock::time_point pong_started{};
  int incoming_type = 0;
  bool close_sent = false, remote_close = false;
  std::uint16_t remote_code = 1005;
  auto received = Clock::now(), send_started = received;
  std::optional<Clock::time_point> closing_started;
  std::array<char, 16 * 1024> buffer{};
  while (true)
  {
    if (interrupted()) return;
    const auto now = Clock::now();
    bool closing = false;
    std::uint16_t close_code;
    {
      std::lock_guard<std::mutex> lock(state.mutex);
      closing = state.close_requested || remote_close;
      close_code = state.close_code;
      if (closing)
      {
        for (const auto &message : state.send_queue) state.send_bytes -= message.payload.size();
        state.send_queue.clear();
      }
      else if (!outgoing && !state.send_queue.empty())
      {
        outgoing = std::move(state.send_queue.front());
        state.send_queue.pop_front();
        sent_offset = 0;
        send_started = now;
      }
    }
    if (closing && !closing_started) closing_started = now;
    if (closing_started && now - *closing_started >= std::chrono::seconds(2))
    { fail("WebSocket close handshake timed out."); return; }
    if (!closing && now - received >= std::chrono::milliseconds(state.request.idle_timeout_ms))
    { fail("WebSocket idle timeout expired."); return; }
    bool want_write = false;
    // libcurl requires completion of a partially sent frame before a control
    // frame can be written. Application messages use bounded fragments so a
    // large upload cannot indefinitely postpone PONG.
    if (pong && !frame_active)
    {
      if (now - pong_started >= std::chrono::milliseconds(state.request.send_timeout_ms))
      { fail("WebSocket control send timeout expired."); return; }
      std::size_t sent = 0;
      const auto result = curl_ws_send(easy, pong->data() + pong_offset,
          pong->size() - pong_offset, &sent, 0, CURLWS_PONG);
      if (result != CURLE_OK && result != CURLE_AGAIN) { fail("WebSocket PONG failed."); return; }
      pong_offset += sent;
      if (result == CURLE_OK && pong_offset == pong->size()) pong.reset();
      else want_write = true;
    }
    if (outgoing && (!pong || frame_active))
    {
      if (now - send_started >= std::chrono::milliseconds(state.request.send_timeout_ms))
      { fail("WebSocket send timeout expired."); return; }
      if (!frame_active)
      {
        frame_end = std::min(outgoing->payload.size(), sent_offset + 64 * 1024);
        frame_active = true;
      }
      std::size_t sent = 0;
      const unsigned flags = (outgoing->text ? CURLWS_TEXT : CURLWS_BINARY)
          | (frame_end < outgoing->payload.size() ? CURLWS_CONT : 0);
      const auto result = curl_ws_send(easy, outgoing->payload.data() + sent_offset,
          frame_end - sent_offset, &sent, 0, flags);
      if (result != CURLE_OK && result != CURLE_AGAIN) { fail("WebSocket send failed."); return; }
      sent_offset += sent;
      if (result == CURLE_OK && sent_offset == frame_end)
      {
        frame_active = false;
        if (sent_offset == outgoing->payload.size())
        {
          std::lock_guard<std::mutex> lock(state.mutex);
          state.send_bytes -= outgoing->payload.size();
          outgoing.reset();
        }
      }
      else want_write = true;
    }
    if (closing && !outgoing && !pong && !close_sent)
    {
      if (!remote_close && close_payload.empty())
      {
        close_payload.push_back(static_cast<char>(close_code >> 8));
        close_payload.push_back(static_cast<char>(close_code & 255));
      }
      std::size_t sent = 0;
      const auto result = curl_ws_send(easy, close_payload.data(), close_payload.size(), &sent, 0, CURLWS_CLOSE);
      if (result != CURLE_OK && result != CURLE_AGAIN) { fail("WebSocket close failed."); return; }
      if (result == CURLE_OK && sent == close_payload.size()) close_sent = true;
      else
      {
        close_payload.erase(0, sent);
        want_write = true;
      }
    }
    if (close_sent && remote_close)
    {
      auto event = MakeControlEvent(StreamEventKind::Closed);
      event.close_code = remote_code;
      QueueTerminal(state, std::move(event));
      return;
    }
    // Bound each drain pass so cancellation and send deadlines remain observable.
    for (int iteration = 0; iteration < 16 && !remote_close && !pong; ++iteration)
    {
      std::size_t bytes = 0;
      const curl_ws_frame *metadata = nullptr;
      const auto result = curl_ws_recv(easy, buffer.data(), buffer.size(), &bytes, &metadata);
      if (result == CURLE_AGAIN) break;
      if (result != CURLE_OK || !metadata) { fail("WebSocket receive failed or closed without a close frame."); return; }
      const auto frame = *metadata;
      received = Clock::now();
      if (frame.flags & (CURLWS_CLOSE | CURLWS_PING | CURLWS_PONG))
      {
        if (bytes > 125 - control.size()) { fail("WebSocket control frame is too large."); return; }
        control.append(buffer.data(), bytes);
        if (frame.bytesleft) continue;
        if (frame.flags & CURLWS_CLOSE)
        {
          if (control.size() == 1) { fail("WebSocket close frame is invalid."); return; }
          if (control.size() >= 2)
          {
            remote_code = (static_cast<unsigned char>(control[0]) << 8) | static_cast<unsigned char>(control[1]);
            if (!IsValidCloseCode(remote_code) || !ValidUtf8(std::string_view(control).substr(2)))
            { fail("WebSocket close frame is invalid."); return; }
          }
          close_payload = control;
          remote_close = true;
          // Stop accepting application sends as soon as a peer close is observed.
          std::lock_guard<std::mutex> lock(state.mutex);
          state.close_requested = true;
        }
        else if (frame.flags & CURLWS_PING)
        {
          pong = control;
          pong_offset = 0;
          pong_started = Clock::now();
          want_write = true;
        }
        control.clear();
        continue;
      }
      const int type = frame.flags & (CURLWS_TEXT | CURLWS_BINARY);
      if (!type || (incoming_type && incoming_type != type)) { fail("WebSocket message type is invalid."); return; }
      incoming_type = type;
      if (bytes > state.request.max_message_bytes - incoming.size()
          || frame.bytesleft > static_cast<curl_off_t>(state.request.max_message_bytes - incoming.size() - bytes))
      { fail("WebSocket message exceeds the size limit."); return; }
      incoming.append(buffer.data(), bytes);
      if (!frame.bytesleft && !(frame.flags & CURLWS_CONT))
      {
        if (type == CURLWS_TEXT && !ValidUtf8(incoming)) { fail("WebSocket text is invalid UTF-8."); return; }
        StreamEvent event;
        event.kind = type == CURLWS_TEXT ? StreamEventKind::WebSocketText : StreamEventKind::WebSocketBinary;
        event.payload = std::move(incoming);
        incoming.clear();
        incoming_type = 0;
        if (!closing && !QueueEvent(state, std::move(event))) return;
      }
    }
    if (outgoing && !want_write) continue;
    pollfd descriptor{socket, static_cast<short>(POLLIN | (want_write ? POLLOUT : 0)), 0};
    if (poll(&descriptor, 1, 50) < 0 && errno != EINTR) { fail("WebSocket poll failed."); return; }
  }
}
}
