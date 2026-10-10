#include "ai/stream_client_win_internal.hpp"

#include "ai/network_diagnostics.hpp"

#include <algorithm>
#include <array>
#include <utility>

namespace ida_agent::ai
{

using namespace stream_client_win_internal;

void StreamClient::Impl::SenderMain(State &state, HINTERNET websocket)
{
  while ( true )
  {
    OutgoingMessage message;
    {
      std::unique_lock<std::mutex> lock(state.mutex);
      state.send_ready.wait(lock, [&state]
      {
        return state.stop_sender || state.close_requested
            || !state.send_queue.empty();
      });
      if ( state.close_requested && !state.cancelled
          && !state.remote_close_received && !state.close_shutdown_sent )
      {
        const std::uint16_t close_code = state.close_code;
        state.close_shutdown_sent = true;
        lock.unlock();
        const DWORD status = WinHttpWebSocketShutdown(
            websocket,
            close_code,
            nullptr,
            0);
        if ( status != NO_ERROR )
        {
          HANDLE receiver = nullptr;
          {
            std::lock_guard<std::mutex> failure_lock(state.mutex);
            if ( !state.cancelled )
              state.sender_failed = true;
            state.stop_sender = true;
            receiver = state.receiver_handle;
          }
          if ( receiver != nullptr )
            CancelSynchronousIo(receiver);
          return;
        }
        HANDLE receiver = nullptr;
        lock.lock();
        const bool completed = state.close_ready.wait_for(
            lock,
            std::chrono::milliseconds(WebSocketCloseTimeoutMs),
            [&state]
            {
              return state.remote_close_received || state.stop_sender
                  || state.cancelled;
            });
        if ( !completed )
          receiver = state.receiver_handle;
        lock.unlock();
        if ( receiver != nullptr )
          CancelSynchronousIo(receiver);
        return;
      }
      if ( state.stop_sender || state.cancelled || state.remote_close_received )
        return;
      message = std::move(state.send_queue.front());
      state.send_bytes -= message.payload.size();
      state.send_queue.pop_front();
    }
    const WINHTTP_WEB_SOCKET_BUFFER_TYPE type = message.text
        ? WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE
        : WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE;
    const DWORD status = WinHttpWebSocketSend(
        websocket,
        type,
        message.payload.empty() ? nullptr : message.payload.data(),
        static_cast<DWORD>(message.payload.size()));
    if ( status != NO_ERROR )
    {
      {
        std::lock_guard<std::mutex> lock(state.mutex);
        if ( !state.cancelled && !state.close_requested )
          state.sender_failed = true;
        state.stop_sender = true;
      }
      HANDLE receiver = nullptr;
      {
        std::lock_guard<std::mutex> lock(state.mutex);
        receiver = state.receiver_handle;
      }
      if ( receiver != nullptr )
        CancelSynchronousIo(receiver);
      return;
    }
  }
}

void StreamClient::Impl::StopAndJoinSender(State &state)
{
  HANDLE sender = nullptr;
  bool interrupt_sender = true;
  {
    std::lock_guard<std::mutex> lock(state.mutex);
    const bool local_close_needs_shutdown = state.close_requested
        && !state.cancelled && !state.remote_close_received
        && !state.close_shutdown_sent;
    if ( !local_close_needs_shutdown )
      state.stop_sender = true;
    interrupt_sender = !local_close_needs_shutdown;
    state.send_ready.notify_all();
    state.close_ready.notify_all();
    sender = state.sender_handle;
  }
  if ( interrupt_sender && sender != nullptr )
    CancelSynchronousIo(sender);
  if ( state.sender.joinable() )
    state.sender.join();
  {
    std::lock_guard<std::mutex> lock(state.mutex);
    state.sender_handle = nullptr;
  }
}

void StreamClient::Impl::CloseWebSocketHandle(
    State &state,
    HINTERNET websocket,
    std::uint16_t code)
{
  DWORD timeout = WebSocketCloseTimeoutMs;
  WinHttpSetOption(
      websocket,
      WINHTTP_OPTION_WEB_SOCKET_CLOSE_TIMEOUT,
      &timeout,
      sizeof(timeout));
  WinHttpWebSocketClose(websocket, code, nullptr, 0);
  std::lock_guard<std::mutex> lock(state.mutex);
  state.websocket_open = false;
}

void StreamClient::Impl::RunWebSocket(
    State &state,
    const std::optional<std::chrono::steady_clock::time_point> &deadline)
{
  LogAiNetworkDiagnostic(
      "websocket.open.begin",
      "bodyBytes=" + std::to_string(state.request.body.size()),
      0,
      state.id);
  BeginAiNetworkExchangeLog(StreamKind::WebSocket, state.request, state.id);
  struct NetworkLogGuard final
  {
    StreamClient::StreamId stream_id;
    ~NetworkLogGuard() { EndAiNetworkExchangeLog(stream_id); }
  } network_log_guard{state.id};
  RequestHandles handles;
  std::string error;
  if ( !OpenHttpRequest(state, handles, deadline, error) )
  {
    if ( IsCancelled(state) )
      QueueTerminal(state, MakeControlEvent(StreamEventKind::Cancelled, "Stream was cancelled."));
    else if ( IsCloseRequested(state) )
      QueueTerminal(state, MakeControlEvent(StreamEventKind::Closed, "WebSocket was closed."));
    else
    {
      LogAiNetworkDiagnostic("websocket.open.error", error, 0, state.id);
      QueueTerminal(state, MakeControlEvent(StreamEventKind::Error, std::move(error)));
    }
    return;
  }
  LogAiNetworkResponseStatus(state.id, handles.status_code);
  if ( handles.status_code != 101 )
  {
    const std::string body = ReadErrorBody(
        state, handles, deadline);
    if ( IsCancelled(state) )
    {
      QueueTerminal(
          state,
          MakeControlEvent(StreamEventKind::Cancelled, "Stream was cancelled."));
      return;
    }
    if ( DeadlineExpired(deadline) )
    {
      QueueTerminal(
          state,
          MakeControlEvent(StreamEventKind::Error, "Stream overall timeout expired."));
      return;
    }
    std::string detail = SanitizeAiNetworkErrorBody(body);
    LogAiNetworkDiagnostic(
        "websocket.http.error",
        detail,
        handles.status_code,
        state.id);
    StreamEvent rejected = MakeControlEvent(
        StreamEventKind::Error,
        std::move(detail));
    rejected.http_status = handles.status_code;
    QueueTerminal(state, std::move(rejected));
    return;
  }
  LogAiNetworkDiagnostic(
      "websocket.open.status", {}, handles.status_code, state.id);
  InternetHandle websocket(WinHttpWebSocketCompleteUpgrade(handles.request.get(), 0));
  handles.request.reset();
  if ( !websocket )
  {
    QueueTerminal(state, MakeControlEvent(StreamEventKind::Error, "WebSocket upgrade failed."));
    return;
  }
  {
    std::lock_guard<std::mutex> lock(state.mutex);
    state.websocket_open = true;
    if ( state.cancelled )
      state.stop_sender = true;
    else
    {
      state.sender = std::thread([&state, handle = websocket.get()]
      {
        SenderMain(state, handle);
      });
      state.sender_handle = state.sender.native_handle();
    }
  }
  struct SenderJoinGuard
  {
    State &state;
    ~SenderJoinGuard() { Impl::StopAndJoinSender(state); }
  } sender_join_guard{state};
  StreamEvent opened;
  opened.kind = StreamEventKind::Opened;
  opened.http_status = handles.status_code;
  if ( !QueueEvent(state, std::move(opened)) )
  {
    StopAndJoinSender(state);
    return;
  }

  std::array<char, 16 * 1024> buffer{};
  std::string message;
  bool assembling = false;
  bool text_message = false;
  while ( true )
  {
    if ( IsCancelled(state) || DeadlineExpired(deadline) )
      break;
    int receive_timeout = RemainingReceiveTimeout(state, deadline);
    WinHttpSetOption(
        websocket.get(),
        WINHTTP_OPTION_RECEIVE_TIMEOUT,
        &receive_timeout,
        sizeof(receive_timeout));
    DWORD read = 0;
    WINHTTP_WEB_SOCKET_BUFFER_TYPE type = WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE;
    const DWORD status = WinHttpWebSocketReceive(
        websocket.get(),
        buffer.data(),
        static_cast<DWORD>(buffer.size()),
        &read,
        &type);
    if ( status != NO_ERROR )
      break;
    if ( type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE )
    {
      {
        std::lock_guard<std::mutex> lock(state.mutex);
        state.remote_close_received = true;
        state.close_ready.notify_all();
      }
      StopAndJoinSender(state);
      USHORT close_status = 1000;
      std::array<char, 256> reason{};
      DWORD reason_size = 0;
      if ( WinHttpWebSocketQueryCloseStatus(
               websocket.get(),
               &close_status,
               reason.data(),
               static_cast<DWORD>(reason.size()),
               &reason_size)
          != NO_ERROR )
      {
        close_status = 1006;
      }
      const std::uint16_t echoed_status = IsValidCloseCode(close_status)
          ? close_status
          : 1000;
      CloseWebSocketHandle(state, websocket.get(), echoed_status);
      StreamEvent closed = MakeControlEvent(StreamEventKind::Closed, "WebSocket peer closed the connection.");
      closed.close_code = close_status;
      QueueTerminal(state, std::move(closed));
      return;
    }

    const bool fragment = type == WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE
        || type == WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE;
    const bool final_text = type == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE;
    const bool final_binary = type == WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE;
    const bool current_text = fragment
        ? type == WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE
        : final_text;
    if ( (!fragment && !final_text && !final_binary)
        || (assembling && current_text != text_message) )
    {
      StopAndJoinSender(state);
      QueueTerminal(state, MakeControlEvent(StreamEventKind::Error, "WebSocket fragment sequence is invalid."));
      return;
    }
    if ( !assembling )
      text_message = current_text;
    if ( read > state.request.max_message_bytes - (std::min)(
            state.request.max_message_bytes,
            message.size()) )
    {
      StopAndJoinSender(state);
      QueueTerminal(state, MakeControlEvent(StreamEventKind::Error, "WebSocket message exceeds the size limit."));
      return;
    }
    message.append(buffer.data(), read);
    AppendAiNetworkResponseLog(
        state.id,
        std::string_view(buffer.data(), read));
    if ( fragment )
    {
      assembling = true;
      continue;
    }
    if ( text_message && !IsValidUtf8(message) )
    {
      StopAndJoinSender(state);
      QueueTerminal(state, MakeControlEvent(StreamEventKind::Error, "WebSocket text contains invalid UTF-8."));
      return;
    }
    StreamEvent received;
    received.kind = text_message
        ? StreamEventKind::WebSocketText
        : StreamEventKind::WebSocketBinary;
    received.payload = std::move(message);
    if ( !QueueEvent(state, std::move(received)) )
    {
      StopAndJoinSender(state);
      return;
    }
    message.clear();
    assembling = false;
  }

  StopAndJoinSender(state);
  bool cancelled = false;
  bool closing = false;
  bool sender_failed = false;
  std::uint16_t close_code = 1000;
  {
    std::lock_guard<std::mutex> lock(state.mutex);
    cancelled = state.cancelled;
    closing = state.close_requested;
    sender_failed = state.sender_failed;
    close_code = state.close_code;
  }
  if ( closing && !cancelled )
  {
    CloseWebSocketHandle(state, websocket.get(), close_code);
    StreamEvent closed = MakeControlEvent(StreamEventKind::Closed, "WebSocket was closed.");
    closed.close_code = close_code;
    QueueTerminal(state, std::move(closed));
  }
  else if ( cancelled )
  {
    QueueTerminal(state, MakeControlEvent(StreamEventKind::Cancelled, "Stream was cancelled."));
  }
  else if ( DeadlineExpired(deadline) )
  {
    QueueTerminal(state, MakeControlEvent(StreamEventKind::Error, "Stream overall timeout expired."));
  }
  else if ( sender_failed )
  {
    QueueTerminal(state, MakeControlEvent(StreamEventKind::Error, "WebSocket send failed."));
  }
  else
  {
    QueueTerminal(state, MakeControlEvent(StreamEventKind::Error, "WebSocket receive failed or became idle."));
  }
}

} // namespace ida_agent::ai
