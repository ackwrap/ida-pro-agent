#include "ai/stream_client_linux_internal.hpp"

#include "ai/utf8.hpp"
#include <algorithm>
#include <limits>
#include <utility>
#include <vector>

namespace ida_agent::ai
{
namespace stream_client_linux_internal
{

std::size_t EventBytes(const StreamEvent &event)
{
  return event.payload.size() + event.sse.event.size() + event.sse.data.size()
      + event.sse.id.size() + event.message.size();
}

StreamEvent MakeControlEvent(StreamEventKind kind, std::string message)
{
  StreamEvent event;
  event.kind = kind;
  event.message = std::move(message);
  return event;
}

bool IsTerminal(StreamEventKind kind)
{
  return kind == StreamEventKind::Closed || kind == StreamEventKind::Error
      || kind == StreamEventKind::Cancelled;
}

bool IsValidCloseCode(std::uint16_t code)
{
  return (code >= 1000 && code <= 1014
          && code != 1004 && code != 1005 && code != 1006)
      || (code >= 3000 && code <= 4999);
}

} // namespace stream_client_linux_internal

using namespace stream_client_linux_internal;

StreamClient::Impl::Impl() = default;

StreamClient::Impl::~Impl()
{
  Shutdown();
}

StreamClient::StreamId StreamClient::Impl::Open(
    StreamKind kind,
    StreamRequest request)
{
  const std::optional<std::string> validation = ValidateStreamRequest(kind, request);
  std::lock_guard<std::mutex> lock(mutex_);
  if ( streams_.size() >= StreamMaxTracked )
    return 0;
  std::shared_ptr<State> state = std::make_shared<State>();
  state->kind = kind;
  state->id = NextStreamId();
  streams_.emplace(state->id, state);
  if ( validation.has_value() )
  {
    QueueTerminal(*state, MakeControlEvent(StreamEventKind::Error, *validation));
    state->worker_done = true;
  }
  else if ( stopping_ )
  {
    QueueTerminal(
        *state,
        MakeControlEvent(StreamEventKind::Cancelled, "Stream client is stopped."));
    state->worker_done = true;
  }
  else if ( active_streams_ >= StreamMaxConcurrent )
  {
    QueueTerminal(
        *state,
        MakeControlEvent(StreamEventKind::Error, "Stream concurrency limit reached."));
    state->worker_done = true;
  }
  else
  {
    state->request = std::move(request);
    ++active_streams_;
    state->counted_active = true;
    try
    {
      state->worker = std::thread([this, state]
      {
        WorkerMain(state);
      });
    }
    catch ( ... )
    {
      --active_streams_;
      state->counted_active = false;
      state->worker_done = true;
      state->request = {};
      QueueTerminal(
          *state,
          MakeControlEvent(StreamEventKind::Error, "Stream worker could not start."));
    }
  }
  return state->id;
}

std::optional<StreamEvent> StreamClient::Impl::TryTakeEvent(StreamId stream_id)
{
  std::shared_ptr<State> state;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto found = streams_.find(stream_id);
    if ( found == streams_.end() )
      return std::nullopt;
    state = found->second;
  }

  std::optional<StreamEvent> result;
  bool reap = false;
  {
    std::lock_guard<std::mutex> lock(state->mutex);
    if ( state->events.empty() )
    {
      reap = state->terminal_queued && state->worker_done;
    }
    else
    {
      result = std::move(state->events.front());
      state->event_bytes -= EventBytes(*result);
      state->events.pop_front();
      reap = IsTerminal(result->kind) && state->events.empty() && state->worker_done;
    }
  }
  if ( reap )
    Retire(stream_id);
  return result;
}

bool StreamClient::Impl::Retire(StreamId stream_id)
{
  std::shared_ptr<State> state = Find(stream_id);
  if ( state == nullptr )
    return true;
  {
    std::lock_guard<std::mutex> lock(state->mutex);
    if ( !state->terminal_queued || !state->events.empty() || !state->worker_done )
      return false;
  }

  std::unique_lock<std::mutex> shutdown_lock(shutdown_mutex_, std::try_to_lock);
  if ( !shutdown_lock.owns_lock() )
    return false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto found = streams_.find(stream_id);
    if ( found == streams_.end() )
      return true;
    if ( found->second != state )
      return true;
  }
  {
    std::lock_guard<std::mutex> lock(state->mutex);
    if ( !state->terminal_queued || !state->events.empty() || !state->worker_done )
      return false;
  }
  if ( state->worker.joinable() )
    state->worker.join();
  std::lock_guard<std::mutex> lock(mutex_);
  const auto found = streams_.find(stream_id);
  if ( found != streams_.end() && found->second == state )
    streams_.erase(found);
  return true;
}

bool StreamClient::Impl::Send(StreamId stream_id, bool text, std::string payload)
{
  std::shared_ptr<State> state = Find(stream_id);
  if ( state == nullptr || state->kind != StreamKind::WebSocket
      || payload.size() > state->request.max_message_bytes
      || (text && !ValidUtf8(payload)) )
  {
    return false;
  }
  std::lock_guard<std::mutex> lock(state->mutex);
  if ( !state->websocket_open || state->cancelled || state->close_requested
      || state->stop_sender || state->terminal_queued
      || state->send_queue.size() >= StreamHardMaxQueuedEvents
      || payload.size() > state->request.max_queued_bytes - (std::min)(
          state->request.max_queued_bytes,
          state->send_bytes) )
  {
    return false;
  }
  state->send_bytes += payload.size();
  state->send_queue.push_back(OutgoingMessage{text, std::move(payload)});
  return true;
}

void StreamClient::Impl::Close(StreamId stream_id, std::uint16_t close_code)
{
  std::shared_ptr<State> state = Find(stream_id);
  if ( state == nullptr || state->kind != StreamKind::WebSocket )
    return;
  bool invalid_code = false;
  {
    std::lock_guard<std::mutex> lock(state->mutex);
    if ( state->terminal_queued || state->worker_done )
      return;
    if ( state->close_requested )
      return;
    invalid_code = !IsValidCloseCode(close_code);
    state->close_requested = !invalid_code;
    if ( !invalid_code )
    {
      state->close_code = close_code;
    }
    state->stop_sender = invalid_code;
  }
  if ( invalid_code )
  {
    QueueTerminal(
        *state,
        MakeControlEvent(StreamEventKind::Error, "WebSocket close code is invalid."));
  }
}

void StreamClient::Impl::Cancel(StreamId stream_id)
{
  std::shared_ptr<State> state = Find(stream_id);
  if ( state == nullptr )
    return;
  RequestCancel(*state);
}

#ifdef IDA_AGENT_STREAM_CLIENT_TESTING
void StreamClient::Impl::SetWorkerExitDelayForTesting(std::uint32_t delay_ms)
{
  std::lock_guard<std::mutex> lock(mutex_);
  worker_exit_delay_ms_ = delay_ms;
}
#endif

void StreamClient::Impl::Shutdown()
{
  std::lock_guard<std::mutex> shutdown_lock(shutdown_mutex_);
  std::vector<std::shared_ptr<State>> states;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    stopping_ = true;
    states.reserve(streams_.size());
    for ( const auto &entry : streams_ )
      states.push_back(entry.second);
  }
  for ( const std::shared_ptr<State> &state : states )
    RequestCancel(*state);
  for ( const std::shared_ptr<State> &state : states )
  {
    if ( state->worker.joinable() )
      state->worker.join();
  }
}

StreamClient::StreamId StreamClient::Impl::NextStreamId()
{
  StreamId id = next_stream_id_++;
  if ( id == 0 )
    id = next_stream_id_++;
  return id;
}

std::shared_ptr<StreamClient::Impl::State> StreamClient::Impl::Find(
    StreamId stream_id)
{
  std::lock_guard<std::mutex> lock(mutex_);
  const auto found = streams_.find(stream_id);
  return found == streams_.end() ? nullptr : found->second;
}

void StreamClient::Impl::RequestCancel(State &state)
{
  std::lock_guard<std::mutex> lock(state.mutex);
  if ( state.worker_done || state.terminal_queued )
    return;
  state.cancelled = true;
  state.stop_sender = true;
}

bool StreamClient::Impl::IsCancelled(State &state)
{
  std::lock_guard<std::mutex> lock(state.mutex);
  return state.cancelled || state.terminal_queued;
}

bool StreamClient::Impl::QueueEvent(State &state, StreamEvent event)
{
  std::lock_guard<std::mutex> lock(state.mutex);
  if ( state.terminal_queued )
    return false;
  const std::size_t bytes = EventBytes(event);
  if ( state.events.size() >= StreamHardMaxQueuedEvents - 1
      || bytes > state.request.max_queued_bytes - (std::min)(
          state.request.max_queued_bytes,
          state.event_bytes) )
  {
    StreamEvent error = MakeControlEvent(
        StreamEventKind::Error,
        "Stream event queue limit reached.");
    while ( state.events.size() >= StreamHardMaxQueuedEvents )
    {
      state.event_bytes -= EventBytes(state.events.back());
      state.events.pop_back();
    }
    if ( EventBytes(error) > state.request.max_queued_bytes - (std::min)(
            state.request.max_queued_bytes,
            state.event_bytes) )
    {
      error.message.clear();
    }
    state.event_bytes += EventBytes(error);
    state.events.push_back(std::move(error));
    state.terminal_queued = true;
    state.stop_sender = true;
    state.cancelled = true;
    return false;
  }
  state.event_bytes += bytes;
  state.events.push_back(std::move(event));
  return true;
}

void StreamClient::Impl::QueueTerminal(State &state, StreamEvent event)
{
  std::lock_guard<std::mutex> lock(state.mutex);
  if ( state.terminal_queued )
    return;
  while ( state.events.size() >= StreamHardMaxQueuedEvents )
  {
    state.event_bytes -= EventBytes(state.events.back());
    state.events.pop_back();
  }
  std::size_t available = state.request.max_queued_bytes - (std::min)(
      state.request.max_queued_bytes,
      state.event_bytes);
  if ( EventBytes(event) > available )
  {
    event.message.clear();
    if ( EventBytes(event) > available )
    {
      event.payload.clear();
      event.sse = {};
    }
  }
  state.event_bytes += EventBytes(event);
  state.events.push_back(std::move(event));
  state.terminal_queued = true;
  state.stop_sender = true;
}

bool StreamClient::Impl::DeadlineExpired(
    const std::optional<std::chrono::steady_clock::time_point> &deadline)
{
  return deadline.has_value() && std::chrono::steady_clock::now() >= *deadline;
}

std::optional<std::chrono::steady_clock::time_point>
StreamClient::Impl::MakeDeadline(const StreamRequest &request)
{
  if ( !request.overall_timeout_ms.has_value() )
    return std::nullopt;
  return std::chrono::steady_clock::now()
      + std::chrono::milliseconds(*request.overall_timeout_ms);
}

void StreamClient::Impl::WorkerMain(const std::shared_ptr<State> &state)
{
  try
  {
    const auto deadline = MakeDeadline(state->request);
    if ( state->kind == StreamKind::Sse )
      RunSse(*state, deadline);
    else
      RunWebSocket(*state, deadline);
  }
  catch ( ... )
  {
    if ( IsCancelled(*state) )
      QueueTerminal(*state, MakeControlEvent(StreamEventKind::Cancelled, "Stream was cancelled."));
    else
      QueueTerminal(*state, MakeControlEvent(StreamEventKind::Error, "Stream processing failed."));
  }
#ifdef IDA_AGENT_STREAM_CLIENT_TESTING
  std::uint32_t worker_exit_delay_ms = 0;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    worker_exit_delay_ms = worker_exit_delay_ms_;
  }
  if ( worker_exit_delay_ms != 0 )
    std::this_thread::sleep_for(std::chrono::milliseconds(worker_exit_delay_ms));
#endif
  {
    std::lock_guard<std::mutex> lock(state->mutex);
    state->websocket_open = false;
    state->worker_done = true;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  if ( state->counted_active )
  {
    state->counted_active = false;
    --active_streams_;
  }
}

StreamClient::StreamClient() : impl_(std::make_unique<Impl>()) {}

StreamClient::~StreamClient()
{
  Shutdown();
}

StreamClient::StreamId StreamClient::OpenSse(StreamRequest request)
{
  return impl_->Open(StreamKind::Sse, std::move(request));
}

StreamClient::StreamId StreamClient::OpenWebSocket(StreamRequest request)
{
  return impl_->Open(StreamKind::WebSocket, std::move(request));
}

std::optional<StreamEvent> StreamClient::TryTakeEvent(StreamId stream_id)
{
  return impl_->TryTakeEvent(stream_id);
}

bool StreamClient::Retire(StreamId stream_id)
{
  return impl_->Retire(stream_id);
}

bool StreamClient::SendText(StreamId stream_id, std::string payload)
{
  return impl_->Send(stream_id, true, std::move(payload));
}

bool StreamClient::SendBinary(StreamId stream_id, std::string payload)
{
  return impl_->Send(stream_id, false, std::move(payload));
}

void StreamClient::Close(StreamId stream_id, std::uint16_t close_code)
{
  impl_->Close(stream_id, close_code);
}

void StreamClient::Cancel(StreamId stream_id)
{
  impl_->Cancel(stream_id);
}

#ifdef IDA_AGENT_STREAM_CLIENT_TESTING
void StreamClient::SetWorkerExitDelayForTesting(std::uint32_t delay_ms)
{
  impl_->SetWorkerExitDelayForTesting(delay_ms);
}
#endif

void StreamClient::Shutdown()
{
  if ( impl_ != nullptr )
    impl_->Shutdown();
}

} // namespace ida_agent::ai
