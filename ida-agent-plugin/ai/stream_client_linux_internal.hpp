#pragma once

#include "ai/stream_client.hpp"

#include <chrono>
#include <deque>
#include <memory>
#include <mutex>
#include <string_view>
#include <thread>
#include <unordered_map>

namespace ida_agent::ai
{
namespace stream_client_linux_internal
{

std::size_t EventBytes(const StreamEvent &event);
StreamEvent MakeControlEvent(StreamEventKind kind, std::string message = {});
bool IsTerminal(StreamEventKind kind);
bool IsValidCloseCode(std::uint16_t code);

} // namespace stream_client_linux_internal

struct StreamClient::Impl final
{
  struct OutgoingMessage
  {
    bool text = false;
    std::string payload;
  };

  struct State
  {
    StreamId id = 0;
    StreamKind kind = StreamKind::Sse;
    StreamRequest request;
    std::mutex mutex;
    std::deque<StreamEvent> events;
    std::deque<OutgoingMessage> send_queue;
    std::size_t event_bytes = 0;
    std::size_t send_bytes = 0;
    bool cancelled = false;
    bool close_requested = false;
    bool stop_sender = false;
    bool websocket_open = false;
    bool terminal_queued = false;
    bool worker_done = false;
    bool counted_active = false;
    std::uint16_t close_code = 1000;
    std::thread worker;
  };

  Impl();
  ~Impl();

  StreamId Open(StreamKind kind, StreamRequest request);
  std::optional<StreamEvent> TryTakeEvent(StreamId stream_id);
  bool Retire(StreamId stream_id);
  bool Send(StreamId stream_id, bool text, std::string payload);
  void Close(StreamId stream_id, std::uint16_t close_code);
  void Cancel(StreamId stream_id);
#ifdef IDA_AGENT_STREAM_CLIENT_TESTING
  void SetWorkerExitDelayForTesting(std::uint32_t delay_ms);
  bool HasTerminalEventForTesting(StreamId stream_id);
#endif
  void Shutdown();

private:
  StreamId NextStreamId();
  std::shared_ptr<State> Find(StreamId stream_id);
  static void RequestCancel(State &state);
  static bool IsCancelled(State &state);
  static bool QueueEvent(State &state, StreamEvent event);
  static void QueueTerminal(State &state, StreamEvent event);
  static bool DeadlineExpired(
      const std::optional<std::chrono::steady_clock::time_point> &deadline);
  static std::optional<std::chrono::steady_clock::time_point> MakeDeadline(
      const StreamRequest &request);
  static void RunSse(
      State &state,
      const std::optional<std::chrono::steady_clock::time_point> &deadline);
  static void RunWebSocket(
      State &state,
      const std::optional<std::chrono::steady_clock::time_point> &deadline);
  void WorkerMain(const std::shared_ptr<State> &state);

  std::mutex mutex_;
  std::mutex shutdown_mutex_;
  std::unordered_map<StreamId, std::shared_ptr<State>> streams_;
  StreamId next_stream_id_ = 1;
  std::size_t active_streams_ = 0;
  bool stopping_ = false;
#ifdef IDA_AGENT_STREAM_CLIENT_TESTING
  std::uint32_t worker_exit_delay_ms_ = 0;
#endif
};

} // namespace ida_agent::ai
