#pragma once

#include "ai/network_types.hpp"
#include "ai/sse_parser.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ida_agent::ai
{

constexpr std::size_t StreamHardMaxPayloadBytes = 32 * 1024 * 1024;
constexpr std::size_t StreamHardMaxQueuedBytes = 64 * 1024 * 1024;
constexpr std::size_t StreamHardMaxQueuedEvents = 1024;
constexpr std::size_t StreamHardMaxHeaders = 256;
constexpr std::size_t StreamHardMaxHeaderNameBytes = 256;
constexpr std::size_t StreamHardMaxHeaderValueBytes = 64 * 1024;
constexpr std::size_t StreamHardMaxHeaderBytes = 256 * 1024;
constexpr std::size_t StreamMaxConcurrent = 4;
constexpr std::size_t StreamMaxTracked = 64;

enum class StreamKind
{
  Sse,
  WebSocket,
};

struct StreamRequest
{
  HttpMethod method = HttpMethod::Get;
  std::string url;
  std::string user_agent;
  std::vector<HttpHeader> headers;
  std::string body;
  std::string log_session_id;
  HttpProxyConfig proxy;
  std::uint32_t connect_timeout_ms = 10000;
  std::uint32_t send_timeout_ms = 30000;
  std::uint32_t idle_timeout_ms = 120000;
  std::optional<std::uint64_t> overall_timeout_ms = 30ULL * 60 * 1000;
  std::size_t max_event_bytes = 4 * 1024 * 1024;
  std::size_t max_message_bytes = 4 * 1024 * 1024;
  std::size_t max_queued_bytes = 8 * 1024 * 1024;
};

enum class StreamEventKind
{
  Opened,
  Sse,
  WebSocketText,
  WebSocketBinary,
  Closed,
  Error,
  Cancelled,
};

struct StreamEvent
{
  StreamEventKind kind = StreamEventKind::Error;
  std::uint32_t http_status = 0;
  SseEvent sse;
  std::string payload;
  std::uint16_t close_code = 0;
  std::string message;
};

// Returns a safe diagnostic that never includes URL, headers, body, payload, or
// proxy credentials. The kind is supplied by OpenSse/OpenWebSocket.
std::optional<std::string> ValidateStreamRequest(
    StreamKind kind,
    const StreamRequest &request);

class StreamClient final
{
public:
  using StreamId = std::uint64_t;

  StreamClient();
  ~StreamClient();

  StreamClient(const StreamClient &) = delete;
  StreamClient &operator=(const StreamClient &) = delete;

  // Open returns zero when StreamMaxTracked unconsumed/active records already
  // exist. Otherwise invalid, concurrency-limited, and stopped opens return a
  // nonzero ID with an immediate terminal event through TryTakeEvent. An ID is
  // eligible for retirement after its terminal event is consumed and its
  // worker exits. TryTakeEvent may retire an already-finished record.
  StreamId OpenSse(StreamRequest request);
  StreamId OpenWebSocket(StreamRequest request);
  std::optional<StreamEvent> TryTakeEvent(StreamId stream_id);
  // Retire never waits for an active worker. Unknown/already-retired IDs are
  // successful; known IDs return false until terminal consumption and worker
  // completion are both observable.
  bool Retire(StreamId stream_id);

  // Send returns false for unknown, non-WebSocket, closing, stopped, invalid,
  // or full send queues. Payload bytes are copied before returning true.
  bool SendText(StreamId stream_id, std::string payload);
  bool SendBinary(StreamId stream_id, std::string payload);
  void Close(StreamId stream_id, std::uint16_t close_code = 1000);
  void Cancel(StreamId stream_id);
#ifdef IDA_AGENT_STREAM_CLIENT_TESTING
  void SetWorkerExitDelayForTesting(std::uint32_t delay_ms);
  // Observe completion without consuming events in queue-bound tests.
  bool HasTerminalEventForTesting(StreamId stream_id);
#endif
  void Shutdown();

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace ida_agent::ai
