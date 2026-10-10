#pragma once

#include "ai/stream_client.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winhttp.h>

#include <chrono>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <string_view>
#include <thread>
#include <unordered_map>

namespace ida_agent::ai
{
namespace stream_client_win_internal
{

constexpr DWORD ErrorBodyReadLimit = 8 * 1024;
constexpr DWORD WebSocketCloseTimeoutMs = 2000;

std::wstring Utf8ToWide(std::string_view value);
bool IsValidUtf8(std::string_view value);
std::string LowerAscii(std::string_view value);
std::wstring FormatProxyEndpoint(const HttpProxyConfig &proxy);
DWORD SelectProxyAuthScheme(DWORD supported_schemes);
const char *WinHttpErrorSymbol(DWORD error) noexcept;
std::string FormatWinHttpSseError(
    std::string_view operation,
    DWORD error,
    std::optional<DWORD> http2_stream_error = std::nullopt);

class InternetHandle final
{
public:
  explicit InternetHandle(HINTERNET handle = nullptr) : handle_(handle) {}
  ~InternetHandle() { reset(); }

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

class WinHttpAsyncRequest;

struct RequestHandles
{
  // Destroy the request before releasing our callback/buffer owner.
  std::shared_ptr<WinHttpAsyncRequest> async;
  InternetHandle session;
  InternetHandle connection;
  InternetHandle request;
  std::uint32_t status_code = 0;
};

std::size_t EventBytes(const StreamEvent &event);
StreamEvent MakeControlEvent(StreamEventKind kind, std::string message = {});
bool IsTerminal(StreamEventKind kind);
bool IsValidCloseCode(std::uint16_t code);

} // namespace stream_client_win_internal

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
    std::condition_variable send_ready;
    std::condition_variable close_ready;
    std::deque<StreamEvent> events;
    std::deque<OutgoingMessage> send_queue;
    std::size_t event_bytes = 0;
    std::size_t send_bytes = 0;
    bool cancelled = false;
    bool close_requested = false;
    bool close_shutdown_sent = false;
    bool remote_close_received = false;
    bool stop_sender = false;
    bool sender_failed = false;
    bool websocket_open = false;
    bool terminal_queued = false;
    bool worker_done = false;
    bool counted_active = false;
    std::uint16_t close_code = 1000;
    HANDLE receiver_handle = nullptr;
    HANDLE sender_handle = nullptr;
    std::thread worker;
    std::thread sender;
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
  static void Interrupt(State &state);
  static void RequestCancel(State &state);
  static bool IsCancelled(State &state);
  static bool IsCloseRequested(State &state);
  static bool QueueEvent(State &state, StreamEvent event);
  static void QueueTerminal(State &state, StreamEvent event);
  static bool DeadlineExpired(
      const std::optional<std::chrono::steady_clock::time_point> &deadline);
  static int RemainingReceiveTimeout(
      const State &state,
      const std::optional<std::chrono::steady_clock::time_point> &deadline);
  static std::optional<std::chrono::steady_clock::time_point> MakeDeadline(
      const StreamRequest &request);
  static bool AddHeaders(HINTERNET request_handle, const State &state);
  static bool OpenHttpRequest(
      State &state,
      stream_client_win_internal::RequestHandles &handles,
      const std::optional<std::chrono::steady_clock::time_point> &deadline,
      std::string &error);
  static std::string ReadErrorBody(
      State &state,
      stream_client_win_internal::RequestHandles &handles,
      const std::optional<std::chrono::steady_clock::time_point> &deadline);
  static void RunSse(
      State &state,
      const std::optional<std::chrono::steady_clock::time_point> &deadline);
  static void SenderMain(State &state, HINTERNET websocket);
  static void StopAndJoinSender(State &state);
  static void CloseWebSocketHandle(
      State &state,
      HINTERNET websocket,
      std::uint16_t code);
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
