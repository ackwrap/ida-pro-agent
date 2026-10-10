#pragma once

#include "ai/stream_client_win_internal.hpp"

#include <chrono>
#include <optional>
#include <string>
#include <string_view>

namespace ida_agent::ai::stream_client_win_internal
{

std::optional<DWORD> QueryHttp2StreamError(HINTERNET request) noexcept;

class SseTimeline final
{
public:
  SseTimeline(StreamClient::StreamId stream_id, const StreamRequest &request);

  void Status(std::uint32_t status) const;
  void Read(std::size_t bytes);
  void Parsed(std::size_t count);
  void OperationError(
      std::string_view phase,
      std::string_view operation,
      DWORD error,
      const std::optional<DWORD> &http2_stream_error) const;
  void Terminal(
      std::string_view reason,
      std::string_view detail = {},
      std::uint32_t status = 0) const;
  long long IdleElapsedMs() const;

private:
  using Clock = std::chrono::steady_clock;

  std::string Metrics() const;

  StreamClient::StreamId stream_id_;
  Clock::time_point started_;
  Clock::time_point last_activity_;
  std::size_t response_bytes_ = 0;
  std::size_t parsed_events_ = 0;
};

} // namespace ida_agent::ai::stream_client_win_internal
