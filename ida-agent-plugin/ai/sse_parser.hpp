#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ida_agent::ai
{

constexpr std::size_t SseHardMaxLineBytes = 1024 * 1024;
constexpr std::size_t SseHardMaxEventBytes = 32 * 1024 * 1024;
constexpr std::size_t SseHardMaxScratchBytes = 64 * 1024 * 1024;

struct SseEvent
{
  std::string event;
  std::string data;
  std::string id;
  std::optional<std::uint64_t> retry_ms;
};

enum class SseParseStatus
{
  Ok,
  EventAvailable,
  Finished,
  Error,
};

struct SseParseResult
{
  SseParseStatus status = SseParseStatus::Ok;
  std::vector<SseEvent> events;
  std::string message;
};

struct SseParserLimits
{
  std::size_t max_line_bytes = 64 * 1024;
  std::size_t max_event_bytes = 4 * 1024 * 1024;
  std::size_t max_scratch_bytes = 8 * 1024 * 1024;
};

class SseParser final
{
public:
  explicit SseParser(SseParserLimits limits = {});

  SseParseResult Feed(std::string_view bytes);
  SseParseResult Finish();

private:
  bool CheckScratch(SseParseResult &result);
  bool ProcessLine(SseParseResult &result);
  bool Dispatch(SseParseResult &result);
  bool Fail(SseParseResult &result, std::string message);
  void ResetEvent();

  SseParserLimits limits_;
  std::string line_;
  std::string data_;
  std::string event_;
  std::string last_event_id_;
  std::optional<std::uint64_t> retry_ms_;
  std::string bom_probe_;
  bool data_seen_ = false;
  bool bom_checked_ = false;
  bool pending_cr_ = false;
  bool finished_ = false;
  bool failed_ = false;
  std::string failure_message_;
};

} // namespace ida_agent::ai
