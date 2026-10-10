#include "ai/stream_client_linux_internal.hpp"
#include "ai/stream_curl_linux.hpp"
#include "ai/network_diagnostics.hpp"
#include <algorithm>
#include <charconv>
#include <functional>
#include <limits>

namespace ida_agent::ai
{
using namespace stream_client_linux_internal;
namespace
{
struct SseTransfer
{
  explicit SseTransfer(const StreamRequest &request)
      : parser({64 * 1024, request.max_event_bytes,
          std::min(SseHardMaxScratchBytes, request.max_event_bytes + SseHardMaxLineBytes)}) {}
  SseParser parser;
  std::function<bool(StreamEvent)> emit;
  std::function<bool()> cancelled;
  std::uint64_t id = 0;
  std::size_t header_bytes = 0;
  std::uint32_t status = 0;
  bool valid_type = false, opened = false, failed = false;
  curl_off_t uploaded = 0;
  Clock::time_point received = Clock::now();
  std::string error;
  std::string error_body;

  bool Deliver(SseParseResult result)
  {
    for (auto &value : result.events)
    {
      StreamEvent event;
      event.kind = StreamEventKind::Sse;
      event.sse = std::move(value);
      if (!emit(std::move(event))) return false;
    }
    if (result.status == SseParseStatus::Error)
    {
      error = std::move(result.message);
      failed = true;
      return false;
    }
    return true;
  }
};
std::size_t Header(char *data, std::size_t size, std::size_t count, void *context) noexcept
{
  auto &transfer = *static_cast<SseTransfer *>(context);
  try
  {
    if (transfer.cancelled() || (size && count > std::numeric_limits<std::size_t>::max() / size)) return 0;
    const auto bytes = size * count;
    if (bytes > StreamHardMaxHeaderBytes - transfer.header_bytes) return 0;
    transfer.header_bytes += bytes;
    transfer.received = Clock::now();
    std::string_view line(data, bytes);
    if (line.substr(0, 5) == "HTTP/")
    {
      auto offset = line.find(' ');
      if (offset == std::string_view::npos) return 0;
      transfer.status = 0;
      std::from_chars(line.data() + offset + 1, line.data() + line.size(), transfer.status);
      transfer.valid_type = false;
      transfer.error_body.clear();
    }
    else
    {
      std::string lower(line);
      std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c)
          { return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : static_cast<char>(c); });
      if (lower.substr(0, 13) == "content-type:")
      {
        auto first = lower.find_first_not_of(" \t", 13);
        auto end = lower.find_first_of(";\r\n", first);
        auto type = first == std::string::npos ? std::string{} : lower.substr(first, end - first);
        while (!type.empty() && (type.back() == ' ' || type.back() == '\t')) type.pop_back();
        transfer.valid_type = type == "text/event-stream";
      }
    }
    if (!transfer.opened && line == "\r\n" && transfer.status >= 200 && transfer.status < 300 && transfer.valid_type)
    {
      transfer.opened = true;
      StreamEvent event;
      event.kind = StreamEventKind::Opened;
      event.http_status = transfer.status;
      LogAiNetworkResponseStatus(transfer.id, transfer.status);
      if (!transfer.emit(std::move(event))) return 0;
    }
    return bytes;
  }
  catch (...) { return 0; }
}
std::size_t Write(char *data, std::size_t size, std::size_t count, void *context) noexcept
{
  auto &transfer = *static_cast<SseTransfer *>(context);
  try
  {
    if (transfer.cancelled() || (size && count > std::numeric_limits<std::size_t>::max() / size)) return 0;
    const auto bytes = size * count;
    transfer.received = Clock::now();
    if (!transfer.opened)
    {
      constexpr std::size_t ErrorLimit = 8 * 1024;
      transfer.error_body.append(data, std::min(bytes, ErrorLimit - transfer.error_body.size()));
      return transfer.error_body.size() < ErrorLimit ? bytes : 0;
    }
    AppendAiNetworkResponseLog(transfer.id, {data, bytes});
    return transfer.Deliver(transfer.parser.Feed({data, bytes})) ? bytes : 0;
  }
  catch (...) { return 0; }
}
int Progress(void *context, curl_off_t, curl_off_t, curl_off_t, curl_off_t uploaded) noexcept
{
  auto &transfer = *static_cast<SseTransfer *>(context);
  transfer.uploaded = uploaded;
  return 0;
}
}

void StreamClient::Impl::RunSse(State &state, const std::optional<Clock::time_point> &deadline)
{
  CurlStream connection(state.request);
  SseTransfer transfer(state.request);
  transfer.id = state.id;
  transfer.emit = [&](StreamEvent event) { return QueueEvent(state, std::move(event)); };
  transfer.cancelled = [&] { return IsCancelled(state); };
  BeginAiNetworkExchangeLog(StreamKind::Sse, state.request, state.id);
  struct EndLog { std::uint64_t id; ~EndLog() { EndAiNetworkExchangeLog(id); } } log{state.id};
  auto *easy = connection.easy.get();
  Set(easy, CURLOPT_HEADERFUNCTION, &Header);
  Set(easy, CURLOPT_HEADERDATA, &transfer);
  Set(easy, CURLOPT_WRITEFUNCTION, &Write);
  Set(easy, CURLOPT_WRITEDATA, &transfer);
  Set(easy, CURLOPT_NOPROGRESS, 0L);
  Set(easy, CURLOPT_XFERINFOFUNCTION, &Progress);
  Set(easy, CURLOPT_XFERINFODATA, &transfer);
  connection.Start();
  Clock::time_point send_started{};
  bool upload_complete = false;
  auto fail = [&](std::string message)
  {
    auto event = MakeControlEvent(StreamEventKind::Error, std::move(message));
    event.http_status = transfer.status;
    QueueTerminal(state, std::move(event));
  };
  while (true)
  {
    if (IsCancelled(state))
    {
      QueueTerminal(state, MakeControlEvent(StreamEventKind::Cancelled, "Stream was cancelled."));
      return;
    }
    if (DeadlineExpired(deadline)) { fail("Stream overall timeout expired."); return; }
    if (auto completed = connection.Perform())
    {
      if (IsCancelled(state)) continue;
      if (transfer.status && (transfer.status < 200 || transfer.status >= 300))
        fail(SanitizeAiNetworkErrorBody(transfer.error_body));
      else if (transfer.status && !transfer.valid_type) fail("SSE response content type is invalid.");
      else if (transfer.failed) fail(transfer.error);
      else if (*completed != CURLE_OK) fail("SSE network transfer failed (curl=" + std::to_string(*completed) + ").");
      else if (!transfer.opened) fail("SSE response headers are invalid.");
      else if (!transfer.Deliver(transfer.parser.Finish())) fail(transfer.error);
      else QueueTerminal(state, MakeControlEvent(StreamEventKind::Closed));
      return;
    }
    const auto now = Clock::now();
    curl_off_t pretransfer = 0;
    curl_easy_getinfo(easy, CURLINFO_PRETRANSFER_TIME_T, &pretransfer);
    if (pretransfer > 0)
    {
      if (send_started == Clock::time_point{}) send_started = now;
      if (!upload_complete && transfer.uploaded >= static_cast<curl_off_t>(state.request.body.size()))
      {
        upload_complete = true;
        transfer.received = now;
      }
      if (upload_complete && now - transfer.received >= std::chrono::milliseconds(state.request.idle_timeout_ms))
      { fail("SSE idle timeout expired."); return; }
      if (!upload_complete && now - send_started >= std::chrono::milliseconds(state.request.send_timeout_ms))
      { fail("SSE send timeout expired."); return; }
    }
    connection.Poll();
  }
}
}
