#include "ai/network_diagnostics.hpp"

#include "ai/file_log.hpp"
#include "ai/network_request_logger.hpp"
#include "ai/stream_client.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#include <unistd.h>
#ifdef __APPLE__
#include <pthread.h>
#else
#include <sys/syscall.h>
#endif
#endif

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <memory>
#include <mutex>
#include <string>

namespace ida_agent::ai
{
namespace
{

constexpr std::size_t MaxDetailBytes = 4096;
constexpr std::size_t MaxDebugLogBytes = 4 * 1024 * 1024;

struct LoggingState final
{
  std::mutex mutex;
  std::shared_ptr<FileLog> debug;
  std::shared_ptr<NetworkRequestLogger> network;
};

LoggingState &Logs()
{
  static auto *state = new LoggingState;
  return *state;
}

std::shared_ptr<FileLog> DebugLog()
{
  LoggingState &state = Logs();
  std::lock_guard<std::mutex> lock(state.mutex);
  return state.debug;
}

std::shared_ptr<NetworkRequestLogger> RequestLogger()
{
  LoggingState &state = Logs();
  std::lock_guard<std::mutex> lock(state.mutex);
  return state.network;
}

std::string Clean(std::string_view value, std::size_t limit)
{
  std::string result(value.substr(0, limit));
  for ( char &character : result )
  {
    const unsigned char byte = static_cast<unsigned char>(character);
    if ( byte < 0x20 || byte == 0x7F )
      character = ' ';
  }
  return result;
}

std::string LowerAscii(std::string_view value)
{
  std::string lowered(value);
  std::transform(
      lowered.begin(), lowered.end(), lowered.begin(),
      [](unsigned char character)
      {
        return static_cast<char>(std::tolower(character));
      });
  return lowered;
}

void RedactToken(std::string &value, std::string_view marker)
{
  std::string lowered = LowerAscii(value);
  const std::string lowered_marker = LowerAscii(marker);
  for ( std::size_t found = lowered.find(lowered_marker);
        found != std::string::npos;
        found = lowered.find(lowered_marker, found + 10) )
  {
    std::size_t end = found + marker.size();
    while ( end < value.size()
        && std::isspace(static_cast<unsigned char>(value[end])) )
    {
      ++end;
    }
    while ( end < value.size()
        && !std::isspace(static_cast<unsigned char>(value[end]))
        && value[end] != '"' && value[end] != '\'' )
    {
      ++end;
    }
    value.replace(found, end - found, "<redacted>");
    lowered.replace(found, end - found, "<redacted>");
  }
}

std::string Redact(std::string value)
{
  for ( std::string_view marker : {
            "bearer ", "sk-", "api_key=", "api_key:", "api key:",
            "apikey=", "apikey:", "authorization:", "token=", "token:",
            "password=", "password:", "secret=", "secret:"} )
  {
    RedactToken(value, marker);
  }
  return value;
}

void AppendJsonField(
    std::string &result,
    const nlohmann::json &object,
    std::string_view field)
{
  const auto found = object.find(std::string(field));
  if ( found == object.end() )
    return;
  std::string value;
  if ( found->is_string() )
    value = found->get<std::string>();
  else if ( found->is_number_integer() || found->is_number_unsigned() )
    value = found->dump();
  else
    return;
  if ( !result.empty() )
    result.push_back(' ');
  result += std::string(field) + "=" + Redact(Clean(value, 1024));
}

} // namespace

void ConfigureAiLogging(
    bool debug_logging,
    bool network_logging) noexcept
{
  try
  {
    LoggingState &state = Logs();
    std::lock_guard<std::mutex> lock(state.mutex);
    if ( debug_logging )
    {
      if ( state.debug == nullptr )
      {
        const std::filesystem::path root = McpLogDirectory();
        if ( !root.empty() )
        {
          state.debug = std::make_shared<FileLog>(
              root / L"debug.log", MaxDebugLogBytes);
        }
      }
    }
    else
    {
      state.debug.reset();
    }
    if ( network_logging )
    {
      if ( state.network == nullptr )
      {
        const std::filesystem::path root = McpLogDirectory();
        if ( !root.empty() )
        {
          state.network = std::make_shared<NetworkRequestLogger>(root / L"network");
          state.network->Configure(true);
        }
      }
    }
    else
    {
      if ( state.network != nullptr )
        state.network->Configure(false);
      state.network.reset();
    }
  }
  catch ( ... )
  {
  }
}

bool AiNetworkDiagnosticsEnabled() noexcept
{
  try
  {
    return DebugLog() != nullptr;
  }
  catch ( ... )
  {
    return false;
  }
}

bool AiNetworkRequestLoggingEnabled() noexcept
{
  try
  {
    return RequestLogger() != nullptr;
  }
  catch ( ... )
  {
    return false;
  }
}

void LogAiNetworkDiagnostic(
    std::string_view phase,
    std::string_view detail,
    std::uint32_t http_status,
    std::uint64_t stream_id) noexcept
{
  try
  {
    if ( !AiNetworkDiagnosticsEnabled() )
      return;
#ifdef __APPLE__
    std::uint64_t thread_id = 0;
    pthread_threadid_np(nullptr, &thread_id);
#endif
    std::string line = "[" + FileLogTimestamp() + "] pid="
#ifdef _WIN32
        + std::to_string(GetCurrentProcessId()) + " tid="
        + std::to_string(GetCurrentThreadId()) + " phase="
#elif defined(__APPLE__)
        + std::to_string(getpid()) + " tid="
        + std::to_string(thread_id) + " phase="
#else
        + std::to_string(getpid()) + " tid="
        + std::to_string(syscall(SYS_gettid)) + " phase="
#endif
        + Clean(phase, 128);
    if ( stream_id != 0 )
      line += " stream=" + std::to_string(stream_id);
    if ( http_status != 0 )
      line += " http=" + std::to_string(http_status);
    if ( !detail.empty() )
      line += " detail=" + Redact(Clean(detail, MaxDetailBytes));
    line.push_back('\n');
    if ( const std::shared_ptr<FileLog> log = DebugLog() )
      log->Append(line);
  }
  catch ( ... )
  {
  }
}

void BeginAiNetworkExchangeLog(
    StreamKind,
    const StreamRequest &request,
    std::uint64_t stream_id) noexcept
{
  try
  {
    if ( const std::shared_ptr<NetworkRequestLogger> logger = RequestLogger() )
    {
      logger->Begin(
          stream_id,
          request.log_session_id,
          request.body);
    }
  }
  catch ( ... )
  {
  }
}

void LogAiNetworkResponseStatus(
    std::uint64_t stream_id,
    std::uint32_t http_status) noexcept
{
  try
  {
    if ( const std::shared_ptr<NetworkRequestLogger> logger = RequestLogger() )
      logger->ResponseStatus(stream_id, http_status);
  }
  catch ( ... )
  {
  }
}

void AppendAiNetworkResponseLog(
    std::uint64_t stream_id,
    std::string_view bytes) noexcept
{
  try
  {
    if ( const std::shared_ptr<NetworkRequestLogger> logger = RequestLogger() )
      logger->AppendResponse(stream_id, bytes);
  }
  catch ( ... )
  {
  }
}

void EndAiNetworkExchangeLog(std::uint64_t stream_id) noexcept
{
  try
  {
    if ( const std::shared_ptr<NetworkRequestLogger> logger = RequestLogger() )
      logger->End(stream_id);
  }
  catch ( ... )
  {
  }
}

std::string SanitizeAiNetworkErrorBody(std::string_view body) noexcept
{
  try
  {
    const nlohmann::json document = nlohmann::json::parse(body, nullptr, false);
    if ( document.is_discarded() || !document.is_object() )
      return "message=" + Redact(Clean(body, MaxDetailBytes));
    const nlohmann::json *error = &document;
    const auto nested = document.find("error");
    if ( nested != document.end() )
    {
      if ( nested->is_object() )
        error = &*nested;
      else if ( nested->is_string() )
        return "message=" + Redact(Clean(nested->get<std::string>(), 1024));
    }
    std::string result;
    for ( std::string_view field : {"type", "code", "param", "message"} )
      AppendJsonField(result, *error, field);
    return result.empty()
        ? "json error body bytes=" + std::to_string(body.size())
        : result;
  }
  catch ( ... )
  {
    return "error body sanitization failed";
  }
}

} // namespace ida_agent::ai
