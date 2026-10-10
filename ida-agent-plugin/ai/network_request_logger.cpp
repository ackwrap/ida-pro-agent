#include "ai/network_request_logger.hpp"

#include <algorithm>
#include <utility>

namespace ida_agent::ai
{

NetworkRequestLogger::NetworkRequestLogger(std::filesystem::path root)
    : root_(std::move(root))
{
  if ( root_.empty() )
  {
    const std::filesystem::path logs = McpLogDirectory();
    if ( !logs.empty() )
      root_ = logs / L"network";
  }
}

void NetworkRequestLogger::Configure(bool enabled) noexcept
{
  std::lock_guard<std::mutex> lock(mutex_);
  enabled_ = enabled;
  if ( !enabled_ )
  {
    exchanges_.clear();
    session_logs_.clear();
  }
}

bool NetworkRequestLogger::Enabled() const noexcept
{
  std::lock_guard<std::mutex> lock(mutex_);
  return enabled_;
}

void NetworkRequestLogger::Begin(
    std::uint64_t stream_id,
    std::string_view session_id,
    std::string_view request_content) noexcept
{
  try
  {
    std::shared_ptr<FileLog> log;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if ( !enabled_ || root_.empty() || stream_id == 0 || session_id.empty() )
        return;
      const std::optional<std::string> safe_id = SafeSessionId(session_id);
      if ( !safe_id.has_value() )
        return;
      auto &session_log = session_logs_[std::string(session_id)];
      if ( session_log == nullptr )
      {
        session_log = std::make_shared<FileLog>(
            root_ / (L"session-" + std::filesystem::path(*safe_id).wstring()
                + L".log"),
            0,
            0);
      }
      log = session_log;
      exchanges_[stream_id] = log;
    }
    std::string record = "\n[" + FileLogTimestamp() + "] request stream="
        + std::to_string(stream_id) + " bytes="
        + std::to_string(request_content.size()) + "\n";
    record.append(request_content);
    record.push_back('\n');
    log->Append(record);
  }
  catch ( ... )
  {
  }
}

void NetworkRequestLogger::ResponseStatus(
    std::uint64_t stream_id,
    std::uint32_t status) noexcept
{
  try
  {
    const std::shared_ptr<FileLog> log = ExchangeLog(stream_id);
    if ( log == nullptr )
      return;
    log->Append(
        "[" + FileLogTimestamp() + "] response stream="
        + std::to_string(stream_id) + " status=" + std::to_string(status)
        + "\n");
  }
  catch ( ... )
  {
  }
}

void NetworkRequestLogger::AppendResponse(
    std::uint64_t stream_id,
    std::string_view content) noexcept
{
  try
  {
    const std::shared_ptr<FileLog> log = ExchangeLog(stream_id);
    if ( log != nullptr && !content.empty() )
      log->Append(content);
  }
  catch ( ... )
  {
  }
}

void NetworkRequestLogger::End(std::uint64_t stream_id) noexcept
{
  try
  {
    std::shared_ptr<FileLog> log;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      const auto found = exchanges_.find(stream_id);
      if ( found == exchanges_.end() )
        return;
      log = found->second;
      exchanges_.erase(found);
    }
    log->Append(
        "\n[" + FileLogTimestamp() + "] response.end stream="
        + std::to_string(stream_id) + "\n");
  }
  catch ( ... )
  {
  }
}

std::optional<std::string> NetworkRequestLogger::SafeSessionId(
    std::string_view session_id)
{
  if ( session_id.empty() || session_id.size() > 64 )
    return std::nullopt;
  constexpr char Hex[] = "0123456789ABCDEF";
  std::string safe;
  safe.reserve(session_id.size() * 3);
  for ( const unsigned char character : session_id )
  {
    const bool plain = (character >= 'A' && character <= 'Z')
        || (character >= 'a' && character <= 'z')
        || (character >= '0' && character <= '9')
        || character == '-' || character == '_';
    if ( plain )
    {
      safe.push_back(static_cast<char>(character));
      continue;
    }
    safe.push_back('~');
    safe.push_back(Hex[character >> 4]);
    safe.push_back(Hex[character & 0x0F]);
  }
  return safe;
}

std::shared_ptr<FileLog> NetworkRequestLogger::ExchangeLog(
    std::uint64_t stream_id) const
{
  std::lock_guard<std::mutex> lock(mutex_);
  if ( !enabled_ )
    return {};
  const auto found = exchanges_.find(stream_id);
  return found == exchanges_.end() ? nullptr : found->second;
}

} // namespace ida_agent::ai
