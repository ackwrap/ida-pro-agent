#include "ai/file_log.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#include "ai/application_paths_linux.hpp"
#include "bridge/instance/private_file_linux.hpp"
#endif

#include <algorithm>
#include <chrono>
#include <ctime>
#include <deque>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <utility>

namespace ida_agent::ai
{

std::filesystem::path McpLogDirectory()
{
#ifdef _WIN32
  const DWORD required = GetEnvironmentVariableW(L"LOCALAPPDATA", nullptr, 0);
  if ( required <= 1 )
    return {};
  std::wstring local(required, L'\0');
  const DWORD actual = GetEnvironmentVariableW(
      L"LOCALAPPDATA", local.data(), required);
  if ( actual == 0 || actual >= required )
    return {};
  local.resize(actual);
  return std::filesystem::path(local) / L"ida-agent" / L"logs";
#else
  const auto path = LinuxAiPath("XDG_STATE_HOME", ".local/state", "logs");
  return path.empty() ? path : path.parent_path().parent_path() / "logs";
#endif
}

std::string FileLogTimestamp()
{
  const auto now = std::chrono::system_clock::now();
  const std::time_t seconds = std::chrono::system_clock::to_time_t(now);
  std::tm utc{};
#ifdef _WIN32
  gmtime_s(&utc, &seconds);
#else
  gmtime_r(&seconds, &utc);
#endif
  const auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(
      now.time_since_epoch()).count() % 1000;
  std::ostringstream result;
  result << std::put_time(&utc, "%Y-%m-%dT%H:%M:%S")
         << '.' << std::setfill('0') << std::setw(3) << milliseconds << 'Z';
  return result.str();
}

FileLog::FileLog(
    std::filesystem::path path,
    std::size_t max_bytes,
    std::size_t max_queued_bytes)
    : path_(std::move(path)), max_bytes_(max_bytes),
      max_queued_bytes_(max_queued_bytes),
      worker_([this]() { WorkerMain(); })
{
}

FileLog::~FileLog()
{
  {
    std::lock_guard<std::mutex> lock(mutex_);
    stopping_ = true;
  }
  ready_.notify_one();
  if ( worker_.joinable() )
    worker_.join();
}

bool FileLog::Append(std::string_view bytes) noexcept
{
  try
  {
    std::lock_guard<std::mutex> lock(mutex_);
    const bool queue_full = max_queued_bytes_ != 0
        && bytes.size() > max_queued_bytes_ - (std::min)(
            max_queued_bytes_, queued_bytes_);
    if ( path_.empty() || stopping_ || queue_full )
    {
      return false;
    }
    constexpr std::size_t MergeLimit = 256 * 1024;
    if ( !queue_.empty()
        && bytes.size() <= MergeLimit - (std::min)(MergeLimit, queue_.back().size()) )
    {
      queue_.back().append(bytes);
    }
    else
    {
      queue_.emplace_back(bytes);
    }
    queued_bytes_ += bytes.size();
    ready_.notify_one();
    return true;
  }
  catch ( ... )
  {
    return false;
  }
}

void FileLog::Flush() noexcept
{
  try
  {
    std::unique_lock<std::mutex> lock(mutex_);
    flushed_.wait(lock, [this]() { return queue_.empty() && !writing_; });
  }
  catch ( ... )
  {
  }
}

const std::filesystem::path &FileLog::Path() const noexcept
{
  return path_;
}

void FileLog::WorkerMain() noexcept
{
  while ( true )
  {
    std::deque<std::string> batch;
    {
      std::unique_lock<std::mutex> lock(mutex_);
      ready_.wait(lock, [this]() { return stopping_ || !queue_.empty(); });
      if ( queue_.empty() && stopping_ )
        return;
      batch.swap(queue_);
      queued_bytes_ = 0;
      writing_ = true;
    }
    WriteBatch(std::move(batch));
    {
      std::lock_guard<std::mutex> lock(mutex_);
      writing_ = false;
      if ( queue_.empty() )
        flushed_.notify_all();
    }
  }
}

void FileLog::WriteBatch(std::deque<std::string> batch) noexcept
{
  try
  {
    std::error_code error;
#ifdef _WIN32
    std::filesystem::create_directories(path_.parent_path(), error);
    if ( error )
      return;
#else
    bridge::PreparePrivateFile(path_);
#endif
    std::size_t batch_bytes = 0;
    for ( const std::string &part : batch )
      batch_bytes += part.size();
    bool truncate = max_bytes_ != 0 && batch_bytes >= max_bytes_;
    if ( !truncate && max_bytes_ != 0
        && std::filesystem::exists(path_, error) && !error )
    {
      const std::uintmax_t size = std::filesystem::file_size(path_, error);
      truncate = !error
          && size > max_bytes_ - (std::min)(max_bytes_, batch_bytes);
    }
    std::ofstream output(
        path_,
        std::ios::binary | (truncate ? std::ios::trunc : std::ios::app));
    if ( !output )
      return;
    std::size_t skip = truncate && batch_bytes > max_bytes_
        ? batch_bytes - max_bytes_
        : 0;
    for ( const std::string &part : batch )
    {
      if ( skip >= part.size() )
      {
        skip -= part.size();
        continue;
      }
      output.write(
          part.data() + skip,
          static_cast<std::streamsize>(part.size() - skip));
      skip = 0;
    }
  }
  catch ( ... )
  {
  }
}

} // namespace ida_agent::ai
