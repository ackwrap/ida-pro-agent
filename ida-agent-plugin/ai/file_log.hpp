#pragma once

#include <cstddef>
#include <condition_variable>
#include <deque>
#include <filesystem>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>

namespace ida_agent::ai
{

std::filesystem::path McpLogDirectory();
std::string FileLogTimestamp();

class FileLog final
{
public:
  explicit FileLog(
      std::filesystem::path path,
      std::size_t max_bytes = 0,
      std::size_t max_queued_bytes = 64 * 1024 * 1024);
  ~FileLog();

  FileLog(const FileLog &) = delete;
  FileLog &operator=(const FileLog &) = delete;

  bool Append(std::string_view bytes) noexcept;
  void Flush() noexcept;
  const std::filesystem::path &Path() const noexcept;

private:
  void WorkerMain() noexcept;
  void WriteBatch(std::deque<std::string> batch) noexcept;

  std::filesystem::path path_;
  std::size_t max_bytes_ = 0;
  std::size_t max_queued_bytes_ = 0;
  std::mutex mutex_;
  std::condition_variable ready_;
  std::condition_variable flushed_;
  std::deque<std::string> queue_;
  std::size_t queued_bytes_ = 0;
  bool writing_ = false;
  bool stopping_ = false;
  std::thread worker_;
};

} // namespace ida_agent::ai
