#pragma once

#include "ai/file_log.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace ida_agent::ai
{

class NetworkRequestLogger final
{
public:
  explicit NetworkRequestLogger(std::filesystem::path root = {});

  void Configure(bool enabled) noexcept;
  bool Enabled() const noexcept;
  void Begin(
      std::uint64_t stream_id,
      std::string_view session_id,
      std::string_view request_content) noexcept;
  void ResponseStatus(
      std::uint64_t stream_id,
      std::uint32_t status) noexcept;
  void AppendResponse(
      std::uint64_t stream_id,
      std::string_view content) noexcept;
  void End(std::uint64_t stream_id) noexcept;

private:
  static std::optional<std::string> SafeSessionId(
      std::string_view session_id);

  std::shared_ptr<FileLog> ExchangeLog(std::uint64_t stream_id) const;

  std::filesystem::path root_;
  mutable std::mutex mutex_;
  bool enabled_ = false;
  std::unordered_map<std::string, std::shared_ptr<FileLog>> session_logs_;
  std::unordered_map<std::uint64_t, std::shared_ptr<FileLog>> exchanges_;
};

} // namespace ida_agent::ai
