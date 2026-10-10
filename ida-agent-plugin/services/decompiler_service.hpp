#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>

namespace ida_agent::services
{

struct DecompileQuery
{
  std::uint64_t address;
  std::uint32_t offset;
  std::uint32_t max_bytes;
};

struct DecompileResult
{
  std::uint64_t entry_address;
  std::string pseudocode;
  std::uint32_t offset;
  std::uint32_t returned_size;
  std::uint32_t original_size;
  bool truncated;
  std::optional<std::uint32_t> next_offset;
};

enum class DecompileStatus
{
  Success,
  InvalidAddress,
  NotFound,
  CapabilityUnavailable,
  InvalidArgument,
  Busy,
  Failed,
  OutputLimit,
};

struct DecompileOutcome
{
  DecompileStatus status;
  std::optional<DecompileResult> result;
};

class DecompilerService
{
public:
  void SetAvailable(bool available) noexcept { available_ = available; }

  // The caller must run this read operation through IdaExecutor.
  DecompileOutcome Decompile(const DecompileQuery &query) const;
  // The caller must run this write operation through IdaExecutor.
  bool Invalidate(std::uint64_t address) const;

private:
  bool available_ = false;
};

nlohmann::json ToJson(const DecompileResult &result);

} // namespace ida_agent::services
