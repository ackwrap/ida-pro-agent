#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>

namespace ida_agent::services
{

enum class ReadonlyStatus
{
  Success,
  InvalidAddress,
  NotFound,
  OutputLimit,
};

struct ReadonlyResult
{
  ReadonlyStatus status;
  nlohmann::json value;
};

class ReadonlyAnalysisService
{
public:
  // Every caller must execute these operations through IdaExecutor.
  ReadonlyResult InstructionGet(std::uint64_t address) const;
  ReadonlyResult FunctionChunks(
      std::uint64_t address,
      std::uint32_t offset,
      std::uint32_t limit) const;
  ReadonlyResult FixupGet(std::uint64_t source) const;
  ReadonlyResult FixupList(
      const std::optional<std::uint64_t> &start,
      const std::optional<std::uint64_t> &end,
      std::uint32_t limit,
      const std::optional<std::uint64_t> &next_address) const;
  ReadonlyResult SwitchGet(std::uint64_t address) const;
  ReadonlyResult ExceptionTryBlocks(std::uint64_t address, std::uint32_t limit) const;
  ReadonlyResult AnalysisStatus() const;
  ReadonlyResult AnalysisPlan(std::uint64_t start, std::uint64_t end) const;
  ReadonlyResult AnalysisProblems(
      const std::string &type,
      const std::optional<std::uint64_t> &start,
      std::uint32_t limit,
      const std::optional<std::uint64_t> &next_address) const;
};

} // namespace ida_agent::services
