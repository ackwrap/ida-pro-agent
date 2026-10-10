#pragma once
#include "query_result.hpp"
#include <cstdint>
#include <optional>
#include <string>

namespace ida_agent::services
{
class SourceInfoService
{
public:
  // Callers execute all inspection operations through IdaExecutor.
  QueryResult SourceFiles(std::uint32_t limit, std::uint32_t cursor) const;
  QueryResult SourceLines(
      std::uint64_t start,
      std::uint64_t end,
      std::uint32_t limit,
      const std::optional<std::uint64_t> &cursor) const;
};
}
