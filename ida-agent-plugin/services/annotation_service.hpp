#pragma once
#include "query_result.hpp"
#include <cstdint>
#include <optional>
#include <string>

namespace ida_agent::services
{
class AnnotationService
{
public:
  // Callers execute all inspection operations through IdaExecutor.
  QueryResult CommentGet(
      std::uint64_t address,
      const std::string &scope,
      bool repeatable) const;
  QueryResult BookmarkList(std::uint32_t limit, std::uint32_t cursor) const;
};
}
