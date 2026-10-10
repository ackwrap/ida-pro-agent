#pragma once

#include "inventory.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace ida_agent::services
{

struct StringInfo
{
  std::uint64_t address;
  std::uint64_t length;
  std::string encoding;
  std::string value;
  bool truncated;
  std::uint64_t original_size;
};

using StringSearchResult = InventoryResult<StringInfo>;
using StringSearchOutcome = InventoryOutcome<StringInfo>;

class StringService
{
public:
  // The caller must run this read operation through IdaExecutor.
  StringSearchOutcome Search(
      std::string_view query,
      std::uint32_t minimum_length,
      std::uint32_t limit,
      const std::optional<std::string> &cursor,
    bool refresh = false) const;
  StringSearchOutcome SearchRegex(
      std::string_view pattern,
      std::uint32_t minimum_length,
      std::uint32_t limit,
      const std::optional<std::string> &cursor,
    bool refresh = false) const;
};

nlohmann::json ToJson(const StringSearchResult &result);

} // namespace ida_agent::services
