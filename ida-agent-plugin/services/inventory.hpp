#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ida_agent::services
{

constexpr std::size_t MaxInventoryScan = 4096;
constexpr std::uint64_t MaxInventoryContinuation = 1000000;

enum class InventoryStatus
{
  Success,
  InvalidCursor,
  OutputLimit,
};

constexpr InventoryStatus ValidateInventoryContinuation(std::uint64_t position)
{
  return position > MaxInventoryContinuation
      ? InventoryStatus::OutputLimit
      : InventoryStatus::Success;
}

template <typename Item>
struct InventoryResult
{
  std::vector<Item> items;
  std::optional<std::string> next_cursor;
  bool has_more = false;
};

template <typename Item>
struct InventoryOutcome
{
  InventoryStatus status;
  std::optional<InventoryResult<Item>> result;
};

} // namespace ida_agent::services
