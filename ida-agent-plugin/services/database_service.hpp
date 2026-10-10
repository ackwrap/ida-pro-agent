#pragma once

#include "inventory.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace ida_agent::services
{

struct AddressRange
{
  std::uint64_t start;
  std::uint64_t end;
};

struct SegmentSummary
{
  std::uint32_t total = 0;
  std::uint32_t code = 0;
  std::uint32_t data = 0;
  std::uint32_t bss = 0;
  std::uint32_t other = 0;
  std::uint32_t readable = 0;
  std::uint32_t writable = 0;
  std::uint32_t executable = 0;
};

struct DatabaseInfo
{
  std::string database;
  std::string processor;
  std::string architecture;
  std::uint32_t address_bits;
  std::optional<AddressRange> address_range;
  SegmentSummary segments;
};

struct SegmentInfo
{
  std::uint64_t start;
  std::uint64_t end;
  std::string name;
  std::string segment_class;
  std::uint32_t bitness;
  std::string permissions;
  std::string type;
};

using SegmentListResult = InventoryResult<SegmentInfo>;
using SegmentListOutcome = InventoryOutcome<SegmentInfo>;

struct EntryPointInfo
{
  std::uint64_t address;
  std::string name;
  std::string type;
  std::optional<std::uint64_t> ordinal;
};

using EntryPointListResult = InventoryResult<EntryPointInfo>;
using EntryPointListOutcome = InventoryOutcome<EntryPointInfo>;

enum class DatabaseSaveStatus
{
  Success,
  InvalidArgument,
  Failed,
};

struct DatabaseSaveResult
{
  bool explicit_target;
};

struct DatabaseSaveOutcome
{
  DatabaseSaveStatus status;
  std::optional<DatabaseSaveResult> result;
};

class DatabaseService
{
public:
  // The caller must run this read operation through IdaExecutor.
  DatabaseInfo Info() const;
  SegmentListOutcome Segments(
      std::string_view name,
      std::uint32_t limit,
      const std::optional<std::string> &cursor) const;
  EntryPointListOutcome EntryPoints(
      std::string_view name,
      std::string_view type,
      std::uint32_t limit,
      const std::optional<std::string> &cursor) const;
  // The caller must run this write operation through IdaExecutor.
  DatabaseSaveOutcome Save(
      const std::optional<std::string> &target,
      bool compact,
      bool backup);
};

std::string ArchitectureName(std::string_view processor, std::uint32_t address_bits);
nlohmann::json ToJson(const DatabaseInfo &info);
nlohmann::json ToJson(const SegmentListResult &result);
nlohmann::json ToJson(const EntryPointListResult &result);
nlohmann::json ToJson(const DatabaseSaveResult &result);

} // namespace ida_agent::services
