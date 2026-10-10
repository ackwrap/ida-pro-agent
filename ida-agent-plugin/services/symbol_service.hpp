#pragma once
#include "query_result.hpp"

#include "inventory.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace ida_agent::services
{

struct ImportInfo
{
  std::uint64_t address;
  std::string name;
  std::string module;
  std::optional<std::uint64_t> ordinal;
};

using ImportListResult = InventoryResult<ImportInfo>;
using ImportListOutcome = InventoryOutcome<ImportInfo>;

struct ExportInfo
{
  std::uint64_t address;
  std::string name;
  std::uint64_t ordinal;
};

using ExportListResult = InventoryResult<ExportInfo>;
using ExportListOutcome = InventoryOutcome<ExportInfo>;

struct SymbolInfo
{
  std::uint64_t address;
  std::string name;
  std::string kind;
};

using SymbolSearchResult = InventoryResult<SymbolInfo>;
using SymbolSearchOutcome = InventoryOutcome<SymbolInfo>;

class SymbolService
{
public:
  QueryResult Demangle(
      const std::optional<std::uint64_t> &address,
      const std::optional<std::string> &name) const;
  // The caller must run this read operation through IdaExecutor.
  ImportListOutcome Imports(
      std::string_view module,
      std::string_view name,
      std::uint32_t limit,
      const std::optional<std::string> &cursor) const;
  ExportListOutcome Exports(
      std::string_view name,
      std::uint32_t limit,
      const std::optional<std::string> &cursor) const;
  SymbolSearchOutcome Search(
      std::string_view name,
      std::string_view kind,
      std::uint32_t limit,
      const std::optional<std::string> &cursor) const;
};

nlohmann::json ToJson(const ImportListResult &result);
nlohmann::json ToJson(const ExportListResult &result);
nlohmann::json ToJson(const SymbolSearchResult &result);

} // namespace ida_agent::services
