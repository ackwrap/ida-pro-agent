#include "symbol_service.hpp"

#include "address.hpp"
#include "inventory_text.hpp"
#include "list_cursor.hpp"

#include <bytes.hpp>
#include <entry.hpp>
#include <funcs.hpp>
#include <nalt.hpp>
#include <name.hpp>

#include <stdexcept>
#include <unordered_set>

namespace ida_agent::services
{
namespace
{

constexpr std::uint64_t MaxJsonInteger = 9007199254740991ULL;

std::string QueryIdentity(
    std::string_view normalized_module,
    std::string_view normalized_name)
{
  std::string identity(normalized_module);
  identity.push_back('\0');
  identity.append(normalized_name);
  return identity;
}

std::string SymbolQueryIdentity(
    std::string_view normalized_name,
    std::string_view kind)
{
  std::string identity(normalized_name);
  identity.push_back('\0');
  identity.append(kind);
  return identity;
}

bool ValidInventoryItemText(std::string_view value)
{
  std::size_t characters = 0;
  return !value.empty() && value.size() <= 1024
      && Utf8CodePointCount(value, &characters) && characters <= 1024;
}

struct ImportContext
{
  std::uint64_t start_position;
  std::uint64_t current_position = 0;
  std::size_t scanned = 0;
  std::uint32_t limit;
  std::string module;
  std::string normalized_module_filter;
  std::string normalized_name_filter;
  ImportListResult *result;
  bool stopped = false;
  bool output_limit = false;
  bool invalid_text = false;
};

int idaapi CollectImport(ea_t address, const char *name, uval_t ordinal, void *parameter)
{
  auto &context = *static_cast<ImportContext *>(parameter);
  if ( context.current_position < context.start_position )
  {
    ++context.current_position;
    return 1;
  }
  if ( context.scanned >= MaxInventoryScan
    || context.result->items.size() >= context.limit )
  {
    context.stopped = true;
    return 0;
  }

  ++context.current_position;
  ++context.scanned;
  std::optional<std::uint64_t> stable_ordinal;
  std::string stable_name;
  if ( name != nullptr && *name != '\0' )
  {
    stable_name = name;
  }
  else
  {
    stable_name = "#" + std::to_string(ordinal);
    if ( ordinal != 0 )
      stable_ordinal = ordinal;
  }
  if ( ordinal > MaxJsonInteger )
  {
    context.output_limit = true;
    return 0;
  }
  std::size_t name_length = 0;
  if ( !Utf8CodePointCount(stable_name, &name_length) || name_length == 0 )
  {
    context.invalid_text = true;
    return 0;
  }
  if ( name_length > 1024 )
  {
    context.output_limit = true;
    return 0;
  }
  if ( !InventoryFilterMatches(context.module, context.normalized_module_filter)
    || !InventoryFilterMatches(stable_name, context.normalized_name_filter) )
  {
    return 1;
  }
  context.result->items.push_back(ImportInfo{
      address,
      std::move(stable_name),
      context.module,
      stable_ordinal,
  });
  return 1;
}

} // namespace

ImportListOutcome SymbolService::Imports(
    std::string_view module,
    std::string_view name,
    std::uint32_t limit,
    const std::optional<std::string> &cursor) const
{
  const std::string normalized_module = NormalizeInventoryFilter(module);
  const std::string normalized_name = NormalizeInventoryFilter(name);
  const std::string identity = QueryIdentity(normalized_module, normalized_name);
  std::uint64_t start_position = 0;
  if ( cursor )
  {
    try
    {
      start_position = rpc::DecodeListCursor("si1", *cursor, identity);
    }
    catch ( const std::invalid_argument & )
    {
      return {InventoryStatus::InvalidCursor, std::nullopt};
    }
  }
  if ( ValidateInventoryContinuation(start_position) == InventoryStatus::OutputLimit )
    return {InventoryStatus::OutputLimit, std::nullopt};

  ImportListResult result;
  result.items.reserve(limit);
  ImportContext context{
      start_position,
      0,
      0,
      limit,
      {},
      normalized_module,
      normalized_name,
      &result,
  };
  const uint module_count = get_import_module_qty();
  for ( uint module_index = 0; module_index < module_count; ++module_index )
  {
    if ( context.scanned >= MaxInventoryScan || result.items.size() >= limit )
    {
      context.stopped = true;
      break;
    }
    qstring module_name;
    if ( !get_import_module_name(&module_name, static_cast<int>(module_index))
      || module_name.empty() )
    {
      context.module = "<unnamed>";
    }
    else
    {
      context.module.assign(module_name.c_str(), module_name.length());
    }
    std::size_t module_length = 0;
    if ( !Utf8CodePointCount(context.module, &module_length) || module_length == 0 )
      throw std::runtime_error("import module is not valid UTF-8");
    if ( module_length > 1024 )
      return {InventoryStatus::OutputLimit, std::nullopt};

    const int enumeration = enum_import_names(
        static_cast<int>(module_index),
        CollectImport,
        &context);
    if ( context.output_limit )
      return {InventoryStatus::OutputLimit, std::nullopt};
    if ( context.invalid_text )
      throw std::runtime_error("import name is not valid UTF-8");
    if ( context.stopped )
      break;
    if ( enumeration != 1 )
      throw std::runtime_error("import enumeration failed");
  }
  if ( context.stopped )
  {
    if ( ValidateInventoryContinuation(context.current_position) == InventoryStatus::OutputLimit )
      return {InventoryStatus::OutputLimit, std::nullopt};
    result.has_more = true;
    result.next_cursor = rpc::EncodeListCursor("si1", identity, context.current_position);
  }
  return {InventoryStatus::Success, std::move(result)};
}

ExportListOutcome SymbolService::Exports(
    std::string_view name,
    std::uint32_t limit,
    const std::optional<std::string> &cursor) const
{
  const std::string normalized_name = NormalizeInventoryFilter(name);
  std::uint64_t position = 0;
  if ( cursor )
  {
    try
    {
      position = rpc::DecodeListCursor("se1", *cursor, normalized_name);
    }
    catch ( const std::invalid_argument & )
    {
      return {InventoryStatus::InvalidCursor, std::nullopt};
    }
  }
  if ( ValidateInventoryContinuation(position) == InventoryStatus::OutputLimit )
    return {InventoryStatus::OutputLimit, std::nullopt};

  const std::size_t count = get_entry_qty();
  ExportListResult result;
  result.items.reserve(limit);
  std::unordered_set<std::uint64_t> seen_ordinals;
  std::size_t scanned = 0;
  while ( position < count && scanned < MaxInventoryScan && result.items.size() < limit )
  {
    const uval_t ordinal = get_entry_ordinal(static_cast<std::size_t>(position));
    const ea_t address = get_entry(ordinal);
    ++position;
    ++scanned;
    if ( address == BADADDR || ordinal == address || ordinal == 0
      || ordinal > MaxJsonInteger || !seen_ordinals.insert(ordinal).second )
    {
      continue;
    }
    qstring encoded_name;
    if ( get_entry_name(&encoded_name, ordinal) <= 0 )
      continue;
    const std::string stable_name(encoded_name.c_str(), encoded_name.length());
    if ( !ValidInventoryItemText(stable_name)
      || !InventoryFilterMatches(stable_name, normalized_name) )
    {
      continue;
    }
    result.items.push_back(ExportInfo{address, stable_name, ordinal});
  }
  if ( position < count )
  {
    if ( ValidateInventoryContinuation(position) == InventoryStatus::OutputLimit )
      return {InventoryStatus::OutputLimit, std::nullopt};
    result.has_more = true;
    result.next_cursor = rpc::EncodeListCursor("se1", normalized_name, position);
  }
  return {InventoryStatus::Success, std::move(result)};
}

SymbolSearchOutcome SymbolService::Search(
    std::string_view name,
    std::string_view kind,
    std::uint32_t limit,
    const std::optional<std::string> &cursor) const
{
  const std::string normalized_name = NormalizeInventoryFilter(name);
  const std::string identity = SymbolQueryIdentity(normalized_name, kind);
  std::uint64_t position = 0;
  if ( cursor )
  {
    try
    {
      position = rpc::DecodeListCursor("sy1", *cursor, identity);
    }
    catch ( const std::invalid_argument & )
    {
      return {InventoryStatus::InvalidCursor, std::nullopt};
    }
  }
  if ( ValidateInventoryContinuation(position) == InventoryStatus::OutputLimit )
    return {InventoryStatus::OutputLimit, std::nullopt};

  const std::size_t count = get_nlist_size();
  SymbolSearchResult result;
  result.items.reserve(limit);
  std::size_t scanned = 0;
  ea_t previous_address = BADADDR;
  while ( position < count && scanned < MaxInventoryScan && result.items.size() < limit )
  {
    const std::size_t index = static_cast<std::size_t>(position);
    const ea_t address = get_nlist_ea(index);
    const char *encoded_name = get_nlist_name(index);
    ++position;
    ++scanned;
    if ( address == BADADDR )
      continue;
    if ( previous_address != BADADDR && address < previous_address )
      throw std::runtime_error("name list order is invalid");
    if ( address == previous_address )
      continue;
    previous_address = address;
    if ( !is_mapped(address) || get_fchunk_info(nullptr, address)
      || encoded_name == nullptr || *encoded_name == '\0' )
    {
      continue;
    }

    const std::string stable_name(encoded_name);
    if ( !ValidInventoryItemText(stable_name)
      || !InventoryFilterMatches(stable_name, normalized_name) )
    {
      continue;
    }
    std::string stable_kind = "label";
    if ( is_public_name(address) )
      stable_kind = "global";
    else if ( is_data(get_flags32(address)) )
      stable_kind = "data";
    if ( !kind.empty() && kind != stable_kind )
      continue;
    result.items.push_back(SymbolInfo{address, stable_name, stable_kind});
  }
  if ( position < count )
  {
    if ( ValidateInventoryContinuation(position) == InventoryStatus::OutputLimit )
      return {InventoryStatus::OutputLimit, std::nullopt};
    result.has_more = true;
    result.next_cursor = rpc::EncodeListCursor("sy1", identity, position);
  }
  return {InventoryStatus::Success, std::move(result)};
}

nlohmann::json ToJson(const ImportListResult &result)
{
  nlohmann::json items = nlohmann::json::array();
  for ( const ImportInfo &item : result.items )
  {
    nlohmann::json encoded = {
        {"address", rpc::FormatAddress(item.address)},
        {"name", item.name},
        {"module", item.module},
    };
    if ( item.ordinal )
      encoded["ordinal"] = *item.ordinal;
    items.push_back(std::move(encoded));
  }
  return {
      {"items", std::move(items)},
      {"nextCursor", result.next_cursor ? nlohmann::json(*result.next_cursor) : nlohmann::json(nullptr)},
      {"hasMore", result.has_more},
  };
}

nlohmann::json ToJson(const ExportListResult &result)
{
  nlohmann::json items = nlohmann::json::array();
  for ( const ExportInfo &item : result.items )
  {
    items.push_back({
        {"address", rpc::FormatAddress(item.address)},
        {"name", item.name},
        {"ordinal", item.ordinal},
    });
  }
  return {
      {"items", std::move(items)},
      {"nextCursor", result.next_cursor ? nlohmann::json(*result.next_cursor) : nlohmann::json(nullptr)},
      {"hasMore", result.has_more},
  };
}

nlohmann::json ToJson(const SymbolSearchResult &result)
{
  nlohmann::json items = nlohmann::json::array();
  for ( const SymbolInfo &item : result.items )
  {
    items.push_back({
        {"address", rpc::FormatAddress(item.address)},
        {"name", item.name},
        {"kind", item.kind},
    });
  }
  return {
      {"items", std::move(items)},
      {"nextCursor", result.next_cursor ? nlohmann::json(*result.next_cursor) : nlohmann::json(nullptr)},
      {"hasMore", result.has_more},
  };
}

} // namespace ida_agent::services
