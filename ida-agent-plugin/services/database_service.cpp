#include "database_service.hpp"

#include "address.hpp"
#include "inventory_text.hpp"
#include "list_cursor.hpp"

#include <ida.hpp>
#include <entry.hpp>
#include <loader.hpp>
#include <nalt.hpp>
#include <segment.hpp>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <stdexcept>
#include <unordered_set>

namespace ida_agent::services
{
namespace
{

const char *StableSegmentType(unsigned char type)
{
  switch ( type )
  {
    case SEG_NORM: return "normal";
    case SEG_XTRN: return "external";
    case SEG_CODE: return "code";
    case SEG_DATA: return "data";
    case SEG_IMP: return "implementation";
    case SEG_GRP: return "group";
    case SEG_NULL: return "null";
    case SEG_UNDF: return "undefined";
    case SEG_BSS: return "bss";
    case SEG_ABSSYM: return "absolute_symbols";
    case SEG_COMM: return "communal";
    case SEG_IMEM: return "internal_memory";
  }
  throw std::runtime_error("segment type is unavailable");
}

std::string StablePermissions(unsigned char permissions)
{
  std::string result = "---";
  if ( (permissions & SEGPERM_READ) != 0 )
    result[0] = 'r';
  if ( (permissions & SEGPERM_WRITE) != 0 )
    result[1] = 'w';
  if ( (permissions & SEGPERM_EXEC) != 0 )
    result[2] = 'x';
  return result;
}

bool ValidInventoryItemText(std::string_view value)
{
  std::size_t characters = 0;
  return !value.empty() && value.size() <= 1024
      && Utf8CodePointCount(value, &characters) && characters <= 1024;
}

bool ValidSaveTarget(std::string_view target)
{
  if ( target.empty() || target.size() > 4096 || target.find('\0') != std::string_view::npos
    || target.rfind("\\\\", 0) == 0 ) return false;
  std::size_t characters = 0;
  if ( !Utf8CodePointCount(target, &characters) || characters == 0 ) return false;
  const std::filesystem::path path{std::string(target)};
  return path.is_absolute() && path.has_filename() && path.lexically_normal() == path;
}

class DatabaseFlagGuard
{
public:
  DatabaseFlagGuard()
      : kill_(is_database_flag(DBFL_KILL)),
        compact_(is_database_flag(DBFL_COMP)),
        backup_(is_database_flag(DBFL_BAK))
  {
    clr_database_flag(DBFL_KILL);
    clr_database_flag(DBFL_COMP);
    clr_database_flag(DBFL_BAK);
  }

  ~DatabaseFlagGuard()
  {
    set_database_flag(DBFL_KILL, kill_);
    set_database_flag(DBFL_COMP, compact_);
    set_database_flag(DBFL_BAK, backup_);
  }

  DatabaseFlagGuard(const DatabaseFlagGuard &) = delete;
  DatabaseFlagGuard &operator=(const DatabaseFlagGuard &) = delete;

private:
  bool kill_;
  bool compact_;
  bool backup_;
};

std::string EntryPointIdentity(
    std::string_view normalized_name,
    std::string_view type)
{
  std::string identity(normalized_name);
  identity.push_back('\0');
  identity.append(type);
  return identity;
}

} // namespace

std::string ArchitectureName(std::string_view processor, std::uint32_t address_bits)
{
  std::string normalized(processor);
  std::transform(
      normalized.begin(),
      normalized.end(),
      normalized.begin(),
      [](unsigned char character) { return static_cast<char>(std::tolower(character)); });

  if ( normalized == "metapc" )
  {
    if ( address_bits == 64 )
      return "x86_64";
    if ( address_bits == 16 )
      return "x86_16";
    return "x86";
  }
  if ( normalized == "arm" )
    return address_bits == 64 ? "arm64" : "arm";
  if ( normalized.rfind("mips", 0) == 0 )
    return address_bits == 64 ? "mips64" : "mips";
  if ( normalized == "ppc" )
    return address_bits == 64 ? "ppc64" : "ppc";
  if ( normalized.rfind("riscv", 0) == 0 )
    return address_bits == 64 ? "riscv64" : "riscv32";
  if ( normalized.rfind("sparc", 0) == 0 )
    return address_bits == 64 ? "sparc64" : "sparc";
  return normalized;
}

DatabaseInfo DatabaseService::Info() const
{
  char database[QMAXPATH]{};
  if ( get_root_filename(database, sizeof(database)) <= 0 )
    qstrncpy(database, "untitled", sizeof(database));

  const qstring processor = inf_get_procname();
  if ( processor.empty() )
    throw std::runtime_error("database processor is unavailable");

  const std::uint32_t address_bits = inf_get_app_bitness();
  const int segment_count = get_segm_qty();
  if ( segment_count < 0 )
    throw std::runtime_error("segment count is unavailable");

  DatabaseInfo result{
      database,
      processor.c_str(),
      ArchitectureName(processor.c_str(), address_bits),
      address_bits,
      std::nullopt,
      {},
  };
  result.segments.total = static_cast<std::uint32_t>(segment_count);

  for ( int index = 0; index < segment_count; ++index )
  {
    segment_info_t segment;
    if ( !get_segment_info_by_num(&segment, index) )
      throw std::runtime_error("segment information is unavailable");

    switch ( segment.get_type() )
    {
      case SEG_CODE:
        ++result.segments.code;
        break;
      case SEG_DATA:
        ++result.segments.data;
        break;
      case SEG_BSS:
        ++result.segments.bss;
        break;
      default:
        ++result.segments.other;
        break;
    }

    const unsigned char permissions = segment.get_perm();
    if ( (permissions & SEGPERM_READ) != 0 )
      ++result.segments.readable;
    if ( (permissions & SEGPERM_WRITE) != 0 )
      ++result.segments.writable;
    if ( (permissions & SEGPERM_EXEC) != 0 )
      ++result.segments.executable;

    if ( !result.address_range )
    {
      result.address_range = AddressRange{segment.start_ea, segment.end_ea};
    }
    else
    {
      result.address_range->start = (std::min)(
          result.address_range->start,
          static_cast<std::uint64_t>(segment.start_ea));
      result.address_range->end = (std::max)(
          result.address_range->end,
          static_cast<std::uint64_t>(segment.end_ea));
    }
  }
  return result;
}

SegmentListOutcome DatabaseService::Segments(
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
      position = rpc::DecodeListCursor("ds1", *cursor, normalized_name);
    }
    catch ( const std::invalid_argument & )
    {
      return {InventoryStatus::InvalidCursor, std::nullopt};
    }
  }
  if ( ValidateInventoryContinuation(position) == InventoryStatus::OutputLimit )
    return {InventoryStatus::OutputLimit, std::nullopt};

  const int count = get_segm_qty();
  if ( count < 0 )
    throw std::runtime_error("segment count is unavailable");
  SegmentListResult result;
  result.items.reserve(limit);
  std::size_t scanned = 0;
  while ( position < static_cast<std::uint64_t>(count)
    && scanned < MaxInventoryScan && result.items.size() < limit )
  {
    segment_info_t segment;
    if ( !get_segment_info_by_num(
             &segment,
             static_cast<int>(position),
             GSI_NAME | GSI_SCLASS) )
    {
      throw std::runtime_error("segment information is unavailable");
    }
    ++position;
    ++scanned;
    const std::string segment_name = segment.get_name();
    std::size_t name_length = 0;
    if ( !Utf8CodePointCount(segment_name, &name_length) || name_length == 0 )
      throw std::runtime_error("segment name is not valid UTF-8");
    if ( name_length > 1024 )
      return {InventoryStatus::OutputLimit, std::nullopt};
    if ( !InventoryFilterMatches(segment_name, normalized_name) )
      continue;

    const std::string segment_class = segment.get_sclass();
    std::size_t class_length = 0;
    if ( !Utf8CodePointCount(segment_class, &class_length) )
      throw std::runtime_error("segment class is not valid UTF-8");
    if ( class_length > 1024 )
      return {InventoryStatus::OutputLimit, std::nullopt};
    result.items.push_back(SegmentInfo{
        segment.start_ea,
        segment.end_ea,
        segment_name,
        segment_class,
        static_cast<std::uint32_t>(segment.abits()),
        StablePermissions(segment.get_perm()),
        StableSegmentType(segment.get_type()),
    });
  }
  if ( position < static_cast<std::uint64_t>(count) )
  {
    if ( ValidateInventoryContinuation(position) == InventoryStatus::OutputLimit )
      return {InventoryStatus::OutputLimit, std::nullopt};
    result.has_more = true;
    result.next_cursor = rpc::EncodeListCursor("ds1", normalized_name, position);
  }
  return {InventoryStatus::Success, std::move(result)};
}

EntryPointListOutcome DatabaseService::EntryPoints(
    std::string_view name,
    std::string_view type,
    std::uint32_t limit,
    const std::optional<std::string> &cursor) const
{
  const std::string normalized_name = NormalizeInventoryFilter(name);
  const std::string identity = EntryPointIdentity(normalized_name, type);
  std::uint64_t position = 0;
  if ( cursor )
  {
    try
    {
      position = rpc::DecodeListCursor("ep1", *cursor, identity);
    }
    catch ( const std::invalid_argument & )
    {
      return {InventoryStatus::InvalidCursor, std::nullopt};
    }
  }
  if ( ValidateInventoryContinuation(position) == InventoryStatus::OutputLimit )
    return {InventoryStatus::OutputLimit, std::nullopt};

  const std::size_t count = get_entry_qty();
  EntryPointListResult result;
  result.items.reserve(limit);
  std::unordered_set<std::uint64_t> seen_ordinals;
  std::size_t scanned = 0;
  while ( position < count && scanned < MaxInventoryScan && result.items.size() < limit )
  {
    const uval_t ordinal = get_entry_ordinal(static_cast<std::size_t>(position));
    const ea_t address = get_entry(ordinal);
    ++position;
    ++scanned;
    if ( address == BADADDR || !seen_ordinals.insert(ordinal).second )
      continue;

    const bool is_export = ordinal != address;
    const std::string stable_type = is_export ? "export" : "entry";
    if ( !type.empty() && type != stable_type )
      continue;
    if ( is_export && (ordinal == 0 || ordinal > 9007199254740991ULL) )
      continue;

    qstring encoded_name;
    if ( get_entry_name(&encoded_name, ordinal) <= 0 )
      continue;
    const std::string stable_name(encoded_name.c_str(), encoded_name.length());
    if ( !ValidInventoryItemText(stable_name)
      || !InventoryFilterMatches(stable_name, normalized_name) )
    {
      continue;
    }
    result.items.push_back(EntryPointInfo{
        address,
        stable_name,
        stable_type,
        is_export
            ? std::optional<std::uint64_t>(static_cast<std::uint64_t>(ordinal))
            : std::nullopt,
    });
  }
  if ( position < count )
  {
    if ( ValidateInventoryContinuation(position) == InventoryStatus::OutputLimit )
      return {InventoryStatus::OutputLimit, std::nullopt};
    result.has_more = true;
    result.next_cursor = rpc::EncodeListCursor("ep1", identity, position);
  }
  return {InventoryStatus::Success, std::move(result)};
}

DatabaseSaveOutcome DatabaseService::Save(
    const std::optional<std::string> &target,
    bool compact,
    bool backup)
{
  if ( target && !ValidSaveTarget(*target) )
    return {DatabaseSaveStatus::InvalidArgument, std::nullopt};

  // Passing zero asks IDA to reuse its current flags. Temporarily clear every
  // persisted save flag so even that path cannot inherit DBFL_KILL.
  DatabaseFlagGuard flag_guard;
  std::uint32_t flags = 0;
  if ( compact )
    flags |= DBFL_COMP;
  if ( backup )
    flags |= DBFL_BAK;
  const char *requested_path = target ? target->c_str() : nullptr;
  if ( !save_database(requested_path, flags) )
    return {DatabaseSaveStatus::Failed, std::nullopt};

  return {DatabaseSaveStatus::Success, DatabaseSaveResult{target.has_value()}};
}

nlohmann::json ToJson(const DatabaseInfo &info)
{
  nlohmann::json address_range = nullptr;
  if ( info.address_range )
  {
    address_range = {
        {"start", rpc::FormatAddress(info.address_range->start)},
        {"end", rpc::FormatAddress(info.address_range->end)},
    };
  }

  return {
      {"database", info.database},
      {"processor", info.processor},
      {"architecture", info.architecture},
      {"addressBits", info.address_bits},
      {"addressRange", std::move(address_range)},
      {"segments",
       {
           {"total", info.segments.total},
           {"code", info.segments.code},
           {"data", info.segments.data},
           {"bss", info.segments.bss},
           {"other", info.segments.other},
           {"readable", info.segments.readable},
           {"writable", info.segments.writable},
           {"executable", info.segments.executable},
       }},
  };
}

nlohmann::json ToJson(const SegmentListResult &result)
{
  nlohmann::json items = nlohmann::json::array();
  for ( const SegmentInfo &segment : result.items )
  {
    items.push_back({
        {"start", rpc::FormatAddress(segment.start)},
        {"end", rpc::FormatAddress(segment.end)},
        {"name", segment.name},
        {"class", segment.segment_class},
        {"bitness", segment.bitness},
        {"permissions", segment.permissions},
        {"type", segment.type},
    });
  }
  return {
      {"items", std::move(items)},
      {"nextCursor", result.next_cursor ? nlohmann::json(*result.next_cursor) : nlohmann::json(nullptr)},
      {"hasMore", result.has_more},
  };
}

nlohmann::json ToJson(const EntryPointListResult &result)
{
  nlohmann::json items = nlohmann::json::array();
  for ( const EntryPointInfo &item : result.items )
  {
    nlohmann::json encoded = {
        {"address", rpc::FormatAddress(item.address)},
        {"name", item.name},
        {"type", item.type},
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

nlohmann::json ToJson(const DatabaseSaveResult &result)
{
  return {{"saved", true}, {"explicitTarget", result.explicit_target}};
}

} // namespace ida_agent::services
