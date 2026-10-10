#include "string_service.hpp"

#include "address.hpp"
#include "inventory_text.hpp"
#include "list_cursor.hpp"
#include "safe_regex.hpp"

#include <bytes.hpp>
#include <nalt.hpp>
#include <strlist.hpp>

#include <limits>
#include <regex>
#include <stdexcept>

namespace ida_agent::services
{
namespace
{

constexpr std::size_t MaxStringValueBytes = 4096;
constexpr std::size_t MaxRegexSubjectBytes = 65536;

constexpr std::uint64_t MaxJsonInteger = 9007199254740991ULL;

std::string QueryIdentity(std::string_view normalized_query, std::uint32_t minimum_length)
{
  std::string identity(normalized_query);
  identity.push_back('\0');
  identity += std::to_string(minimum_length);
  return identity;
}

std::string StableEncoding(int type)
{
  const char *encoding = encoding_from_strtype(type);
  if ( encoding == nullptr || *encoding == '\0' )
    return "unknown";
  const std::string value(encoding);
  std::size_t length = 0;
  if ( !Utf8CodePointCount(value, &length) || length == 0 || length > 128 )
    return "unknown";
  return value;
}

bool ReadStringValue(
    const string_info_ex_t &entry,
    std::size_t maximum_source_bytes,
    std::string *value,
    std::string *encoding)
{
  if ( entry.type == STRTYPE_DECOMP )
  {
    if ( entry.decompiler_string.length() > maximum_source_bytes )
      return false;
    value->assign(entry.decompiler_string.c_str(), entry.decompiler_string.length());
    *encoding = "UTF-8";
    return true;
  }
  if ( entry.length < 0 )
    return false;
  if ( static_cast<std::uint64_t>(entry.length) > maximum_source_bytes )
    return false;
  qstring contents;
  const ssize_t generated = get_strlit_contents(
      &contents,
      entry.ea,
      static_cast<std::size_t>(entry.length),
      entry.type);
  if ( generated < 0 )
    return false;
  value->assign(contents.c_str(), contents.length());
  if ( !value->empty() && value->back() == '\0' )
    value->pop_back();
  if ( value->size() > maximum_source_bytes )
    return false;
  *encoding = StableEncoding(entry.type);
  return true;
}

template <typename Matcher>
StringSearchOutcome SearchStrings(
    std::string_view query_identity,
    std::string_view cursor_kind,
    std::uint32_t minimum_length,
    std::uint32_t limit,
    const std::optional<std::string> &cursor,
    bool refresh,
    std::size_t maximum_source_bytes,
    Matcher matches)
{
  if ( refresh && cursor )
    throw std::invalid_argument("refresh cannot be combined with cursor");
  const std::string identity = QueryIdentity(query_identity, minimum_length);
  std::uint64_t position = 0;
  if ( cursor )
  {
    try
    {
      position = rpc::DecodeListCursor(cursor_kind, *cursor, identity);
    }
    catch ( const std::invalid_argument & )
    {
      return {InventoryStatus::InvalidCursor, std::nullopt};
    }
  }
  if ( ValidateInventoryContinuation(position) == InventoryStatus::OutputLimit )
    return {InventoryStatus::OutputLimit, std::nullopt};

  // Rebuild only on explicit first-page refresh. IDA may still build a missing
  // list on the first get_strlist_qty() call. All access stays on IdaExecutor.
  if ( refresh )
    build_strlist();
  const std::size_t count = get_strlist_qty();
  StringSearchResult result;
  result.items.reserve(limit);
  std::size_t scanned = 0;
  ea_t previous_address = BADADDR;
  while ( position < count && scanned < MaxInventoryScan && result.items.size() < limit )
  {
    string_info_ex_t entry;
    if ( !get_strlist_item_ex(&entry, static_cast<std::size_t>(position)) )
      throw std::runtime_error("string list entry is unavailable");
    ++position;
    ++scanned;
    if ( entry.ea == BADADDR || (previous_address != BADADDR && entry.ea <= previous_address) )
      throw std::runtime_error("string list order is invalid");
    previous_address = entry.ea;

    std::string value;
    std::string encoding;
    if ( !ReadStringValue(entry, maximum_source_bytes, &value, &encoding) )
      continue;
    std::size_t character_count = 0;
    if ( !Utf8CodePointCount(value, &character_count) )
      continue;
    if ( character_count < minimum_length || !matches(value) )
      continue;
    if ( character_count > MaxJsonInteger || value.size() > MaxJsonInteger )
      return {InventoryStatus::OutputLimit, std::nullopt};
    result.items.push_back(StringInfo{
        entry.ea,
        static_cast<std::uint64_t>(character_count),
        std::move(encoding),
        TruncateUtf8Bytes(value, MaxStringValueBytes),
        value.size() > MaxStringValueBytes,
        static_cast<std::uint64_t>(value.size()),
    });
  }
  if ( position < count )
  {
    if ( ValidateInventoryContinuation(position) == InventoryStatus::OutputLimit )
      return {InventoryStatus::OutputLimit, std::nullopt};
    result.has_more = true;
    result.next_cursor = rpc::EncodeListCursor(cursor_kind, identity, position);
  }
  return {InventoryStatus::Success, std::move(result)};
}

} // namespace

StringSearchOutcome StringService::Search(
    std::string_view query,
    std::uint32_t minimum_length,
    std::uint32_t limit,
    const std::optional<std::string> &cursor,
    bool refresh) const
{
  const std::string normalized_query = NormalizeInventoryFilter(query);
  return SearchStrings(
      normalized_query,
      "ss1",
      minimum_length,
      limit,
      cursor,
      refresh,
      (std::numeric_limits<std::size_t>::max)(),
      [&normalized_query](const std::string &value)
      {
        return InventoryFilterMatches(value, normalized_query);
      });
}

StringSearchOutcome StringService::SearchRegex(
    std::string_view pattern,
    std::uint32_t minimum_length,
    std::uint32_t limit,
    const std::optional<std::string> &cursor,
    bool refresh) const
{
  const std::string stable_pattern(pattern);
  if ( !IsSafeRegex(stable_pattern) )
    throw std::regex_error(std::regex_constants::error_complexity);
  const std::regex expression(
      stable_pattern,
      std::regex::ECMAScript | std::regex::icase | std::regex::optimize);
  return SearchStrings(
      stable_pattern,
      "sr1",
      minimum_length,
      limit,
      cursor,
      refresh,
      MaxRegexSubjectBytes,
      [&expression](const std::string &value)
      {
        return std::regex_search(value, expression);
      });
}

nlohmann::json ToJson(const StringSearchResult &result)
{
  nlohmann::json items = nlohmann::json::array();
  for ( const StringInfo &item : result.items )
  {
    items.push_back({
        {"address", rpc::FormatAddress(item.address)},
        {"length", item.length},
        {"encoding", item.encoding},
        {"value", item.value},
        {"truncated", item.truncated},
        {"originalSize", item.original_size},
    });
  }
  return {
      {"items", std::move(items)},
      {"nextCursor", result.next_cursor ? nlohmann::json(*result.next_cursor) : nlohmann::json(nullptr)},
      {"hasMore", result.has_more},
  };
}

} // namespace ida_agent::services
