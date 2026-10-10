#include "type_service_internal.hpp"

#include "inventory_text.hpp"

#include <typeinf.hpp>

#include <algorithm>
#include <cctype>
#include <utility>

namespace ida_agent::services
{
namespace
{

std::string Lower(std::string_view value)
{
  std::string result(value);
  std::transform(
      result.begin(), result.end(), result.begin(),
      [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
  return result;
}

bool KindMatches(std::string_view filter, const tinfo_t &type)
{
  if ( filter.empty() || filter == "any" ) return true;
  if ( filter == "udt" ) return type.is_udt();
  return filter == type_service_detail::Kind(type);
}

bool IsKnownKind(std::string_view kind)
{
  return kind.empty() || kind == "any" || kind == "typedef" || kind == "enum"
      || kind == "function" || kind == "pointer" || kind == "array"
      || kind == "udt" || kind == "struct" || kind == "union" || kind == "other";
}

} // namespace

using type_service_detail::Details;
using type_service_detail::MaxDetailDeclarationBytes;
using type_service_detail::MaxDetailMembers;
using type_service_detail::MaxDetailRelatedTypes;
using type_service_detail::MaxOrdinals;
using type_service_detail::MaxQueryDeclarationBytes;
using type_service_detail::MaxQueryMembers;
using type_service_detail::MaxQueryRelatedTypes;

TypeSearchOutcome TypeService::Search(
    std::string_view name,
    std::string_view kind,
    std::uint32_t ordinal,
    std::uint32_t limit) const
{
  if ( !IsKnownKind(kind) ) return {TypeStatus::InvalidArgument, std::nullopt};
  const std::uint32_t end = get_ordinal_limit();
  if ( end == 0 || end == std::uint32_t(-1) ) return {TypeStatus::Success, TypeSearchResult{}};
  if ( ordinal == 0 ) ordinal = 1;
  if ( ordinal > MaxOrdinals ) return {TypeStatus::OutputLimit, std::nullopt};
  const std::string name_filter = Lower(name);
  TypeSearchResult result;
  std::uint32_t current = ordinal;
  std::size_t scanned = 0;
  for ( ; current < end && current <= MaxOrdinals && scanned < 4096; ++current, ++scanned )
  {
    const char *type_name = get_numbered_type_name(nullptr, current);
    if ( type_name == nullptr || *type_name == '\0' ) continue;
    const std::string stable_type_name(type_name);
    if ( stable_type_name.size() > 1024 || !is_valid_utf8(stable_type_name.c_str()) ) continue;
    tinfo_t type;
    if ( !type.get_numbered_type(current) || !KindMatches(kind, type) ) continue;
    if ( !name_filter.empty() && Lower(stable_type_name).find(name_filter) == std::string::npos ) continue;
    if ( result.items.size() == limit ) break;
    auto details = Details(
        type, stable_type_name, current, MaxQueryMembers, MaxQueryRelatedTypes,
        MaxQueryDeclarationBytes);
    if ( details ) result.items.push_back(std::move(*details));
  }
  if ( current < end )
  {
    if ( current > MaxOrdinals ) return {TypeStatus::OutputLimit, std::nullopt};
    result.has_more = true;
    result.next_ordinal = current;
  }
  return {TypeStatus::Success, std::move(result)};
}

TypeDetailsOutcome TypeService::Get(std::string_view name) const
{
  tinfo_t type;
  const std::string stable_name(name);
  if ( !type.get_named_type(stable_name.c_str()) ) return {TypeStatus::NotFound, std::nullopt};
  const int32 ordinal = get_type_ordinal(nullptr, stable_name.c_str());
  auto result = Details(
      type, stable_name, ordinal > 0 ? static_cast<std::uint32_t>(ordinal) : 0,
      MaxDetailMembers, MaxDetailRelatedTypes, MaxDetailDeclarationBytes);
  return result ? TypeDetailsOutcome{TypeStatus::Success, std::move(result)}
                : TypeDetailsOutcome{TypeStatus::OutputLimit, std::nullopt};
}

} // namespace ida_agent::services
