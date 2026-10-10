#include "type_service.hpp"

#include <typeinf.hpp>
#include <xref.hpp>

#include <algorithm>
#include <utility>

namespace ida_agent::services
{

StructFieldXrefOutcome TypeService::FieldXrefs(
    std::string_view type_name,
    std::string_view field_name,
    std::uint32_t limit) const
{
  tinfo_t type;
  const std::string stable_type(type_name), stable_field(field_name);
  if ( !type.get_named_type(stable_type.c_str()) || !type.is_udt() ) return {TypeStatus::NotFound, std::nullopt};
  const int index = type.find_udm(stable_field.c_str(), STRMEM_NAME);
  if ( index < 0 ) return {TypeStatus::NotFound, std::nullopt};
  const tid_t field_tid = type.get_udm_tid(static_cast<std::size_t>(index));
  if ( field_tid == BADNODE ) return {TypeStatus::NotFound, std::nullopt};
  StructFieldXrefResult result;
  xrefblk_t xref;
  for ( bool found = xref.first_to(field_tid, XREF_ALL); found; found = xref.next_to() )
  {
    if ( result.items.size() == limit ) { result.truncated = true; break; }
    result.items.push_back(xref.from);
  }
  std::sort(result.items.begin(), result.items.end());
  result.items.erase(std::unique(result.items.begin(), result.items.end()), result.items.end());
  return {TypeStatus::Success, std::move(result)};
}

} // namespace ida_agent::services
