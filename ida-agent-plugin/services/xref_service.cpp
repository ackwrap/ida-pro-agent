#include "xref_service.hpp"

#include "address.hpp"
#include "xref_query_cursor.hpp"

#include <bytes.hpp>
#include <xref.hpp>

#include <stdexcept>
#include <string_view>

namespace ida_agent::services
{
namespace
{

constexpr std::uint64_t MaxXrefPhaseIndex = 1000000;

std::string_view DirectionName(XrefDirection direction)
{
  return direction == XrefDirection::Incoming ? "incoming" : "outgoing";
}

std::string_view CategoryName(XrefCategory category)
{
  switch ( category )
  {
    case XrefCategory::All:
      return "all";
    case XrefCategory::Code:
      return "code";
    case XrefCategory::Data:
      return "data";
  }
  throw std::runtime_error("xref category is invalid");
}

std::string QueryIdentity(const XrefQuery &query)
{
  return rpc::FormatAddress(query.address) + "|" + std::string(DirectionName(query.direction))
      + "|" + std::string(CategoryName(query.category))
      + (query.include_flow ? "|1" : "|0");
}

std::string XrefType(bool code, unsigned char type)
{
  const unsigned char masked = type & XREF_MASK;
  if ( code )
  {
    switch ( masked )
    {
      case fl_CF:
        return "call_far";
      case fl_CN:
        return "call_near";
      case fl_JF:
        return "jump_far";
      case fl_JN:
        return "jump_near";
      case fl_F:
        return "flow";
      default:
        return "unknown_code";
    }
  }
  switch ( masked )
  {
    case dr_O:
      return "offset";
    case dr_W:
      return "write";
    case dr_R:
      return "read";
    case dr_T:
      return "text";
    case dr_I:
      return "informational";
    case dr_S:
      return "symbolic";
    default:
      return "unknown_data";
  }
}

bool FirstXref(
    xrefblk_t &xref,
    const XrefQuery &query,
    bool data_phase)
{
  int flags = XREF_EA | (data_phase ? XREF_DATA : XREF_CODE);
  if ( !data_phase && !query.include_flow )
    flags |= XREF_NOFLOW;
  if ( query.direction == XrefDirection::Outgoing )
    return xref.first_from(query.address, flags);
  return xref.first_to(query.address, flags);
}

bool NextXref(xrefblk_t &xref, XrefDirection direction)
{
  return direction == XrefDirection::Outgoing ? xref.next_from() : xref.next_to();
}

} // namespace

XrefQueryOutcome XrefService::Query(const XrefQuery &query) const
{
  const ea_t address = static_cast<ea_t>(query.address);
  if ( static_cast<std::uint64_t>(address) != query.address
    || address == BADADDR || !is_mapped(address) )
    return {XrefQueryStatus::InvalidAddress, std::nullopt};

  const std::string identity = QueryIdentity(query);
  bool cursor_data_phase = false;
  std::uint64_t cursor_next_index = 0;
  if ( query.cursor )
  {
    try
    {
      const rpc::XrefQueryCursor decoded = rpc::DecodeXrefQueryCursor(
          *query.cursor,
          identity);
      cursor_data_phase = decoded.data_phase;
      cursor_next_index = decoded.next_index;
    }
    catch ( const std::invalid_argument & )
    {
      return {XrefQueryStatus::InvalidCursor, std::nullopt};
    }
    if ( cursor_next_index > MaxXrefPhaseIndex
      || (query.category == XrefCategory::Code && cursor_data_phase)
      || (query.category == XrefCategory::Data && !cursor_data_phase) )
    {
      return {XrefQueryStatus::InvalidCursor, std::nullopt};
    }
  }

  const bool first_data_phase = query.category == XrefCategory::Data
      || (query.cursor && cursor_data_phase);
  const bool last_data_phase = query.category != XrefCategory::Code;
  XrefQueryResult result;
  result.items.reserve(query.limit);

  for ( bool data_phase = first_data_phase;; data_phase = true )
  {
    xrefblk_t xref;
    const std::uint64_t resume_index =
        query.cursor && data_phase == cursor_data_phase ? cursor_next_index : 0;
    std::uint64_t phase_index = 0;
    for ( bool ok = FirstXref(xref, query, data_phase);
          ok;
          ok = NextXref(xref, query.direction) )
    {
      if ( phase_index < resume_index )
      {
        ++phase_index;
        continue;
      }
      XrefInfo item{
          xref.from,
          xref.to,
          XrefType(xref.iscode, xref.type),
          xref.iscode,
          xref.user,
      };
      if ( result.items.size() == query.limit )
      {
        if ( phase_index > MaxXrefPhaseIndex )
          return {XrefQueryStatus::OutputLimit, std::nullopt};
        result.has_more = true;
        result.next_cursor = rpc::EncodeXrefQueryCursor(
            identity,
            data_phase,
            phase_index);
        return {XrefQueryStatus::Success, std::move(result)};
      }
      result.items.push_back(std::move(item));
      ++phase_index;
    }
    if ( phase_index < resume_index )
      return {XrefQueryStatus::InvalidCursor, std::nullopt};
    if ( data_phase || !last_data_phase )
      break;
  }
  return {XrefQueryStatus::Success, std::move(result)};
}

nlohmann::json ToJson(const XrefQueryResult &result)
{
  nlohmann::json items = nlohmann::json::array();
  for ( const XrefInfo &item : result.items )
  {
    items.push_back({
        {"from", rpc::FormatAddress(item.from)},
        {"to", rpc::FormatAddress(item.to)},
        {"type", item.type},
        {"code", item.code},
        {"userDefined", item.user_defined},
    });
  }
  nlohmann::json next_cursor = nullptr;
  if ( result.next_cursor )
    next_cursor = *result.next_cursor;
  return {
      {"items", std::move(items)},
      {"nextCursor", std::move(next_cursor)},
      {"hasMore", result.has_more},
  };
}

} // namespace ida_agent::services
