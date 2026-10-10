#include "type_service.hpp"
#include "query_helpers.hpp"
#include "address.hpp"
#include <bytes.hpp>
#include <typeinf.hpp>
#include <xref.hpp>
#include <algorithm>
#include <limits>

namespace ida_agent::services
{
using namespace query;
namespace
{
constexpr std::uint32_t MaxNameBytes = 4096;
constexpr std::uint32_t MaxSourceScans = 1000000;
std::string XrefType(bool code, unsigned char type)
{
  const unsigned char masked = type & XREF_MASK;
  if ( code )
  {
    switch ( masked )
    {
      case fl_CF: return "call_far";
      case fl_CN: return "call_near";
      case fl_JF: return "jump_far";
      case fl_JN: return "jump_near";
      case fl_F: return "flow";
      default: return "unknown_code";
    }
  }
  switch ( masked )
  {
    case dr_O: return "offset";
    case dr_W: return "write";
    case dr_R: return "read";
    case dr_T: return "text";
    case dr_I: return "informational";
    case dr_S: return "symbolic";
    default: return "unknown_data";
  }
}
}

QueryResult TypeService::TypeXrefs(
    const std::string &name,
    std::uint32_t limit,
    std::uint32_t cursor) const
{
  if ( !BoundedUtf8(name, MaxNameBytes) || name.empty() )
    return {QueryStatus::InvalidArgument, {}};
  tinfo_t type;
  if ( !type.get_named_type(name.c_str()) ) return {QueryStatus::NotFound, {}};
  const tid_t tid = type.get_tid();
  if ( tid == BADADDR ) return {QueryStatus::CapabilityUnavailable, {}};
  nlohmann::json items = nlohmann::json::array();
  xrefblk_t xref;
  bool ok = xref.first_to(tid, XREF_TID);
  std::uint32_t position = 0;
  while ( ok && position < cursor && position < MaxSourceScans )
  {
    ++position;
    ok = xref.next_to();
  }
  while ( ok && items.size() < limit && position < MaxSourceScans )
  {
    if ( xref.from != BADADDR && is_mapped(xref.from) )
    {
      items.push_back({
          {"address", rpc::FormatAddress(xref.from)}, {"code", xref.iscode},
          {"userDefined", xref.user}, {"xrefType", XrefType(xref.iscode, xref.type)},
      });
    }
    ++position;
    ok = xref.next_to();
  }
  if ( ok && position >= MaxSourceScans ) return {QueryStatus::OutputLimit, {}};
  return {QueryStatus::Success, {
      {"items", std::move(items)},
      {"nextCursor", ok ? nlohmann::json(position) : nlohmann::json(nullptr)},
      {"hasMore", ok},
  }};
}
}
