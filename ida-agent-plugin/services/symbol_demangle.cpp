#include "symbol_service.hpp"
#include "query_helpers.hpp"
#include "address.hpp"
#include <name.hpp>
#include <demangle.hpp>
#include <algorithm>
#include <limits>

namespace ida_agent::services
{
using namespace query;
namespace
{
constexpr std::uint32_t MaxNameBytes = 4096;
constexpr std::uint32_t MaxTextBytes = 16 * 1024;
}

QueryResult SymbolService::Demangle(
    const std::optional<std::uint64_t> &address,
    const std::optional<std::string> &name) const
{
  std::string raw;
  if ( address )
  {
    ea_t ea = BADADDR;
    if ( !StableAddress(*address, &ea) ) return {QueryStatus::InvalidAddress, {}};
    qstring ida_name;
    if ( get_ea_name(&ida_name, ea) <= 0 ) return {QueryStatus::NotFound, {}};
    raw.assign(ida_name.c_str(), ida_name.length());
  }
  else if ( name )
  {
    raw = *name;
  }
  else
  {
    return {QueryStatus::InvalidArgument, {}};
  }
  if ( !BoundedUtf8(raw, MaxNameBytes) ) return {QueryStatus::InvalidArgument, {}};
  const auto form = [&raw](uint32 flags) -> nlohmann::json {
    qstring output;
    demangle_name(&output, raw.c_str(), flags, DQT_FULL);
    std::string value(output.c_str(), output.length());
    if ( value.empty() || value == raw ) return nullptr;
    if ( !BoundedUtf8(value, MaxTextBytes) ) return nullptr;
    return value;
  };
  return {QueryStatus::Success, {
      {"raw", raw}, {"short", form(MNG_SHORT_FORM)}, {"long", form(MNG_LONG_FORM)},
  }};
}
}
