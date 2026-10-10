#include "source_info_service.hpp"
#include "query_helpers.hpp"
#include "address.hpp"
#include <nalt.hpp>
#include <bytes.hpp>
#include <algorithm>
#include <limits>

namespace ida_agent::services
{
using namespace query;
namespace
{
constexpr std::uint32_t MaxSourceScans = 1000000;
}

QueryResult SourceInfoService::SourceFiles(std::uint32_t limit, std::uint32_t cursor) const
{
  const std::size_t quantity = get_sourcefiles_qty();
  const std::size_t begin = (std::min)(static_cast<std::size_t>(cursor), quantity);
  const std::size_t finish = (std::min)(begin + limit, quantity);
  nlohmann::json items = nlohmann::json::array();
  for ( std::size_t index = begin; index < finish; ++index )
  {
    sourcefile_info_t source;
    if ( !getn_sourcefile(&source, index) )
      return {QueryStatus::OutputLimit, {}};
    const auto filename = BoundedBasename(source.filename.c_str());
    if ( !filename || source.range.start_ea == BADADDR || source.range.end_ea == BADADDR
      || source.range.start_ea >= source.range.end_ea )
      return {QueryStatus::OutputLimit, {}};
    items.push_back({
        {"start", rpc::FormatAddress(source.range.start_ea)},
        {"end", rpc::FormatAddress(source.range.end_ea)},
        {"filename", *filename},
    });
  }
  const bool more = finish < quantity;
  return {QueryStatus::Success, {
      {"items", std::move(items)},
      {"nextCursor", more ? nlohmann::json(finish) : nlohmann::json(nullptr)},
      {"hasMore", more},
  }};
}

QueryResult SourceInfoService::SourceLines(
    std::uint64_t start,
    std::uint64_t end,
    std::uint32_t limit,
    const std::optional<std::uint64_t> &cursor) const
{
  ea_t lower = BADADDR;
  ea_t upper = BADADDR;
  ea_t current = BADADDR;
  if ( !StableAddress(start, &lower) || !StableAddress(end, &upper) || lower >= upper )
    return {QueryStatus::InvalidAddress, {}};
  if ( cursor )
  {
    if ( !StableAddress(*cursor, &current) || current < lower || current >= upper )
      return {QueryStatus::InvalidAddress, {}};
  }
  else
  {
    current = lower;
  }
  nlohmann::json items = nlohmann::json::array();
  std::uint32_t scanned = 0;
  while ( current != BADADDR && current < upper && scanned < MaxSourceScans && items.size() < limit )
  {
    ++scanned;
    if ( has_aflag_linnum(get_aflags(current)) )
    {
      qstring path;
      nlohmann::json filename = nullptr;
      if ( get_sourcefile_by_ea(&path, current) )
      {
        const auto base = BoundedBasename(path.c_str());
        if ( !base ) return {QueryStatus::OutputLimit, {}};
        filename = *base;
      }
      items.push_back({
          {"address", rpc::FormatAddress(current)},
          {"line", get_source_linnum(current)},
          {"filename", std::move(filename)},
      });
    }
    current = next_addr(current);
  }
  const bool more = current != BADADDR && current < upper;
  return {QueryStatus::Success, {
      {"items", std::move(items)},
      {"nextCursor", more ? nlohmann::json(rpc::FormatAddress(current)) : nlohmann::json(nullptr)},
      {"hasMore", more},
  }};
}
}
