#include "debugger_service.hpp"
#include "query_helpers.hpp"
#include "address.hpp"
#include <dbg.hpp>
#include <algorithm>
#include <limits>

namespace ida_agent::services
{
using namespace query;
namespace
{
constexpr std::uint32_t MaxNameBytes = 4096;
constexpr std::uint32_t MaxThreads = 1024;
constexpr std::uint32_t MaxModules = 4096;
}

QueryResult DebuggerService::DebuggerThreads(std::uint32_t limit, std::uint32_t cursor) const
{
  if ( dbg == nullptr ) return {QueryStatus::CapabilityUnavailable, {}};
  if ( get_process_state() != DSTATE_SUSP ) return {QueryStatus::Conflict, {}};
  const int quantity = get_thread_qty();
  if ( quantity < 0 || quantity > static_cast<int>(MaxThreads) ) return {QueryStatus::OutputLimit, {}};
  const std::uint32_t begin = (std::min)(cursor, static_cast<std::uint32_t>(quantity));
  const std::uint32_t finish = (std::min)(begin + limit, static_cast<std::uint32_t>(quantity));
  const thid_t current = get_current_thread();
  nlohmann::json items = nlohmann::json::array();
  for ( std::uint32_t index = begin; index < finish; ++index )
  {
    const thid_t thread = getn_thread(static_cast<int>(index));
    if ( thread == NO_THREAD || thread <= 0 ) return {QueryStatus::OutputLimit, {}};
    const char *raw_name = getn_thread_name(static_cast<int>(index));
    nlohmann::json name = nullptr;
    if ( raw_name != nullptr && *raw_name != '\0' )
    {
      std::string value(raw_name);
      if ( !BoundedUtf8(value, MaxNameBytes) ) return {QueryStatus::OutputLimit, {}};
      name = std::move(value);
    }
    items.push_back({{"threadId", thread}, {"name", std::move(name)}, {"current", thread == current}});
  }
  const bool more = finish < static_cast<std::uint32_t>(quantity);
  return {QueryStatus::Success, {
      {"items", std::move(items)},
      {"nextCursor", more ? nlohmann::json(finish) : nlohmann::json(nullptr)},
      {"hasMore", more},
  }};
}

QueryResult DebuggerService::DebuggerModules(std::uint32_t limit, std::uint32_t cursor) const
{
  if ( dbg == nullptr ) return {QueryStatus::CapabilityUnavailable, {}};
  if ( get_process_state() != DSTATE_SUSP ) return {QueryStatus::Conflict, {}};
  nlohmann::json items = nlohmann::json::array();
  modinfo_t module;
  bool ok = get_first_module(&module);
  std::uint32_t position = 0;
  while ( ok && position < cursor && position < MaxModules )
  {
    ++position;
    ok = get_next_module(&module);
  }
  while ( ok && items.size() < limit && position < MaxModules )
  {
    if ( module.base == BADADDR ) return {QueryStatus::OutputLimit, {}};
    const auto name = BoundedBasename(module.name.c_str());
    if ( !name ) return {QueryStatus::OutputLimit, {}};
    items.push_back({
        {"name", *name}, {"base", rpc::FormatAddress(module.base)}, {"size", module.size},
        {"rebaseTo", module.rebase_to == BADADDR ? nlohmann::json(nullptr) : nlohmann::json(rpc::FormatAddress(module.rebase_to))},
    });
    ++position;
    ok = get_next_module(&module);
  }
  if ( ok && position >= MaxModules ) return {QueryStatus::OutputLimit, {}};
  return {QueryStatus::Success, {
      {"items", std::move(items)},
      {"nextCursor", ok ? nlohmann::json(position) : nlohmann::json(nullptr)},
      {"hasMore", ok},
  }};
}
}
