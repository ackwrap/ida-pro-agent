#pragma once

#include <nlohmann/json.hpp>
#include <optional>

namespace ida_agent::rpc
{

// Refresh is a first-page operation, never a continuation option.
inline std::optional<bool> ReadStringSearchRefresh(const nlohmann::json &params)
{
  const auto value = params.find("refresh");
  if ( value == params.end() )
    return false;
  if ( !value->is_boolean() )
    return std::nullopt;
  const bool refresh = value->get<bool>();
  if ( refresh && params.contains("cursor") )
    return std::nullopt;
  return refresh;
}

} // namespace ida_agent::rpc
