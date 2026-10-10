#pragma once
#include <nlohmann/json.hpp>

namespace ida_agent::services
{
enum class QueryStatus
{
  Success,
  InvalidAddress,
  InvalidArgument,
  NotFound,
  CapabilityUnavailable,
  Conflict,
  Busy,
  DecompileFailed,
  OutputLimit,
};

struct QueryResult
{
  QueryStatus status;
  nlohmann::json value;
};

}
