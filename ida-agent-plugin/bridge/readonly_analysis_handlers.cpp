#include "readonly_analysis_handlers.hpp"

#include "ida_executor.hpp"
#include "rpc/address.hpp"
#include "services/readonly_analysis_service.hpp"

#include <chrono>
#include <cmath>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace ida_agent::bridge
{
namespace
{

Dispatcher::MethodResult Error(rpc::ErrorCode code, const char *message, bool retryable = false)
{
  return rpc::RpcError{code, message, retryable};
}

bool HasOnlyFields(const nlohmann::json &params, std::initializer_list<std::string_view> allowed)
{
  for ( auto field = params.begin(); field != params.end(); ++field )
  {
    bool found = false;
    for ( std::string_view name : allowed )
      found = found || field.key() == name;
    if ( !found )
      return false;
  }
  return true;
}

std::optional<std::uint64_t> Address(const nlohmann::json &params, const char *name, bool required)
{
  if ( !params.contains(name) )
  {
    if ( required )
      throw std::invalid_argument("address is required");
    return std::nullopt;
  }
  if ( !params[name].is_string() )
    throw std::invalid_argument("address must be a string");
  return rpc::ParseAddress(params[name].get<std::string>());
}

std::optional<std::uint32_t> Integer(
    const nlohmann::json &params,
    const char *name,
    std::uint32_t default_value,
    std::uint32_t minimum,
    std::uint32_t maximum)
{
  if ( !params.contains(name) )
    return default_value;
  const auto &value = params[name];
  std::uint64_t parsed = 0;
  if ( value.is_number_unsigned() )
    parsed = value.get<std::uint64_t>();
  else if ( value.is_number_integer() && value.get<std::int64_t>() >= 0 )
    parsed = static_cast<std::uint64_t>(value.get<std::int64_t>());
  else
    return std::nullopt;
  if ( parsed < minimum || parsed > maximum )
    return std::nullopt;
  return static_cast<std::uint32_t>(parsed);
}

Dispatcher::MethodResult Convert(services::ReadonlyResult result)
{
  switch ( result.status )
  {
    case services::ReadonlyStatus::Success: return std::move(result.value);
    case services::ReadonlyStatus::InvalidAddress:
      return Error(rpc::ErrorCode::InvalidAddress, "IDA address is invalid");
    case services::ReadonlyStatus::NotFound:
      return Error(rpc::ErrorCode::NotFound, "requested IDA object was not found");
    case services::ReadonlyStatus::OutputLimit:
      return Error(rpc::ErrorCode::OutputLimit, "IDA output exceeds the configured limit");
  }
  throw std::runtime_error("readonly analysis status is unavailable");
}

template <typename Operation>
Dispatcher::MethodResult Run(IdaExecutor &executor, const rpc::Request &request, Operation operation)
{
  try
  {
    return Convert(executor.ReadFor(std::chrono::milliseconds(request.timeout_ms), std::move(operation)));
  }
  catch ( const IdaTimeoutError & )
  {
    return Error(rpc::ErrorCode::Timeout, "IDA request timed out", true);
  }
  catch ( const IdaBusyError & )
  {
    return Error(rpc::ErrorCode::IdaBusy, "IDA is busy", true);
  }
}

template <typename Operation>
Dispatcher::MethodResult RunWrite(IdaExecutor &executor, const rpc::Request &request, Operation operation)
{
  try
  {
    return Convert(executor.WriteFor(std::chrono::milliseconds(request.timeout_ms), std::move(operation)));
  }
  catch ( const IdaTimeoutError & ) { return Error(rpc::ErrorCode::Timeout, "IDA request timed out", true); }
  catch ( const IdaBusyError & ) { return Error(rpc::ErrorCode::IdaBusy, "IDA is busy", true); }
}

} // namespace

Dispatcher::MethodHandlers BuildReadonlyAnalysisHandlers(
    IdaExecutor &executor,
    const services::ReadonlyAnalysisService &service)
{
  Dispatcher::MethodHandlers handlers;
  handlers.emplace("instruction.get", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( !HasOnlyFields(request.params, {"address"}) ) return Error(rpc::ErrorCode::InvalidArgument, "instruction.get contains an unknown parameter");
    try { const auto address = Address(request.params, "address", true); return Run(executor, request, [&service, address]() { return service.InstructionGet(*address); }); }
    catch ( const std::invalid_argument & ) { return Error(rpc::ErrorCode::InvalidArgument, "instruction.get parameters are invalid"); }
  });
  handlers.emplace("function.chunks", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( !HasOnlyFields(request.params, {"address", "offset", "limit"}) ) return Error(rpc::ErrorCode::InvalidArgument, "function.chunks contains an unknown parameter");
    try { const auto address = Address(request.params, "address", true); const auto offset = Integer(request.params, "offset", 0, 0, 1000000); const auto limit = Integer(request.params, "limit", 20, 1, 100); if ( !offset || !limit ) throw std::invalid_argument("integer"); return Run(executor, request, [&service, address, offset, limit]() { return service.FunctionChunks(*address, *offset, *limit); }); }
    catch ( const std::invalid_argument & ) { return Error(rpc::ErrorCode::InvalidArgument, "function.chunks parameters are invalid"); }
  });
  handlers.emplace("fixup.get", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( !HasOnlyFields(request.params, {"address"}) ) return Error(rpc::ErrorCode::InvalidArgument, "fixup.get contains an unknown parameter");
    try { const auto address = Address(request.params, "address", true); return Run(executor, request, [&service, address]() { return service.FixupGet(*address); }); }
    catch ( const std::invalid_argument & ) { return Error(rpc::ErrorCode::InvalidArgument, "fixup.get parameters are invalid"); }
  });
  handlers.emplace("fixup.list", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( !HasOnlyFields(request.params, {"start", "end", "limit", "nextAddress"}) ) return Error(rpc::ErrorCode::InvalidArgument, "fixup.list contains an unknown parameter");
    try { const auto start = Address(request.params, "start", false); const auto end = Address(request.params, "end", false); const auto next = Address(request.params, "nextAddress", false); const auto limit = Integer(request.params, "limit", 20, 1, 100); if ( !limit || start.has_value() != end.has_value() || (start && *start >= *end) || (next && start && (*next < *start || *next >= *end)) ) throw std::invalid_argument("range"); return Run(executor, request, [&service, start, end, limit, next]() { return service.FixupList(start, end, *limit, next); }); }
    catch ( const std::invalid_argument & ) { return Error(rpc::ErrorCode::InvalidArgument, "fixup.list parameters are invalid"); }
  });
  handlers.emplace("switch.get", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( !HasOnlyFields(request.params, {"address"}) ) return Error(rpc::ErrorCode::InvalidArgument, "switch.get contains an unknown parameter");
    try { const auto address = Address(request.params, "address", true); return Run(executor, request, [&service, address]() { return service.SwitchGet(*address); }); }
    catch ( const std::invalid_argument & ) { return Error(rpc::ErrorCode::InvalidArgument, "switch.get parameters are invalid"); }
  });
  handlers.emplace("exception.try_blocks", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( !HasOnlyFields(request.params, {"address", "limit"}) ) return Error(rpc::ErrorCode::InvalidArgument, "exception.try_blocks contains an unknown parameter");
    try { const auto address = Address(request.params, "address", true); const auto limit = Integer(request.params, "limit", 20, 1, 100); if ( !limit ) throw std::invalid_argument("limit"); return Run(executor, request, [&service, address, limit]() { return service.ExceptionTryBlocks(*address, *limit); }); }
    catch ( const std::invalid_argument & ) { return Error(rpc::ErrorCode::InvalidArgument, "exception.try_blocks parameters are invalid"); }
  });
  handlers.emplace("analysis.status", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( !request.params.empty() ) return Error(rpc::ErrorCode::InvalidArgument, "analysis.status params must be empty");
    return Run(executor, request, [&service]() { return service.AnalysisStatus(); });
  });
  handlers.emplace("analysis.plan", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( !HasOnlyFields(request.params, {"start", "end", "confirm"}) || !request.params.contains("confirm") || !request.params["confirm"].is_boolean() || !request.params["confirm"].get<bool>() ) return Error(rpc::ErrorCode::InvalidArgument, "analysis.plan parameters are invalid");
    try { const auto start = Address(request.params, "start", true); const auto end = Address(request.params, "end", true); if ( *start >= *end || *end - *start > 16ULL * 1024 * 1024 ) return Error(rpc::ErrorCode::InvalidArgument, "analysis.plan range is invalid"); return RunWrite(executor, request, [&service, start, end]() { return service.AnalysisPlan(*start, *end); }); }
    catch ( const std::invalid_argument & ) { return Error(rpc::ErrorCode::InvalidArgument, "analysis.plan parameters are invalid"); }
  });
  handlers.emplace("analysis.problems", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( !HasOnlyFields(request.params, {"type", "start", "limit", "nextAddress"}) ) return Error(rpc::ErrorCode::InvalidArgument, "analysis.problems contains an unknown parameter");
    try { if ( !request.params.contains("type") || !request.params["type"].is_string() ) throw std::invalid_argument("type"); const std::string type = request.params["type"].get<std::string>(); const auto start = Address(request.params, "start", false); const auto next = Address(request.params, "nextAddress", false); const auto limit = Integer(request.params, "limit", 20, 1, 100); if ( !limit || (start && next && *next < *start) ) throw std::invalid_argument("continuation"); return Run(executor, request, [&service, type, start, limit, next]() { return service.AnalysisProblems(type, start, *limit, next); }); }
    catch ( const std::invalid_argument & ) { return Error(rpc::ErrorCode::InvalidArgument, "analysis.problems parameters are invalid"); }
  });
  return handlers;
}

} // namespace ida_agent::bridge
