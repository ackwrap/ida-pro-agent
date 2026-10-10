#include "function_graph_handlers.hpp"

#include "ida_executor.hpp"
#include "rpc/address.hpp"
#include "services/function_service.hpp"

#include <chrono>
#include <cmath>
#include <optional>
#include <stdexcept>
#include <string>

namespace ida_agent::bridge
{
namespace
{
constexpr std::size_t MaxFunctionGraphResultBytes = 500 * 1024;

Dispatcher::MethodResult Error(rpc::ErrorCode code, const char *message, bool retryable = false)
{
  return rpc::RpcError{code, message, retryable};
}

std::optional<std::uint32_t> Bounded(const nlohmann::json &value, std::uint32_t low, std::uint32_t high)
{
  if ( !value.is_number_integer() && !value.is_number_unsigned() )
    return std::nullopt;
  if ( value.is_number_unsigned() )
  {
    const auto parsed = value.get<std::uint64_t>();
    if ( parsed < low || parsed > high ) return std::nullopt;
    return static_cast<std::uint32_t>(parsed);
  }
  const auto parsed = value.get<std::int64_t>();
  if ( parsed < low || parsed > high )
    return std::nullopt;
  return static_cast<std::uint32_t>(parsed);
}

Dispatcher::MethodResult Run(
    IdaExecutor &executor,
    const rpc::Request &request,
    const std::function<Dispatcher::MethodResult()> &operation)
{
  try
  {
    return executor.ReadFor(std::chrono::milliseconds(request.timeout_ms), operation);
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

template <typename Outcome>
Dispatcher::MethodResult Result(Outcome outcome)
{
  switch ( outcome.status )
  {
    case services::FunctionAnalysisStatus::InvalidAddress:
      return Error(rpc::ErrorCode::InvalidAddress, "function address is not mapped");
    case services::FunctionAnalysisStatus::NotFound:
      return Error(rpc::ErrorCode::NotFound, "function was not found");
    case services::FunctionAnalysisStatus::OutputLimit:
      return Error(rpc::ErrorCode::OutputLimit, "function graph exceeds the configured limit");
    case services::FunctionAnalysisStatus::Success:
      break;
  }
  if ( !outcome.result )
    throw std::runtime_error("function graph did not return a result");
  nlohmann::json result = services::ToJson(*outcome.result);
  if ( result.dump().size() > MaxFunctionGraphResultBytes )
    return Error(rpc::ErrorCode::OutputLimit, "function graph exceeds the configured limit");
  return result;
}

} // namespace

Dispatcher::MethodHandlers BuildFunctionGraphHandlers(
    IdaExecutor &executor,
    const services::FunctionService &function_service)
{
  Dispatcher::MethodHandlers handlers;
  handlers.emplace("function.callers", [&executor, &function_service](const rpc::Request &request)
      -> Dispatcher::MethodResult
  {
    for ( auto field = request.params.begin(); field != request.params.end(); ++field )
    {
      if ( field.key() != "address" && field.key() != "offset" && field.key() != "limit" )
        return Error(rpc::ErrorCode::InvalidArgument, "function.callers contains an unknown parameter");
    }
    if ( !request.params.contains("address") || !request.params["address"].is_string() )
      return Error(rpc::ErrorCode::InvalidArgument, "function.callers requires address");
    std::uint64_t address = 0;
    try { address = rpc::ParseAddress(request.params["address"].get<std::string>()); }
    catch ( const std::invalid_argument & ) { return Error(rpc::ErrorCode::InvalidAddress, "function address is invalid"); }
    std::uint32_t offset = 0;
    std::uint32_t limit = 20;
    if ( request.params.contains("offset") )
    {
      const auto value = Bounded(request.params["offset"], 0, 1000000);
      if ( !value ) return Error(rpc::ErrorCode::InvalidArgument, "function.callers offset is invalid");
      offset = *value;
    }
    if ( request.params.contains("limit") )
    {
      const auto value = Bounded(request.params["limit"], 1, 100);
      if ( !value ) return Error(rpc::ErrorCode::InvalidArgument, "function.callers limit is invalid");
      limit = *value;
    }
    return Run(executor, request, [&function_service, address, offset, limit]()
    {
      return Result(function_service.Callers({address, offset, limit}));
    });
  });
  handlers.emplace("function.callgraph", [&executor, &function_service](const rpc::Request &request)
      -> Dispatcher::MethodResult
  {
    for ( auto field = request.params.begin(); field != request.params.end(); ++field )
    {
      if ( field.key() != "roots" && field.key() != "direction" && field.key() != "maxDepth"
        && field.key() != "maxNodes" && field.key() != "maxEdges" && field.key() != "perFunction" )
      {
        return Error(rpc::ErrorCode::InvalidArgument, "function.callgraph contains an unknown parameter");
      }
    }
    if ( !request.params.contains("roots") || !request.params["roots"].is_array()
      || request.params["roots"].empty() || request.params["roots"].size() > 16 )
    {
      return Error(rpc::ErrorCode::InvalidArgument, "function.callgraph roots must contain 1 to 16 addresses");
    }
    services::CallGraphQuery query{{}, services::CallGraphDirection::Callees, 2, 100, 200, 100};
    for ( const auto &root : request.params["roots"] )
    {
      if ( !root.is_string() ) return Error(rpc::ErrorCode::InvalidArgument, "callgraph root is invalid");
      try { query.roots.push_back(rpc::ParseAddress(root.get<std::string>())); }
      catch ( const std::invalid_argument & ) { return Error(rpc::ErrorCode::InvalidAddress, "callgraph root is invalid"); }
    }
    if ( request.params.contains("direction") )
    {
      if ( !request.params["direction"].is_string() ) return Error(rpc::ErrorCode::InvalidArgument, "callgraph direction is invalid");
      const std::string value = request.params["direction"].get<std::string>();
      if ( value == "callers" ) query.direction = services::CallGraphDirection::Callers;
      else if ( value == "callees" ) query.direction = services::CallGraphDirection::Callees;
      else if ( value == "both" ) query.direction = services::CallGraphDirection::Both;
      else return Error(rpc::ErrorCode::InvalidArgument, "callgraph direction is invalid");
    }
    const struct { const char *name; std::uint32_t low; std::uint32_t high; std::uint32_t *target; } bounds[] = {
        {"maxDepth", 0, 5, &query.max_depth}, {"maxNodes", 1, 500, &query.max_nodes},
        {"maxEdges", 1, 1000, &query.max_edges}, {"perFunction", 1, 100, &query.per_function},
    };
    for ( const auto &bound : bounds )
    {
      if ( !request.params.contains(bound.name) ) continue;
      const auto value = Bounded(request.params[bound.name], bound.low, bound.high);
      if ( !value ) return Error(rpc::ErrorCode::InvalidArgument, "callgraph bound is invalid");
      *bound.target = *value;
    }
    return Run(executor, request, [&function_service, query]() { return Result(function_service.CallGraph(query)); });
  });
  return handlers;
}

} // namespace ida_agent::bridge
