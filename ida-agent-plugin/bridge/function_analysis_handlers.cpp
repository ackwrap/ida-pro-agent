#include "function_analysis_handlers.hpp"

#include "ida_executor.hpp"
#include "rpc/address.hpp"
#include "services/function_service.hpp"

#include <chrono>
#include <cmath>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace ida_agent::bridge
{
namespace
{

Dispatcher::MethodResult Error(
    rpc::ErrorCode code,
    const char *message,
    bool retryable = false)
{
  return rpc::RpcError{code, message, retryable};
}

std::optional<std::uint32_t> ReadBoundedInteger(
    const nlohmann::json &value,
    std::uint32_t minimum,
    std::uint32_t maximum)
{
  std::uint64_t parsed = 0;
  if ( value.is_number_unsigned() )
  {
    parsed = value.get<std::uint64_t>();
  }
  else if ( value.is_number_integer() )
  {
    const std::int64_t signed_value = value.get<std::int64_t>();
    if ( signed_value < 0 )
      return std::nullopt;
    parsed = static_cast<std::uint64_t>(signed_value);
  }
  else if ( value.is_number_float() )
  {
    const double float_value = value.get<double>();
    if ( !std::isfinite(float_value) || std::floor(float_value) != float_value
      || float_value < minimum || float_value > maximum )
    {
      return std::nullopt;
    }
    parsed = static_cast<std::uint64_t>(float_value);
  }
  else
  {
    return std::nullopt;
  }
  if ( parsed < minimum || parsed > maximum )
    return std::nullopt;
  return static_cast<std::uint32_t>(parsed);
}

std::optional<services::FunctionPageQuery> ReadFunctionPageQuery(
    const nlohmann::json &params,
    std::string_view method,
    rpc::RpcError *error)
{
  for ( auto field = params.begin(); field != params.end(); ++field )
  {
    if ( field.key() != "address" && field.key() != "offset" && field.key() != "limit" )
    {
      *error = rpc::RpcError{
          rpc::ErrorCode::InvalidArgument,
          std::string(method) + " contains an unknown parameter",
          false,
      };
      return std::nullopt;
    }
  }
  if ( !params.contains("address") || !params["address"].is_string() )
  {
    *error = rpc::RpcError{
        rpc::ErrorCode::InvalidArgument,
        std::string(method) + " requires a string address",
        false,
    };
    return std::nullopt;
  }

  std::uint64_t address = 0;
  try
  {
    address = rpc::ParseAddress(params["address"].get<std::string>());
  }
  catch ( const std::invalid_argument & )
  {
    *error = rpc::RpcError{
        rpc::ErrorCode::InvalidAddress,
        std::string(method) + " address is invalid",
        false,
    };
    return std::nullopt;
  }

  std::uint32_t offset = 0;
  if ( params.contains("offset") )
  {
    const auto parsed = ReadBoundedInteger(params["offset"], 0, 1000000);
    if ( !parsed )
    {
      *error = rpc::RpcError{
          rpc::ErrorCode::InvalidArgument,
          std::string(method) + " offset must be from 0 to 1000000",
          false,
      };
      return std::nullopt;
    }
    offset = *parsed;
  }
  std::uint32_t limit = 20;
  if ( params.contains("limit") )
  {
    const auto parsed = ReadBoundedInteger(params["limit"], 1, 100);
    if ( !parsed )
    {
      *error = rpc::RpcError{
          rpc::ErrorCode::InvalidArgument,
          std::string(method) + " limit must be from 1 to 100",
          false,
      };
      return std::nullopt;
    }
    limit = *parsed;
  }
  return services::FunctionPageQuery{address, offset, limit};
}

template <typename Operation>
Dispatcher::MethodResult RunFunctionAnalysis(
    IdaExecutor &executor,
    const rpc::Request &request,
    Operation &&operation)
{
  try
  {
    auto outcome = executor.ReadFor(
        std::chrono::milliseconds(request.timeout_ms),
        std::forward<Operation>(operation));
    switch ( outcome.status )
    {
      case services::FunctionAnalysisStatus::InvalidAddress:
        return Error(rpc::ErrorCode::InvalidAddress, "function address is not mapped");
      case services::FunctionAnalysisStatus::NotFound:
        return Error(rpc::ErrorCode::NotFound, "function was not found at the address");
      case services::FunctionAnalysisStatus::OutputLimit:
        return Error(rpc::ErrorCode::OutputLimit, "function analysis exceeds the configured limit");
      case services::FunctionAnalysisStatus::Success:
        break;
    }
    if ( !outcome.result )
      throw std::runtime_error("function analysis did not return a result");
    return services::ToJson(*outcome.result);
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

} // namespace

Dispatcher::MethodHandlers BuildFunctionAnalysisHandlers(
    IdaExecutor &executor,
    const services::FunctionService &function_service)
{
  Dispatcher::MethodHandlers handlers;
  handlers.emplace(
      "function.disassemble",
      [&executor, &function_service](const rpc::Request &request)
          -> Dispatcher::MethodResult
      {
        rpc::RpcError parse_error;
        const auto query = ReadFunctionPageQuery(
            request.params,
            "function.disassemble",
            &parse_error);
        if ( !query )
          return parse_error;
        return RunFunctionAnalysis(
            executor,
            request,
            [&function_service, query]() { return function_service.Disassemble(*query); });
      });
  handlers.emplace(
      "function.basic_blocks",
      [&executor, &function_service](const rpc::Request &request)
          -> Dispatcher::MethodResult
      {
        rpc::RpcError parse_error;
        const auto query = ReadFunctionPageQuery(
            request.params,
            "function.basic_blocks",
            &parse_error);
        if ( !query )
          return parse_error;
        return RunFunctionAnalysis(
            executor,
            request,
            [&function_service, query]() { return function_service.BasicBlocks(*query); });
      });
  handlers.emplace(
      "function.callees",
      [&executor, &function_service](const rpc::Request &request)
          -> Dispatcher::MethodResult
      {
        rpc::RpcError parse_error;
        const auto query = ReadFunctionPageQuery(
            request.params,
            "function.callees",
            &parse_error);
        if ( !query )
          return parse_error;
        return RunFunctionAnalysis(
            executor,
            request,
            [&function_service, query]() { return function_service.Callees(*query); });
      });
  return handlers;
}

} // namespace ida_agent::bridge
