#pragma once
#include "rpc/dispatcher.hpp"
#include "ida_executor.hpp"
#include "services/query_result.hpp"
#include <chrono>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>

namespace ida_agent::bridge::query
{
Dispatcher::MethodResult Error(rpc::ErrorCode code, const char *message, bool retryable = false);
bool Fields(const nlohmann::json &params, std::initializer_list<std::string_view> allowed);
std::optional<std::uint32_t> Integer(const nlohmann::json &params, const char *name, std::uint32_t default_value, std::uint32_t minimum, std::uint32_t maximum);
std::optional<std::uint64_t> Address(const nlohmann::json &params, const char *name, bool required);
std::optional<std::string> Text(const nlohmann::json &params, const char *name, bool required, std::size_t maximum);
Dispatcher::MethodResult Convert(services::QueryResult result);

template <typename Operation>
Dispatcher::MethodResult Run(IdaExecutor &executor, const rpc::Request &request, Operation operation)
{
  try
  {
    return Convert(executor.ReadFor(std::chrono::milliseconds(request.timeout_ms), std::move(operation)));
  }
  catch ( const IdaTimeoutError & ) { return Error(rpc::ErrorCode::Timeout, "IDA request timed out", true); }
  catch ( const IdaBusyError & ) { return Error(rpc::ErrorCode::IdaBusy, "IDA is busy", true); }
}
}
