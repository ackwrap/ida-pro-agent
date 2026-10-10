#include "query_handler_support.hpp"
#include "debugger_handlers.hpp"

#include "ida_executor.hpp"
#include "rpc/address.hpp"
#include "services/debugger_service.hpp"

#include <chrono>
#include <exception>
#include <limits>
#include <optional>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace ida_agent::bridge
{
namespace
{
constexpr std::size_t MaxDebuggerResultBytes = 500 * 1024;

Dispatcher::MethodResult Error(rpc::ErrorCode code, const char *message, bool retryable = false)
{
  return rpc::RpcError{code, message, retryable};
}

bool Fields(const nlohmann::json &params, std::initializer_list<const char *> allowed)
{
  if ( !params.is_object() )
    return false;
  for ( auto field = params.begin(); field != params.end(); ++field )
  {
    bool found = false;
    for ( const char *name : allowed )
      found = found || field.key() == name;
    if ( !found )
      return false;
  }
  return true;
}

bool Address(const nlohmann::json &params, std::uint64_t *address)
{
  if ( !params.contains("address") || !params["address"].is_string() )
    return false;
  try
  {
    *address = rpc::ParseAddress(params["address"].get<std::string>());
    return true;
  }
  catch ( const std::exception & )
  {
    return false;
  }
}

bool Int64(const nlohmann::json &value, std::int64_t *result)
{
  if ( value.is_number_integer() )
  {
    *result = value.get<std::int64_t>();
    return true;
  }
  if ( value.is_number_unsigned() )
  {
    const std::uint64_t unsigned_value = value.get<std::uint64_t>();
    if ( unsigned_value <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) )
    {
      *result = static_cast<std::int64_t>(unsigned_value);
      return true;
    }
  }
  return false;
}

bool Uint32(const nlohmann::json &value, std::uint32_t *result)
{
  if ( !value.is_number_unsigned() )
    return false;
  const std::uint64_t unsigned_value = value.get<std::uint64_t>();
  if ( unsigned_value > std::numeric_limits<std::uint32_t>::max() )
    return false;
  *result = static_cast<std::uint32_t>(unsigned_value);
  return true;
}

template <typename Outcome>
Dispatcher::MethodResult Result(Outcome outcome)
{
  switch ( outcome.status )
  {
    case services::DebuggerStatus::Unavailable:
      return Error(rpc::ErrorCode::CapabilityUnavailable, "debugger is unavailable");
    case services::DebuggerStatus::AlreadyRunning:
      return Error(rpc::ErrorCode::Conflict, "debugger is already running");
    case services::DebuggerStatus::NotRunning:
      return Error(rpc::ErrorCode::Conflict, "debugger is not running");
    case services::DebuggerStatus::NotSuspended:
      return Error(rpc::ErrorCode::Conflict, "debugger is not suspended");
    case services::DebuggerStatus::InvalidAddress:
      return Error(rpc::ErrorCode::InvalidAddress, "debugger address is invalid");
    case services::DebuggerStatus::InvalidArgument:
      return Error(rpc::ErrorCode::InvalidArgument, "debugger request is invalid");
    case services::DebuggerStatus::NotFound:
      return Error(rpc::ErrorCode::NotFound, "debugger object was not found");
    case services::DebuggerStatus::Failed:
      return Error(rpc::ErrorCode::InternalError, "debugger rejected the request");
    case services::DebuggerStatus::StateUncertain:
      return Error(rpc::ErrorCode::InternalError, "debugger state may have changed");
    case services::DebuggerStatus::OutputLimit:
      return Error(rpc::ErrorCode::OutputLimit, "debugger output limit exceeded");
    case services::DebuggerStatus::Success:
      break;
  }
  if ( !outcome.result )
    return Error(rpc::ErrorCode::InternalError, "debugger result is unavailable");
  nlohmann::json result = services::ToJson(*outcome.result);
  if ( result.dump().size() > MaxDebuggerResultBytes )
    return Error(rpc::ErrorCode::OutputLimit, "debugger output limit exceeded");
  return result;
}

template <typename Operation>
Dispatcher::MethodResult DebuggerCommand(IdaExecutor &executor, const rpc::Request &request, Operation operation)
{
  try { return executor.DebuggerFor(std::chrono::milliseconds(request.timeout_ms), std::move(operation)); }
  catch ( const IdaTimeoutError & ) { return Error(rpc::ErrorCode::Timeout, "debugger request timed out before execution", true); }
  catch ( const IdaBusyError & ) { return Error(rpc::ErrorCode::IdaBusy, "IDA is busy", true); }
}

template <typename Operation>
Dispatcher::MethodResult Read(IdaExecutor &executor, const rpc::Request &request, Operation operation)
{
  try
  {
    return executor.ReadFor(std::chrono::milliseconds(request.timeout_ms), std::move(operation));
  }
  catch ( const IdaTimeoutError & )
  {
    return Error(rpc::ErrorCode::Timeout, "debugger request timed out", true);
  }
  catch ( const IdaBusyError & )
  {
    return Error(rpc::ErrorCode::IdaBusy, "IDA is busy", true);
  }
}

template <typename Operation>
Dispatcher::MethodResult Write(IdaExecutor &executor, const rpc::Request &request, Operation operation)
{
  try
  {
    return executor.WriteFor(std::chrono::milliseconds(request.timeout_ms), std::move(operation));
  }
  catch ( const IdaTimeoutError & )
  {
    return Error(rpc::ErrorCode::Timeout, "debugger request timed out", true);
  }
  catch ( const IdaBusyError & )
  {
    return Error(rpc::ErrorCode::IdaBusy, "IDA is busy", true);
  }
}

std::optional<services::BreakpointMutation> ParseBreakpointMutation(const nlohmann::json &params)
{
  services::BreakpointMutation mutation;
  if ( params.contains("enabled") )
  {
    if ( !params["enabled"].is_boolean() )
      return std::nullopt;
    mutation.enabled = params["enabled"].get<bool>();
  }
  if ( params.contains("condition") )
  {
    if ( params["condition"].is_null() )
      mutation.condition = std::string{};
    else if ( params["condition"].is_string() )
    {
      mutation.condition = params["condition"].get<std::string>();
      if ( mutation.condition->size() > 4096
        || mutation.condition->find('\0') != std::string::npos
        || !is_valid_utf8(mutation.condition->c_str()) )
        return std::nullopt;
    }
    else
      return std::nullopt;
  }
  if ( params.contains("type") )
  {
    if ( !params["type"].is_string() )
      return std::nullopt;
    mutation.type = params["type"].get<std::string>();
    if ( *mutation.type != "software" && *mutation.type != "hardware" )
      return std::nullopt;
  }
  if ( params.contains("size") )
  {
    std::uint32_t size = 0;
    if ( !Uint32(params["size"], &size) || size > 8 )
      return std::nullopt;
    mutation.size = size;
  }
  if ( params.contains("language") )
  {
    if ( !params["language"].is_string() )
      return std::nullopt;
    mutation.language = params["language"].get<std::string>();
    if ( mutation.language->empty() || mutation.language->size() > 128
      || mutation.language->find('\0') != std::string::npos
      || !is_valid_utf8(mutation.language->c_str()) )
      return std::nullopt;
  }
  if ( params.contains("lowLevel") )
  {
    if ( !params["lowLevel"].is_boolean() )
      return std::nullopt;
    mutation.low_level = params["lowLevel"].get<bool>();
  }
  if ( params.contains("passCount") )
  {
    std::uint32_t pass_count = 0;
    if ( !Uint32(params["passCount"], &pass_count)
      || pass_count > static_cast<std::uint32_t>(std::numeric_limits<int>::max()) )
      return std::nullopt;
    mutation.pass_count = pass_count;
  }
  return mutation;
}

std::optional<services::RegisterRequest> ParseRegisterRequest(const nlohmann::json &params)
{
  if ( !Fields(params, {"threadMode", "threadIds", "registerMode", "names"}) )
    return std::nullopt;
  services::RegisterRequest result;
  result.thread_mode = params.contains("threadIds") ? "specified" : "current";
  result.register_mode = params.contains("names") ? "named" : "all";

  if ( params.contains("threadMode") )
  {
    if ( !params["threadMode"].is_string() )
      return std::nullopt;
    result.thread_mode = params["threadMode"].get<std::string>();
    if ( result.thread_mode != "current" && result.thread_mode != "specified" && result.thread_mode != "all" )
      return std::nullopt;
  }
  if ( params.contains("registerMode") )
  {
    if ( !params["registerMode"].is_string() )
      return std::nullopt;
    result.register_mode = params["registerMode"].get<std::string>();
    if ( result.register_mode != "all" && result.register_mode != "named" && result.register_mode != "general-purpose" )
      return std::nullopt;
  }

  if ( params.contains("threadIds") )
  {
    const auto &thread_ids = params["threadIds"];
    if ( !thread_ids.is_array() || thread_ids.empty() || thread_ids.size() > 256 )
      return std::nullopt;
    std::unordered_set<std::int64_t> unique;
    for ( const auto &value : thread_ids )
    {
      std::int64_t thread_id = 0;
      if ( !Int64(value, &thread_id) || thread_id <= 0 || !unique.insert(thread_id).second )
        return std::nullopt;
      result.thread_ids.push_back(thread_id);
    }
  }

  if ( params.contains("names") )
  {
    const auto &names = params["names"];
    if ( !names.is_array() || names.empty() || names.size() > 256 )
      return std::nullopt;
    std::unordered_set<std::string> unique;
    for ( const auto &value : names )
    {
      if ( !value.is_string() )
        return std::nullopt;
      std::string name = value.get<std::string>();
      if ( name.empty() || name.size() > 128 || !unique.insert(name).second )
        return std::nullopt;
      result.names.push_back(std::move(name));
    }
  }

  if ( (result.thread_mode == "specified") != !result.thread_ids.empty()
    || (result.register_mode == "named") != !result.names.empty() )
    return std::nullopt;
  return result;
}
} // namespace

Dispatcher::MethodHandlers BuildDebuggerHandlers(IdaExecutor &executor, const services::DebuggerService &service)
{
  Dispatcher::MethodHandlers handlers;
  handlers.emplace("debugger.backends", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( !request.params.is_object() || !request.params.empty() )
      return Error(rpc::ErrorCode::InvalidArgument, "debugger.backends params must be empty");
    return DebuggerCommand(executor, request, [&service]() { return Result(service.Backends()); });
  });
  handlers.emplace("debugger.configuration", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( !request.params.is_object() || !request.params.empty() )
      return Error(rpc::ErrorCode::InvalidArgument, "debugger.configuration params must be empty");
    return DebuggerCommand(executor, request, [&service]() { return Result(service.Configuration()); });
  });
  handlers.emplace("debugger.detach", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( !request.params.is_object() || !request.params.empty() )
      return Error(rpc::ErrorCode::InvalidArgument, "debugger.detach params must be empty");
    return DebuggerCommand(executor, request, [&service]() { return Result(service.Detach()); });
  });
  handlers.emplace("debugger.suspend", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( !request.params.is_object() || !request.params.empty() )
      return Error(rpc::ErrorCode::InvalidArgument, "debugger.suspend params must be empty");
    return DebuggerCommand(executor, request, [&service]() { return Result(service.Suspend()); });
  });
  handlers.emplace("debugger.select", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    const auto params = services::ParseDebuggerSelect(request.params);
    if ( !params ) return Error(rpc::ErrorCode::InvalidArgument, "debugger.select params are invalid");
    return DebuggerCommand(executor, request, [&service, params]() { return Result(service.Select(*params)); });
  });
  handlers.emplace("debugger.configure", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    const auto params = services::ParseDebuggerConfigure(request.params);
    if ( !params ) return Error(rpc::ErrorCode::InvalidArgument, "debugger.configure params are invalid");
    return DebuggerCommand(executor, request, [&service, params]() { return Result(service.Configure(*params)); });
  });
  handlers.emplace("debugger.processes", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    const auto params = services::ParseDebuggerProcesses(request.params);
    if ( !params ) return Error(rpc::ErrorCode::InvalidArgument, "debugger.processes params are invalid");
    return DebuggerCommand(executor, request, [&service, params]() { return Result(service.Processes(*params)); });
  });
  handlers.emplace("debugger.attach", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    const auto params = services::ParseDebuggerAttach(request.params);
    if ( !params ) return Error(rpc::ErrorCode::InvalidArgument, "debugger.attach params are invalid");
    return DebuggerCommand(executor, request, [&service, params]() { return Result(service.Attach(*params)); });
  });

  handlers.emplace("debugger.info", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( !request.params.is_object() || !request.params.empty() )
      return Error(rpc::ErrorCode::InvalidArgument, "debugger.info params must be empty");
    return DebuggerCommand(executor, request, [&service]() { return Result(service.Info()); });
  });
  handlers.emplace("debugger.start", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( !request.params.is_object() || !request.params.empty() )
      return Error(rpc::ErrorCode::InvalidArgument, "debugger.start params must be empty");
    return Write(executor, request, [&service]() { return Result(service.Start()); });
  });
  handlers.emplace("debugger.exit", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( !request.params.is_object() || !request.params.empty() )
      return Error(rpc::ErrorCode::InvalidArgument, "debugger.exit params must be empty");
    return DebuggerCommand(executor, request, [&service]() { return Result(service.Exit()); });
  });
  handlers.emplace("debugger.control", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( !Fields(request.params, {"action", "address"})
      || !request.params.contains("action")
      || !request.params["action"].is_string() )
      return Error(rpc::ErrorCode::InvalidArgument, "debugger.control params are invalid");
    const std::string action = request.params["action"].get<std::string>();
    std::optional<std::uint64_t> address;
    if ( request.params.contains("address") )
    {
      std::uint64_t value = 0;
      if ( !Address(request.params, &value) )
        return Error(rpc::ErrorCode::InvalidAddress, "debugger control address is invalid");
      address = value;
    }
    if ( (action == "run_to") != address.has_value() )
      return Error(rpc::ErrorCode::InvalidArgument, "debugger.control action and address are inconsistent");
    return Write(executor, request, [&service, action, address]() {
      return Result(service.Control(action, address));
    });
  });
  handlers.emplace("debugger.breakpoints", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( request.params.is_object() && request.params.empty() )
      return Read(executor, request, [&service]() { return Result(service.Breakpoints()); });
    if ( !Fields(request.params, {"action", "address", "enabled", "condition", "type", "size", "language", "lowLevel", "passCount"})
      || !request.params.contains("action")
      || !request.params["action"].is_string() )
      return Error(rpc::ErrorCode::InvalidArgument, "debugger.breakpoints params are invalid");
    const std::string action = request.params["action"].get<std::string>();
    if ( action != "add" && action != "delete" && action != "toggle" && action != "condition" )
      return Error(rpc::ErrorCode::InvalidArgument, "breakpoint action is invalid");
    std::uint64_t address = 0;
    if ( !Address(request.params, &address) )
      return Error(rpc::ErrorCode::InvalidAddress, "breakpoint address is invalid");
    const auto mutation = ParseBreakpointMutation(request.params);
    if ( !mutation )
      return Error(rpc::ErrorCode::InvalidArgument, "breakpoint mutation is invalid");
    return Write(executor, request, [&service, action, address, mutation]() {
      return Result(service.Breakpoint(action, address, *mutation));
    });
  });
  handlers.emplace("debugger.registers", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    const auto register_request = ParseRegisterRequest(request.params);
    if ( !register_request )
      return Error(rpc::ErrorCode::InvalidArgument, "debugger.registers params are invalid");
    return Read(executor, request, [&service, register_request]() {
      return Result(service.Registers(*register_request));
    });
  });
  handlers.emplace("debugger.stacktrace", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( !Fields(request.params, {"threadId", "limit"}) )
      return Error(rpc::ErrorCode::InvalidArgument, "debugger.stacktrace params are invalid");
    std::optional<std::int64_t> thread;
    std::uint32_t limit = 100;
    if ( request.params.contains("threadId") )
    {
      std::int64_t value = 0;
      if ( !Int64(request.params["threadId"], &value) || value <= 0 )
        return Error(rpc::ErrorCode::InvalidArgument, "threadId is invalid");
      thread = value;
    }
    if ( request.params.contains("limit")
      && (!Uint32(request.params["limit"], &limit) || limit == 0 || limit > 1000) )
      return Error(rpc::ErrorCode::InvalidArgument, "stacktrace limit is invalid");
    return Read(executor, request, [&service, thread, limit]() {
      return Result(service.StackTrace(thread, limit));
    });
  });
  handlers.emplace("debugger.memory_read", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    std::uint64_t address = 0;
    std::uint32_t length = 0;
    if ( !Fields(request.params, {"address", "length"})
      || !Address(request.params, &address)
      || !request.params.contains("length")
      || !Uint32(request.params["length"], &length)
      || length == 0
      || length > 65536 )
      return Error(rpc::ErrorCode::InvalidArgument, "debugger.memory_read params are invalid");
    return Read(executor, request, [&service, address, length]() {
      return Result(service.ReadMemory(address, length));
    });
  });
  handlers.emplace("debugger.memory_write", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    std::uint64_t address = 0;
    if ( !Fields(request.params, {"address", "bytes"})
      || !Address(request.params, &address)
      || !request.params.contains("bytes")
      || !request.params["bytes"].is_string() )
      return Error(rpc::ErrorCode::InvalidArgument, "debugger.memory_write params are invalid");
    const std::string bytes = request.params["bytes"].get<std::string>();
    return Write(executor, request, [&service, address, bytes]() {
      return Result(service.WriteMemory(address, bytes));
    });
  });
  handlers.emplace("debugger.threads", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( !query::Fields(request.params, {"limit", "cursor"}) ) return query::Error(rpc::ErrorCode::InvalidArgument, "debugger.threads parameters are invalid"); const auto limit = query::Integer(request.params, "limit", 20, 1, 100); const auto cursor = query::Integer(request.params, "cursor", 0, 0, 1024); if ( !limit || !cursor ) return query::Error(rpc::ErrorCode::InvalidArgument, "debugger.threads parameters are invalid"); return query::Run(executor, request, [&service, limit, cursor]() { return service.DebuggerThreads(*limit, *cursor); });
  });
  handlers.emplace("debugger.modules", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( !query::Fields(request.params, {"limit", "cursor"}) ) return query::Error(rpc::ErrorCode::InvalidArgument, "debugger.modules parameters are invalid"); const auto limit = query::Integer(request.params, "limit", 20, 1, 100); const auto cursor = query::Integer(request.params, "cursor", 0, 0, 4096); if ( !limit || !cursor ) return query::Error(rpc::ErrorCode::InvalidArgument, "debugger.modules parameters are invalid"); return query::Run(executor, request, [&service, limit, cursor]() { return service.DebuggerModules(*limit, *cursor); });
  });
  return handlers;
}
} // namespace ida_agent::bridge
