#include "script_handlers.hpp"

#include "ida_executor.hpp"
#include "services/script_service.hpp"

#include <chrono>
#include <string>
#include <utility>

namespace ida_agent::bridge
{
namespace
{
Dispatcher::MethodResult Error(rpc::ErrorCode code, const char *message, bool retryable = false)
{
  return rpc::RpcError{code, message, retryable};
}

Dispatcher::MethodResult ScriptResult(services::ScriptExecutionOutcome outcome)
{
  switch ( outcome.status )
  {
    case services::ScriptStatus::Unavailable:
      return Error(rpc::ErrorCode::CapabilityUnavailable, "requested script language is unavailable");
    case services::ScriptStatus::InvalidArgument:
      return Error(rpc::ErrorCode::InvalidArgument, "script execution parameters are invalid");
    case services::ScriptStatus::Failed:
      return Error(rpc::ErrorCode::InternalError, "script runtime failed to return a result");
    case services::ScriptStatus::Success:
      break;
  }
  if ( !outcome.result )
    return Error(rpc::ErrorCode::InternalError, "script result is unavailable");
  return services::ToJson(*outcome.result);
}
} // namespace

Dispatcher::MethodHandlers BuildScriptHandlers(
    IdaExecutor &executor,
    const services::ScriptService &service)
{
  Dispatcher::MethodHandlers handlers;
  handlers.emplace(
      "script.execute",
      [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult
      {
        if ( !request.params.is_object() || request.params.size() != 2
          || !request.params.contains("language") || !request.params["language"].is_string()
          || !request.params.contains("code") || !request.params["code"].is_string() )
          return Error(rpc::ErrorCode::InvalidArgument, "script.execute params are invalid");
        const std::string language = request.params["language"].get<std::string>();
        const std::string code = request.params["code"].get<std::string>();
        if ( (language != "python" && language != "idc") || code.empty() || code.size() > 32 * 1024
          || code.find('\0') != std::string::npos || !is_valid_utf8(code.c_str()) )
          return Error(rpc::ErrorCode::InvalidArgument, "script.execute params are invalid");
        try
        {
          return executor.WriteFor(
              std::chrono::milliseconds(request.timeout_ms),
              [&service, language, code]() { return ScriptResult(service.Execute(language, code)); });
        }
        catch ( const IdaTimeoutError & )
        {
          return Error(rpc::ErrorCode::Timeout, "script request timed out before execution", true);
        }
        catch ( const IdaBusyError & )
        {
          return Error(rpc::ErrorCode::IdaBusy, "IDA is busy", true);
        }
      });
  return handlers;
}
} // namespace ida_agent::bridge
