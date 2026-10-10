#include "semantic_analysis_handlers.hpp"
#include "ida_executor.hpp"
#include "services/semantic_analysis/service.hpp"
#include "services/semantic_analysis/request.hpp"
#include <chrono>
#include <stdexcept>

namespace ida_agent::bridge
{
namespace
{
Dispatcher::MethodResult Convert(services::QueryResult result)
{
  using S = services::QueryStatus;
  using E = rpc::ErrorCode;
  switch (result.status)
  {
    case S::Success: return std::move(result.value);
    case S::CapabilityUnavailable: return rpc::RpcError{E::CapabilityUnavailable, "Hex-Rays is unavailable", false};
    case S::InvalidAddress: return rpc::RpcError{E::InvalidAddress, "call address is invalid", false};
    case S::InvalidArgument: return rpc::RpcError{E::InvalidArgument, "call mapping is ambiguous or argument is invalid", false};
    case S::NotFound: return rpc::RpcError{E::NotFound, "call was not recovered at the exact address", false};
    case S::OutputLimit: return rpc::RpcError{E::OutputLimit, "microcode extraction or output exceeded its budget", false};
    case S::Busy: return rpc::RpcError{E::IdaBusy, "Hex-Rays is busy", true};
    default: return rpc::RpcError{E::DecompileFailed, "microcode analysis failed", false};
  }
}
}
Dispatcher::MethodHandlers BuildSemanticAnalysisHandlers(IdaExecutor &executor, const services::SemanticAnalysisService &service)
{
  Dispatcher::MethodHandlers handlers;
  for (bool guards : {false, true})
    handlers.emplace(guards ? "analysis.guard_evidence" : "analysis.trace_argument",
        [&executor, &service, guards](const rpc::Request &request) -> Dispatcher::MethodResult {
      try
      {
        const auto params = services::semantic::ParseRequest(request.params);
        return Convert(executor.ReadFor(std::chrono::milliseconds(request.timeout_ms),
            [&service, params, guards]() { return service.AnalyzeArgument(params, guards); }));
      }
      catch (const std::invalid_argument &) { return rpc::RpcError{rpc::ErrorCode::InvalidArgument, "invalid argument analysis parameters", false}; }
      catch (const IdaTimeoutError &) { return rpc::RpcError{rpc::ErrorCode::Timeout, "IDA analysis request timed out", true}; }
      catch (const IdaBusyError &) { return rpc::RpcError{rpc::ErrorCode::IdaBusy, "IDA is busy", true}; }
    });
  handlers.emplace("analysis.trace_argument_callers", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    try
    {
      auto params = services::semantic::ParseCallersRequest(request.params);
      return Convert(executor.ReadFor(std::chrono::milliseconds(request.timeout_ms),
          [&service, params]() { return service.TraceArgumentCallers(params); }));
    }
    catch (const std::invalid_argument &) { return rpc::RpcError{rpc::ErrorCode::InvalidArgument, "invalid caller trace parameters", false}; }
    catch (const IdaTimeoutError &) { return rpc::RpcError{rpc::ErrorCode::Timeout, "IDA analysis request timed out", true}; }
    catch (const IdaBusyError &) { return rpc::RpcError{rpc::ErrorCode::IdaBusy, "IDA is busy", true}; }
  });
  return handlers;
}
}
