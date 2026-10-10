#include "dispatcher.hpp"

#include <string>
#include <utility>

namespace ida_agent::bridge
{
namespace
{

rpc::Response ErrorResponse(
    const rpc::Request &request,
    rpc::ErrorCode code,
    std::string message,
    bool retryable = false)
{
  return rpc::Response{
      std::string(rpc::ProtocolVersion),
      request.request_id,
      request.session_id,
      std::nullopt,
      rpc::RpcError{code, std::move(message), retryable},
  };
}

} // namespace

Dispatcher::Dispatcher(std::string session_id, MethodHandlers handlers)
    : session_id_(std::move(session_id)), handlers_(std::move(handlers))
{
}

rpc::Response Dispatcher::Dispatch(const rpc::Request &request) const
{
  if ( request.session_id != session_id_ )
  {
    return ErrorResponse(
        request,
        rpc::ErrorCode::PermissionDenied,
        "request session does not match this IDA instance");
  }
  if ( request.method == "system.ping" )
  {
    if ( !request.params.empty() )
    {
      return ErrorResponse(
          request,
          rpc::ErrorCode::InvalidArgument,
          "system.ping params must be empty");
    }
    return rpc::Response{
        std::string(rpc::ProtocolVersion),
        request.request_id,
        request.session_id,
        nlohmann::json{{"status", "ok"}},
        std::nullopt,
    };
  }

  const auto handler = handlers_.find(request.method);
  if ( handler != handlers_.end() )
  {
    MethodResult outcome = handler->second(request);
    if ( const auto *error = std::get_if<rpc::RpcError>(&outcome) )
    {
      return ErrorResponse(
          request,
          error->code,
          error->message,
          error->retryable);
    }
    return rpc::Response{
        std::string(rpc::ProtocolVersion),
        request.request_id,
        request.session_id,
        std::move(std::get<nlohmann::json>(outcome)),
        std::nullopt,
    };
  }

  return ErrorResponse(request, rpc::ErrorCode::NotFound, "RPC method was not found");
}

} // namespace ida_agent::bridge
