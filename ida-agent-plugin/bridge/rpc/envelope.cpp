#include "envelope.hpp"

#include "validation.hpp"

#include <limits>
#include <stdexcept>
#include <utility>

namespace ida_agent::rpc
{

Request ParseRequest(std::string_view encoded)
{
  const Json root = ParseRootObject(encoded);
  RequireExactFields(
      root,
      {"protocolVersion", "requestId", "sessionId", "method", "params", "timeoutMs"});

  Request request{
      ReadString(root, "protocolVersion"),
      ReadString(root, "requestId"),
      ReadString(root, "sessionId"),
      ReadString(root, "method"),
      ReadObject(root, "params"),
      0,
  };

  ValidateProtocolVersion(request.protocol_version);
  ValidateIdentifier(request.request_id, "requestId");
  ValidateIdentifier(request.session_id, "sessionId");
  ValidateMethod(request.method);

  const std::uint64_t timeout_ms = ReadUnsigned(root, "timeoutMs");
  if ( timeout_ms < MinTimeoutMs || timeout_ms > MaxTimeoutMs )
    throw std::invalid_argument("timeoutMs is out of range");
  request.timeout_ms = static_cast<std::uint32_t>(timeout_ms);
  return request;
}

RequestCorrelation ParseRequestCorrelation(std::string_view encoded)
{
  Json root;
  try
  {
    root = Json::parse(encoded.begin(), encoded.end());
  }
  catch ( const Json::exception &error )
  {
    throw std::invalid_argument(std::string("invalid JSON: ") + error.what());
  }
  if ( !root.is_object() )
    throw std::invalid_argument("message root must be an object");

  const std::string protocol_version = ReadString(root, "protocolVersion");
  RequestCorrelation correlation{
      ReadString(root, "requestId"),
      ReadString(root, "sessionId"),
  };
  ValidateProtocolVersion(protocol_version);
  ValidateIdentifier(correlation.request_id, "requestId");
  ValidateIdentifier(correlation.session_id, "sessionId");
  return correlation;
}

Response ParseResponse(std::string_view encoded)
{
  const Json root = ParseRootObject(encoded);
  RequireExactFields(
      root,
      {"protocolVersion", "requestId", "sessionId"},
      {"result", "error"});

  Response response{
      ReadString(root, "protocolVersion"),
      ReadString(root, "requestId"),
      ReadString(root, "sessionId"),
      std::nullopt,
      std::nullopt,
  };
  ValidateProtocolVersion(response.protocol_version);
  ValidateIdentifier(response.request_id, "requestId");
  ValidateIdentifier(response.session_id, "sessionId");

  const bool has_result = root.contains("result");
  const bool has_error = root.contains("error");
  if ( has_result == has_error )
    throw std::invalid_argument("response must contain exactly one of result or error");

  if ( has_result )
  {
    response.result = ReadObject(root, "result");
    return response;
  }

  const Json &error = ReadObject(root, "error");
  RequireExactFields(error, {"code", "message", "retryable"}, {"recoveryChangeId"});
  std::optional<std::string> recovery_change_id;
  if ( error.contains("recoveryChangeId") )
    recovery_change_id = ReadString(error, "recoveryChangeId");
  response.error = RpcError{
      ParseErrorCode(ReadString(error, "code")),
      ReadString(error, "message"),
      ReadBool(error, "retryable"),
      std::move(recovery_change_id),
  };
  ValidateError(*response.error);
  return response;
}

std::string SerializeResponse(const Response &response)
{
  ValidateProtocolVersion(response.protocol_version);
  ValidateIdentifier(response.request_id, "requestId");
  ValidateIdentifier(response.session_id, "sessionId");
  if ( response.result.has_value() == response.error.has_value() )
    throw std::invalid_argument("response must contain exactly one of result or error");

  Json encoded{
      {"protocolVersion", response.protocol_version},
      {"requestId", response.request_id},
      {"sessionId", response.session_id},
  };
  if ( response.result )
  {
    if ( !response.result->is_object() )
      throw std::invalid_argument("result must be an object");
    encoded["result"] = *response.result;
  }
  else
  {
    ValidateError(*response.error);
    encoded["error"] = {
        {"code", ToString(response.error->code)},
        {"message", response.error->message},
        {"retryable", response.error->retryable},
    };
    if ( response.error->recovery_change_id )
      encoded["error"]["recoveryChangeId"] = *response.error->recovery_change_id;
  }
  return encoded.dump();
}

} // namespace ida_agent::rpc
