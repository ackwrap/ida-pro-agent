#pragma once

#include <string>
#include <string_view>
#include <optional>

namespace ida_agent::rpc
{

enum class ErrorCode
{
  InvalidArgument,
  InvalidAddress,
  NotFound,
  CapabilityUnavailable,
  PermissionDenied,
  IdaBusy,
  DecompileFailed,
  Conflict,
  Timeout,
  OutputLimit,
  InternalError,
};

struct RpcError
{
  ErrorCode code;
  std::string message;
  bool retryable;
  std::optional<std::string> recovery_change_id;
};

ErrorCode ParseErrorCode(std::string_view encoded);
std::string_view ToString(ErrorCode code);
void ValidateError(const RpcError &error);

} // namespace ida_agent::rpc
