#include "error.hpp"

#include "validation.hpp"

#include <array>
#include <stdexcept>
#include <utility>

namespace ida_agent::rpc
{
namespace
{

constexpr std::array<std::pair<std::string_view, ErrorCode>, 11> error_codes =
{{
  {"INVALID_ARGUMENT", ErrorCode::InvalidArgument},
  {"INVALID_ADDRESS", ErrorCode::InvalidAddress},
  {"NOT_FOUND", ErrorCode::NotFound},
  {"CAPABILITY_UNAVAILABLE", ErrorCode::CapabilityUnavailable},
  {"PERMISSION_DENIED", ErrorCode::PermissionDenied},
  {"IDA_BUSY", ErrorCode::IdaBusy},
  {"DECOMPILE_FAILED", ErrorCode::DecompileFailed},
  {"CONFLICT", ErrorCode::Conflict},
  {"TIMEOUT", ErrorCode::Timeout},
  {"OUTPUT_LIMIT", ErrorCode::OutputLimit},
  {"INTERNAL_ERROR", ErrorCode::InternalError},
}};

} // namespace

ErrorCode ParseErrorCode(std::string_view encoded)
{
  for ( const auto &[name, code] : error_codes )
  {
    if ( name == encoded )
      return code;
  }
  throw std::invalid_argument("unknown RPC error code");
}

std::string_view ToString(ErrorCode code)
{
  for ( const auto &[name, candidate] : error_codes )
  {
    if ( candidate == code )
      return name;
  }
  throw std::invalid_argument("unknown RPC error code");
}

void ValidateError(const RpcError &error)
{
  static_cast<void>(ToString(error.code));
  const std::size_t message_length = Utf8CodePointCount(error.message);
  if ( message_length == 0 || message_length > 1024 )
    throw std::invalid_argument("error message must contain 1 to 1024 characters");
  if ( error.recovery_change_id )
  {
    if ( error.code != ErrorCode::InternalError || error.recovery_change_id->empty()
      || error.recovery_change_id->size() > 256 )
    {
      throw std::invalid_argument("recoveryChangeId is invalid");
    }
    for ( const unsigned char value : *error.recovery_change_id )
    {
      const bool valid = (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z')
          || (value >= '0' && value <= '9') || value == '.' || value == '_' || value == ':' || value == '-';
      if ( !valid ) throw std::invalid_argument("recoveryChangeId is invalid");
    }
  }
}

} // namespace ida_agent::rpc
