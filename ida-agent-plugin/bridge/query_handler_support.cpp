#include "query_handler_support.hpp"
#include "rpc/address.hpp"
#include <stdexcept>

namespace ida_agent::bridge::query
{
Dispatcher::MethodResult Error(rpc::ErrorCode code, const char *message, bool retryable)
{
  return rpc::RpcError{code, message, retryable};
}

bool Fields(const nlohmann::json &params, std::initializer_list<std::string_view> allowed)
{
  if ( !params.is_object() ) return false;
  for ( auto field = params.begin(); field != params.end(); ++field )
  {
    bool found = false;
    for ( std::string_view name : allowed ) found = found || field.key() == name;
    if ( !found ) return false;
  }
  return true;
}

std::optional<std::uint32_t> Integer(
    const nlohmann::json &params,
    const char *name,
    std::uint32_t default_value,
    std::uint32_t minimum,
    std::uint32_t maximum)
{
  if ( !params.contains(name) ) return default_value;
  const auto &value = params[name];
  std::uint64_t parsed = 0;
  if ( value.is_number_unsigned() ) parsed = value.get<std::uint64_t>();
  else if ( value.is_number_integer() && value.get<std::int64_t>() >= 0 )
    parsed = static_cast<std::uint64_t>(value.get<std::int64_t>());
  else return std::nullopt;
  if ( parsed < minimum || parsed > maximum ) return std::nullopt;
  return static_cast<std::uint32_t>(parsed);
}

std::optional<std::uint64_t> Address(const nlohmann::json &params, const char *name, bool required)
{
  if ( !params.contains(name) )
  {
    if ( required ) throw std::invalid_argument("address is required");
    return std::nullopt;
  }
  if ( !params[name].is_string() ) throw std::invalid_argument("address must be a string");
  return rpc::ParseAddress(params[name].get<std::string>());
}

std::optional<std::string> Text(const nlohmann::json &params, const char *name, bool required, std::size_t maximum)
{
  if ( !params.contains(name) )
  {
    if ( required ) return std::nullopt;
    return std::string{};
  }
  if ( !params[name].is_string() ) return std::nullopt;
  std::string value = params[name].get<std::string>();
  if ( value.empty() || value.size() > maximum || value.find('\0') != std::string::npos
    || !is_valid_utf8(value.c_str()) )
    return std::nullopt;
  return value;
}

Dispatcher::MethodResult Convert(services::QueryResult result)
{
  switch ( result.status )
  {
    case services::QueryStatus::Success: return std::move(result.value);
    case services::QueryStatus::InvalidAddress: return Error(rpc::ErrorCode::InvalidAddress, "IDA address is invalid");
    case services::QueryStatus::InvalidArgument: return Error(rpc::ErrorCode::InvalidArgument, "RPC parameters are invalid");
    case services::QueryStatus::NotFound: return Error(rpc::ErrorCode::NotFound, "requested IDA object was not found");
    case services::QueryStatus::CapabilityUnavailable: return Error(rpc::ErrorCode::CapabilityUnavailable, "required IDA capability is unavailable");
    case services::QueryStatus::Conflict: return Error(rpc::ErrorCode::Conflict, "required IDA runtime state is unavailable");
    case services::QueryStatus::Busy: return Error(rpc::ErrorCode::IdaBusy, "Hex-Rays is busy", true);
    case services::QueryStatus::DecompileFailed: return Error(rpc::ErrorCode::DecompileFailed, "decompilation failed");
    case services::QueryStatus::OutputLimit: return Error(rpc::ErrorCode::OutputLimit, "IDA output exceeds the configured limit");
  }
  throw std::runtime_error("Query status is unavailable");
}
}
