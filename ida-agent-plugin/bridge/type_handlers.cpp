#include "query_handler_support.hpp"
#include "type_handlers.hpp"

#include "ida_executor.hpp"
#include "rpc/address.hpp"
#include "services/inventory_text.hpp"
#include "services/type_service.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace ida_agent::bridge
{
namespace
{
constexpr std::size_t MaxTypeResultBytes = 500 * 1024;

Dispatcher::MethodResult Error(rpc::ErrorCode code, const char *message, bool retryable = false) { return rpc::RpcError{code, message, retryable}; }

bool Fields(const nlohmann::json &params, std::initializer_list<const char *> allowed)
{
  for ( auto field = params.begin(); field != params.end(); ++field )
  {
    bool found = false; for ( const char *name : allowed ) found = found || field.key() == name;
    if ( !found ) return false;
  }
  return true;
}

std::optional<std::uint32_t> Unsigned(const nlohmann::json &params, const char *name, std::uint32_t fallback, std::uint32_t minimum, std::uint32_t maximum)
{
  if ( !params.contains(name) ) return fallback;
  const auto &encoded = params[name];
  std::uint64_t value = 0;
  if ( encoded.is_number_unsigned() )
  {
    value = encoded.get<std::uint64_t>();
  }
  else if ( encoded.is_number_integer() )
  {
    const std::int64_t signed_value = encoded.get<std::int64_t>();
    if ( signed_value < 0 ) return std::nullopt;
    value = static_cast<std::uint64_t>(signed_value);
  }
  else
  {
    return std::nullopt;
  }
  if ( value < minimum || value > maximum ) return std::nullopt;
  return static_cast<std::uint32_t>(value);
}

bool Address(const nlohmann::json &params, std::uint64_t *address)
{
  if ( !params.contains("address") || !params["address"].is_string() ) return false;
  try { *address = rpc::ParseAddress(params["address"].get<std::string>()); return true; }
  catch ( const std::invalid_argument & ) { return false; }
}

bool Text(
    const nlohmann::json &params,
    const char *name,
    bool required,
    bool allow_empty,
    std::string *value)
{
  value->clear();
  if ( !params.contains(name) ) return !required;
  if ( !params[name].is_string() ) return false;
  *value = params[name].get<std::string>();
  std::size_t characters = 0;
  return (allow_empty || !value->empty()) && value->find('\0') == std::string::npos
      && value->size() <= 1024
      && services::Utf8CodePointCount(*value, &characters) && characters <= 256;
}

bool TypeKind(std::string_view kind)
{
  return kind.empty() || kind == "any" || kind == "typedef" || kind == "enum"
      || kind == "function" || kind == "pointer" || kind == "array"
      || kind == "udt" || kind == "struct" || kind == "union" || kind == "other";
}

template <typename Operation>
Dispatcher::MethodResult Run(IdaExecutor &executor, const rpc::Request &request, Operation operation)
{
  try
  {
    auto outcome = executor.ReadFor(std::chrono::milliseconds(request.timeout_ms), std::move(operation));
    switch ( outcome.status )
    {
      case services::TypeStatus::InvalidAddress: return Error(rpc::ErrorCode::InvalidAddress, "type address is invalid");
      case services::TypeStatus::InvalidArgument: return Error(rpc::ErrorCode::InvalidArgument, "type request is invalid");
      case services::TypeStatus::NotFound: return Error(rpc::ErrorCode::NotFound, "type information was not found");
      case services::TypeStatus::OutputLimit: return Error(rpc::ErrorCode::OutputLimit, "type output limit exceeded");
      case services::TypeStatus::Success: break;
    }
    if ( !outcome.result ) return Error(rpc::ErrorCode::InternalError, "type result is unavailable");
    nlohmann::json result = services::ToJson(*outcome.result);
    if ( result.dump().size() > MaxTypeResultBytes )
      return Error(rpc::ErrorCode::OutputLimit, "type output limit exceeded");
    return result;
  }
  catch ( const IdaTimeoutError & ) { return Error(rpc::ErrorCode::Timeout, "IDA request timed out", true); }
  catch ( const IdaBusyError & ) { return Error(rpc::ErrorCode::IdaBusy, "IDA is busy", true); }
}
}

Dispatcher::MethodHandlers BuildTypeHandlers(IdaExecutor &executor, const services::TypeService &service)
{
  Dispatcher::MethodHandlers handlers;
  const auto query_handler = [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult
  {
    if ( !Fields(request.params, {"name", "kind", "ordinal", "limit"}) )
      return Error(rpc::ErrorCode::InvalidArgument, "type query contains an unknown parameter");
    std::string name, kind;
    if ( !Text(request.params, "name", false, true, &name)
      || !Text(request.params, "kind", false, true, &kind) || !TypeKind(kind) )
      return Error(rpc::ErrorCode::InvalidArgument, "type query filter is invalid");
    const auto ordinal = Unsigned(request.params, "ordinal", 1, 1, 1000000), limit = Unsigned(request.params, "limit", 20, 1, 100);
    if ( kind.size() > 64 || !ordinal || !limit ) return Error(rpc::ErrorCode::InvalidArgument, "type query params are invalid");
    return Run(executor, request, [&service, name, kind, ordinal, limit]() { return service.Search(name, kind, *ordinal, *limit); });
  };
  handlers.emplace("type.search", query_handler);
  handlers.emplace("type.query", query_handler);
  handlers.emplace("type.get", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult
  {
    std::string name;
    if ( !Fields(request.params, {"name"}) || request.params.size() != 1
      || !Text(request.params, "name", true, false, &name) )
      return Error(rpc::ErrorCode::InvalidArgument, "type.get requires a valid name");
    return Run(executor, request, [&service, name]() { return service.Get(name); });
  });
  handlers.emplace("type.read_value", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult
  {
    if ( !Fields(request.params, {"address", "name", "maxBytes"}) )
      return Error(rpc::ErrorCode::InvalidArgument, "type.read_value contains an unknown parameter");
    std::uint64_t address = 0;
    std::string name;
    const auto max_bytes = Unsigned(request.params, "maxBytes", 4096, 1, 65536);
    if ( !Address(request.params, &address) || !Text(request.params, "name", true, false, &name) || !max_bytes )
      return Error(rpc::ErrorCode::InvalidArgument, "type.read_value params are invalid");
    return Run(executor, request, [&service, address, name, max_bytes]() { return service.ReadValue(address, name, *max_bytes); });
  });
  handlers.emplace("type.read_struct", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult
  {
    if ( !Fields(request.params, {"address", "name", "maxBytes"}) )
      return Error(rpc::ErrorCode::InvalidArgument, "type.read_struct contains an unknown parameter");
    std::uint64_t address = 0;
    std::string name;
    const auto max_bytes = Unsigned(request.params, "maxBytes", 4096, 1, 65536);
    if ( !Address(request.params, &address) || !Text(request.params, "name", false, true, &name) || !max_bytes )
      return Error(rpc::ErrorCode::InvalidArgument, "type.read_struct params are invalid");
    return Run(executor, request, [&service, address, name, max_bytes]() { return service.ReadStruct(address, name, *max_bytes); });
  });
  handlers.emplace("global.value", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult
  {
    if ( !Fields(request.params, {"address", "name", "maxBytes"}) )
      return Error(rpc::ErrorCode::InvalidArgument, "global.value contains an unknown parameter");
    const bool has_address = request.params.contains("address");
    const bool has_name = request.params.contains("name");
    if ( has_address == has_name )
      return Error(rpc::ErrorCode::InvalidArgument, "global.value requires exactly one of address or name");
    std::optional<std::uint64_t> address;
    std::optional<std::string> name;
    if ( has_address )
    {
      std::uint64_t parsed = 0;
      if ( !Address(request.params, &parsed) ) return Error(rpc::ErrorCode::InvalidArgument, "global.value address is invalid");
      address = parsed;
    }
    else
    {
      std::string parsed;
      if ( !Text(request.params, "name", true, false, &parsed) ) return Error(rpc::ErrorCode::InvalidArgument, "global.value name is invalid");
      name = std::move(parsed);
    }
    const auto max_bytes = Unsigned(request.params, "maxBytes", 4096, 1, 65536);
    if ( !max_bytes ) return Error(rpc::ErrorCode::InvalidArgument, "global.value maxBytes is invalid");
    return Run(executor, request, [&service, address, name, max_bytes]() { return service.GlobalValue(address, name, *max_bytes); });
  });
  handlers.emplace("function.stack_frame", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult
  {
    std::uint64_t address = 0; if ( !Fields(request.params, {"address"}) || request.params.size() != 1 || !Address(request.params, &address) ) return Error(rpc::ErrorCode::InvalidArgument, "function.stack_frame requires address");
    return Run(executor, request, [&service, address]() { return service.StackFrame(address); });
  });
  handlers.emplace("type.infer", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult
  {
    std::uint64_t address = 0; if ( !Fields(request.params, {"address"}) || request.params.size() != 1 || !Address(request.params, &address) ) return Error(rpc::ErrorCode::InvalidArgument, "type.infer requires address");
    return Run(executor, request, [&service, address]() { return service.Infer(address); });
  });
  handlers.emplace("xref.struct_field", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult
  {
    if ( !Fields(request.params, {"type", "field", "limit"}) || !request.params.contains("type") || !request.params["type"].is_string() || !request.params.contains("field") || !request.params["field"].is_string() ) return Error(rpc::ErrorCode::InvalidArgument, "xref.struct_field params are invalid");
    const std::string type = request.params["type"].get<std::string>(), field = request.params["field"].get<std::string>(); const auto limit = Unsigned(request.params, "limit", 100, 1, 1000);
    if ( type.empty() || field.empty() || type.size() > 1024 || field.size() > 1024 || !limit ) return Error(rpc::ErrorCode::InvalidArgument, "xref.struct_field params are invalid");
    return Run(executor, request, [&service, type, field, limit]() { return service.FieldXrefs(type, field, *limit); });
  });
  handlers.emplace("type.xrefs", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( !query::Fields(request.params, {"name", "limit", "cursor"}) ) return query::Error(rpc::ErrorCode::InvalidArgument, "type.xrefs parameters are invalid"); const auto name = query::Text(request.params, "name", true, 4096); const auto limit = query::Integer(request.params, "limit", 20, 1, 100); const auto cursor = query::Integer(request.params, "cursor", 0, 0, 1000000); if ( !name || !limit || !cursor ) return query::Error(rpc::ErrorCode::InvalidArgument, "type.xrefs parameters are invalid"); return query::Run(executor, request, [&service, name, limit, cursor]() { return service.TypeXrefs(*name, *limit, *cursor); });
  });
  return handlers;
}
} // namespace ida_agent::bridge
