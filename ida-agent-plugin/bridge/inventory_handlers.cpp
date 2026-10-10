#include "inventory_handlers.hpp"

#include "ida_executor.hpp"
#include "rpc/string_search_options.hpp"
#include "services/database_service.hpp"
#include "services/inventory_text.hpp"
#include "services/string_service.hpp"
#include "services/symbol_service.hpp"

#include <chrono>
#include <cmath>
#include <cstdint>
#include <optional>
#include <regex>
#include <stdexcept>
#include <string>
#include <string_view>

namespace ida_agent::bridge
{
namespace
{

Dispatcher::MethodResult Error(
    rpc::ErrorCode code,
    const char *message,
    bool retryable = false)
{
  return rpc::RpcError{code, message, retryable};
}

std::optional<std::uint32_t> ReadInteger(
    const nlohmann::json &params,
    std::string_view field,
    std::uint32_t default_value,
    std::uint32_t minimum,
    std::uint32_t maximum)
{
  if ( !params.contains(field) )
    return default_value;
  const nlohmann::json &value = params[std::string(field)];
  std::uint64_t parsed = 0;
  if ( value.is_number_unsigned() )
  {
    parsed = value.get<std::uint64_t>();
  }
  else if ( value.is_number_integer() )
  {
    const std::int64_t signed_value = value.get<std::int64_t>();
    if ( signed_value < 0 )
      return std::nullopt;
    parsed = static_cast<std::uint64_t>(signed_value);
  }
  else if ( value.is_number_float() )
  {
    const double float_value = value.get<double>();
    if ( !std::isfinite(float_value) || std::floor(float_value) != float_value
      || float_value < minimum || float_value > maximum )
    {
      return std::nullopt;
    }
    parsed = static_cast<std::uint64_t>(float_value);
  }
  else
  {
    return std::nullopt;
  }
  if ( parsed < minimum || parsed > maximum )
    return std::nullopt;
  return static_cast<std::uint32_t>(parsed);
}

bool ReadFilter(
    const nlohmann::json &params,
    std::string_view field,
    std::string *value)
{
  value->clear();
  if ( !params.contains(field) )
    return true;
  const nlohmann::json &encoded = params[std::string(field)];
  if ( !encoded.is_string() )
    return false;
  *value = encoded.get<std::string>();
  std::size_t characters = 0;
  return value->size() <= 1024
      && services::Utf8CodePointCount(*value, &characters)
      && characters <= 256;
}

bool ReadCursor(const nlohmann::json &params, std::optional<std::string> *cursor)
{
  cursor->reset();
  if ( !params.contains("cursor") )
    return true;
  if ( !params["cursor"].is_string() )
    return false;
  *cursor = params["cursor"].get<std::string>();
  return (*cursor)->size() <= 1024;
}

bool ReadEnum(
    const nlohmann::json &params,
    std::string_view field,
    std::initializer_list<std::string_view> allowed,
    std::string *value)
{
  value->clear();
  if ( !params.contains(field) )
    return true;
  const nlohmann::json &encoded = params[std::string(field)];
  if ( !encoded.is_string() )
    return false;
  *value = encoded.get<std::string>();
  for ( std::string_view candidate : allowed )
  {
    if ( *value == candidate )
      return true;
  }
  return false;
}

bool HasOnlyFields(
    const nlohmann::json &params,
    std::initializer_list<std::string_view> allowed)
{
  for ( auto field = params.begin(); field != params.end(); ++field )
  {
    bool matched = false;
    for ( std::string_view name : allowed )
      matched = matched || field.key() == name;
    if ( !matched )
      return false;
  }
  return true;
}

Dispatcher::MethodResult InventoryFailure(
    services::InventoryStatus status,
    const char *cursor_message,
    const char *limit_message)
{
  if ( status == services::InventoryStatus::InvalidCursor )
    return Error(rpc::ErrorCode::InvalidArgument, cursor_message);
  if ( status == services::InventoryStatus::OutputLimit )
    return Error(rpc::ErrorCode::OutputLimit, limit_message);
  throw std::runtime_error("inventory result is unavailable");
}

} // namespace

Dispatcher::MethodHandlers BuildInventoryHandlers(
    IdaExecutor &executor,
    const services::DatabaseService &database_service,
    const services::StringService &string_service,
    const services::SymbolService &symbol_service)
{
  Dispatcher::MethodHandlers handlers;
  handlers.emplace(
      "database.segments",
      [&executor, &database_service](const rpc::Request &request) -> Dispatcher::MethodResult
      {
        if ( !HasOnlyFields(request.params, {"name", "limit", "cursor"}) )
          return Error(rpc::ErrorCode::InvalidArgument, "database.segments contains an unknown parameter");
        std::string name;
        std::optional<std::string> cursor;
        const auto limit = ReadInteger(request.params, "limit", 20, 1, 100);
        if ( !ReadFilter(request.params, "name", &name) || !ReadCursor(request.params, &cursor)
          || !limit )
        {
          return Error(rpc::ErrorCode::InvalidArgument, "database.segments parameters are invalid");
        }
        try
        {
          const auto outcome = executor.ReadFor(
              std::chrono::milliseconds(request.timeout_ms),
              [&database_service, &name, &cursor, limit]()
              {
                return database_service.Segments(name, *limit, cursor);
              });
          if ( outcome.status != services::InventoryStatus::Success )
          {
            return InventoryFailure(
                outcome.status,
                "database.segments cursor is invalid",
                "database.segments continuation exceeds the configured limit");
          }
          if ( !outcome.result )
            throw std::runtime_error("database.segments did not return a result");
          return services::ToJson(*outcome.result);
        }
        catch ( const IdaTimeoutError & )
        {
          return Error(rpc::ErrorCode::Timeout, "IDA request timed out", true);
        }
        catch ( const IdaBusyError & )
        {
          return Error(rpc::ErrorCode::IdaBusy, "IDA is busy", true);
        }
      });
  handlers.emplace(
      "string.search",
      [&executor, &string_service](const rpc::Request &request) -> Dispatcher::MethodResult
      {
        if ( !HasOnlyFields(request.params, {"query", "minLength", "limit", "cursor", "refresh"}) )
          return Error(rpc::ErrorCode::InvalidArgument, "string.search contains an unknown parameter");
        std::string query;
        std::optional<std::string> cursor;
        const auto refresh = rpc::ReadStringSearchRefresh(request.params);
        const auto minimum_length = ReadInteger(request.params, "minLength", 4, 1, 4096);
        const auto limit = ReadInteger(request.params, "limit", 20, 1, 100);
        if ( !ReadFilter(request.params, "query", &query) || !ReadCursor(request.params, &cursor)
          || !minimum_length || !limit || !refresh )
        {
          return Error(rpc::ErrorCode::InvalidArgument, "string.search parameters are invalid");
        }
        try
        {
          const auto outcome = executor.ReadFor(
              std::chrono::milliseconds(request.timeout_ms),
              [&string_service, &query, &cursor, minimum_length, limit, refresh]()
              {
                return string_service.Search(query, *minimum_length, *limit, cursor, *refresh);
              });
          if ( outcome.status != services::InventoryStatus::Success )
          {
            return InventoryFailure(
                outcome.status,
                "string.search cursor is invalid",
                "string.search continuation exceeds the configured limit");
          }
          if ( !outcome.result )
            throw std::runtime_error("string.search did not return a result");
          return services::ToJson(*outcome.result);
        }
        catch ( const IdaTimeoutError & )
        {
          return Error(rpc::ErrorCode::Timeout, "IDA request timed out", true);
        }
        catch ( const IdaBusyError & )
        {
          return Error(rpc::ErrorCode::IdaBusy, "IDA is busy", true);
        }
      });
  handlers.emplace(
      "string.search_regex",
      [&executor, &string_service](const rpc::Request &request) -> Dispatcher::MethodResult
      {
        if ( !HasOnlyFields(request.params, {"pattern", "minLength", "limit", "cursor", "refresh"}) )
          return Error(rpc::ErrorCode::InvalidArgument, "string.search_regex contains an unknown parameter");
        std::string pattern;
        std::optional<std::string> cursor;
        const auto refresh = rpc::ReadStringSearchRefresh(request.params);
        const auto minimum_length = ReadInteger(request.params, "minLength", 4, 1, 4096);
        const auto limit = ReadInteger(request.params, "limit", 20, 1, 100);
        if ( !request.params.contains("pattern")
          || !ReadFilter(request.params, "pattern", &pattern)
          || !ReadCursor(request.params, &cursor) || !minimum_length || !limit || !refresh )
        {
          return Error(rpc::ErrorCode::InvalidArgument, "string.search_regex parameters are invalid");
        }
        try
        {
          const auto outcome = executor.ReadFor(
              std::chrono::milliseconds(request.timeout_ms),
              [&string_service, &pattern, &cursor, minimum_length, limit, refresh]()
              {
                return string_service.SearchRegex(pattern, *minimum_length, *limit, cursor, *refresh);
              });
          if ( outcome.status != services::InventoryStatus::Success )
          {
            return InventoryFailure(
                outcome.status,
                "string.search_regex cursor is invalid",
                "string.search_regex continuation exceeds the configured limit");
          }
          if ( !outcome.result )
            throw std::runtime_error("string.search_regex did not return a result");
          return services::ToJson(*outcome.result);
        }
        catch ( const std::regex_error & )
        {
          return Error(rpc::ErrorCode::InvalidArgument, "string.search_regex pattern is invalid");
        }
        catch ( const IdaTimeoutError & )
        {
          return Error(rpc::ErrorCode::Timeout, "IDA request timed out", true);
        }
        catch ( const IdaBusyError & )
        {
          return Error(rpc::ErrorCode::IdaBusy, "IDA is busy", true);
        }
      });
  handlers.emplace(
      "symbol.imports",
      [&executor, &symbol_service](const rpc::Request &request) -> Dispatcher::MethodResult
      {
        if ( !HasOnlyFields(request.params, {"module", "name", "limit", "cursor"}) )
          return Error(rpc::ErrorCode::InvalidArgument, "symbol.imports contains an unknown parameter");
        std::string module;
        std::string name;
        std::optional<std::string> cursor;
        const auto limit = ReadInteger(request.params, "limit", 20, 1, 100);
        if ( !ReadFilter(request.params, "module", &module)
          || !ReadFilter(request.params, "name", &name)
          || !ReadCursor(request.params, &cursor) || !limit )
        {
          return Error(rpc::ErrorCode::InvalidArgument, "symbol.imports parameters are invalid");
        }
        try
        {
          const auto outcome = executor.ReadFor(
              std::chrono::milliseconds(request.timeout_ms),
              [&symbol_service, &module, &name, &cursor, limit]()
              {
                return symbol_service.Imports(module, name, *limit, cursor);
              });
          if ( outcome.status != services::InventoryStatus::Success )
          {
            return InventoryFailure(
                outcome.status,
                "symbol.imports cursor is invalid",
                "symbol.imports continuation exceeds the configured limit");
          }
          if ( !outcome.result )
            throw std::runtime_error("symbol.imports did not return a result");
          return services::ToJson(*outcome.result);
        }
        catch ( const IdaTimeoutError & )
        {
          return Error(rpc::ErrorCode::Timeout, "IDA request timed out", true);
        }
        catch ( const IdaBusyError & )
        {
          return Error(rpc::ErrorCode::IdaBusy, "IDA is busy", true);
        }
      });
  handlers.emplace(
      "database.entry_points",
      [&executor, &database_service](const rpc::Request &request) -> Dispatcher::MethodResult
      {
        if ( !HasOnlyFields(request.params, {"name", "type", "limit", "cursor"}) )
          return Error(rpc::ErrorCode::InvalidArgument, "database.entry_points contains an unknown parameter");
        std::string name;
        std::string type;
        std::optional<std::string> cursor;
        const auto limit = ReadInteger(request.params, "limit", 20, 1, 100);
        if ( !ReadFilter(request.params, "name", &name)
          || !ReadEnum(request.params, "type", {"entry", "export"}, &type)
          || !ReadCursor(request.params, &cursor) || !limit )
        {
          return Error(rpc::ErrorCode::InvalidArgument, "database.entry_points parameters are invalid");
        }
        try
        {
          const auto outcome = executor.ReadFor(
              std::chrono::milliseconds(request.timeout_ms),
              [&database_service, &name, &type, &cursor, limit]()
              {
                return database_service.EntryPoints(name, type, *limit, cursor);
              });
          if ( outcome.status != services::InventoryStatus::Success )
          {
            return InventoryFailure(
                outcome.status,
                "database.entry_points cursor is invalid",
                "database.entry_points continuation exceeds the configured limit");
          }
          if ( !outcome.result )
            throw std::runtime_error("database.entry_points did not return a result");
          return services::ToJson(*outcome.result);
        }
        catch ( const IdaTimeoutError & )
        {
          return Error(rpc::ErrorCode::Timeout, "IDA request timed out", true);
        }
        catch ( const IdaBusyError & )
        {
          return Error(rpc::ErrorCode::IdaBusy, "IDA is busy", true);
        }
      });
  handlers.emplace(
      "symbol.exports",
      [&executor, &symbol_service](const rpc::Request &request) -> Dispatcher::MethodResult
      {
        if ( !HasOnlyFields(request.params, {"name", "limit", "cursor"}) )
          return Error(rpc::ErrorCode::InvalidArgument, "symbol.exports contains an unknown parameter");
        std::string name;
        std::optional<std::string> cursor;
        const auto limit = ReadInteger(request.params, "limit", 20, 1, 100);
        if ( !ReadFilter(request.params, "name", &name)
          || !ReadCursor(request.params, &cursor) || !limit )
        {
          return Error(rpc::ErrorCode::InvalidArgument, "symbol.exports parameters are invalid");
        }
        try
        {
          const auto outcome = executor.ReadFor(
              std::chrono::milliseconds(request.timeout_ms),
              [&symbol_service, &name, &cursor, limit]()
              {
                return symbol_service.Exports(name, *limit, cursor);
              });
          if ( outcome.status != services::InventoryStatus::Success )
          {
            return InventoryFailure(
                outcome.status,
                "symbol.exports cursor is invalid",
                "symbol.exports continuation exceeds the configured limit");
          }
          if ( !outcome.result )
            throw std::runtime_error("symbol.exports did not return a result");
          return services::ToJson(*outcome.result);
        }
        catch ( const IdaTimeoutError & )
        {
          return Error(rpc::ErrorCode::Timeout, "IDA request timed out", true);
        }
        catch ( const IdaBusyError & )
        {
          return Error(rpc::ErrorCode::IdaBusy, "IDA is busy", true);
        }
      });
  handlers.emplace(
      "symbol.search",
      [&executor, &symbol_service](const rpc::Request &request) -> Dispatcher::MethodResult
      {
        if ( !HasOnlyFields(request.params, {"name", "kind", "limit", "cursor"}) )
          return Error(rpc::ErrorCode::InvalidArgument, "symbol.search contains an unknown parameter");
        std::string name;
        std::string kind;
        std::optional<std::string> cursor;
        const auto limit = ReadInteger(request.params, "limit", 20, 1, 100);
        if ( !ReadFilter(request.params, "name", &name)
          || !ReadEnum(request.params, "kind", {"global", "data", "label"}, &kind)
          || !ReadCursor(request.params, &cursor) || !limit )
        {
          return Error(rpc::ErrorCode::InvalidArgument, "symbol.search parameters are invalid");
        }
        try
        {
          const auto outcome = executor.ReadFor(
              std::chrono::milliseconds(request.timeout_ms),
              [&symbol_service, &name, &kind, &cursor, limit]()
              {
                return symbol_service.Search(name, kind, *limit, cursor);
              });
          if ( outcome.status != services::InventoryStatus::Success )
          {
            return InventoryFailure(
                outcome.status,
                "symbol.search cursor is invalid",
                "symbol.search continuation exceeds the configured limit");
          }
          if ( !outcome.result )
            throw std::runtime_error("symbol.search did not return a result");
          return services::ToJson(*outcome.result);
        }
        catch ( const IdaTimeoutError & )
        {
          return Error(rpc::ErrorCode::Timeout, "IDA request timed out", true);
        }
        catch ( const IdaBusyError & )
        {
          return Error(rpc::ErrorCode::IdaBusy, "IDA is busy", true);
        }
      });
  return handlers;
}

} // namespace ida_agent::bridge
