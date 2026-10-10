#include "read_handlers.hpp"

#include "function_analysis_handlers.hpp"
#include "composite_handlers.hpp"
#include "function_graph_handlers.hpp"
#include "ida_executor.hpp"
#include "inventory_handlers.hpp"
#include "search_handlers.hpp"
#include "type_handlers.hpp"
#include "rpc/address.hpp"
#include "services/database_service.hpp"
#include "services/decompiler_service.hpp"
#include "services/function_service.hpp"
#include "services/memory_service.hpp"
#include "services/search_service.hpp"
#include "services/string_service.hpp"
#include "services/symbol_service.hpp"
#include "services/type_service.hpp"
#include "services/xref_service.hpp"

#include <cmath>
#include <chrono>
#include <cstdint>
#include <optional>
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

std::optional<std::uint32_t> ReadLimit(const nlohmann::json &params)
{
  if ( !params.contains("limit") )
    return 20;
  const nlohmann::json &value = params["limit"];
  std::int64_t limit = 0;
  if ( value.is_number_unsigned() )
  {
    const std::uint64_t unsigned_limit = value.get<std::uint64_t>();
    if ( unsigned_limit > 100 )
      return std::nullopt;
    limit = static_cast<std::int64_t>(unsigned_limit);
  }
  else if ( value.is_number_integer() )
  {
    limit = value.get<std::int64_t>();
  }
  else if ( value.is_number_float() )
  {
    const double float_limit = value.get<double>();
    if ( !std::isfinite(float_limit) || std::floor(float_limit) != float_limit
      || float_limit < 1.0 || float_limit > 100.0 )
    {
      return std::nullopt;
    }
    limit = static_cast<std::int64_t>(float_limit);
  }
  else
  {
    return std::nullopt;
  }
  if ( limit < 1 || limit > 100 )
    return std::nullopt;
  return static_cast<std::uint32_t>(limit);
}

std::optional<std::uint32_t> ReadBoundedInteger(
    const nlohmann::json &value,
    std::uint32_t minimum,
    std::uint32_t maximum)
{
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

std::size_t Utf8Length(std::string_view value)
{
  std::size_t length = 0;
  for ( unsigned char character : value )
  {
    if ( (character & 0xC0) != 0x80 )
      ++length;
  }
  return length;
}

} // namespace

Dispatcher::MethodHandlers BuildReadHandlers(
    IdaExecutor &executor,
    const services::DatabaseService &database_service,
    const services::FunctionService &function_service,
    const services::XrefService &xref_service,
    const services::MemoryService &memory_service,
    const services::DecompilerService &decompiler_service,
    const services::SearchService &search_service,
    const services::StringService &string_service,
    const services::SymbolService &symbol_service,
    const services::TypeService &type_service)
{
  Dispatcher::MethodHandlers handlers;
  auto inventory_handlers = BuildInventoryHandlers(
      executor, database_service, string_service, symbol_service);
  handlers.merge(inventory_handlers);
  auto function_analysis_handlers = BuildFunctionAnalysisHandlers(executor, function_service);
  handlers.merge(function_analysis_handlers);
  auto function_graph_handlers = BuildFunctionGraphHandlers(executor, function_service);
  handlers.merge(function_graph_handlers);
  auto search_handlers = BuildSearchHandlers(executor, search_service);
  handlers.merge(search_handlers);
  auto type_handlers = BuildTypeHandlers(executor, type_service);
  handlers.merge(type_handlers);
  auto composite_handlers = BuildCompositeHandlers(
      executor,
      database_service,
      decompiler_service,
      function_service,
      string_service,
      symbol_service,
      xref_service);
  handlers.merge(composite_handlers);
  handlers.emplace(
      "database.info",
      [&executor, &database_service](const rpc::Request &request)
          -> Dispatcher::MethodResult
      {
        if ( !request.params.empty() )
          return Error(rpc::ErrorCode::InvalidArgument, "database.info params must be empty");
        try
        {
          return services::ToJson(executor.ReadFor(
              std::chrono::milliseconds(request.timeout_ms),
              [&database_service]() { return database_service.Info(); }));
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
      "function.get",
      [&executor, &function_service](const rpc::Request &request)
          -> Dispatcher::MethodResult
      {
        if ( request.params.size() != 1 || !request.params.contains("address")
          || !request.params["address"].is_string() )
        {
          return Error(
              rpc::ErrorCode::InvalidArgument,
              "function.get params must contain only a string address");
        }

        std::uint64_t address = 0;
        try
        {
          address = rpc::ParseAddress(request.params["address"].get<std::string>());
        }
        catch ( const std::invalid_argument & )
        {
          return Error(rpc::ErrorCode::InvalidAddress, "function address is invalid");
        }

        try
        {
          const services::FunctionLookup lookup = executor.ReadFor(
              std::chrono::milliseconds(request.timeout_ms),
              [&function_service, address]() { return function_service.Get(address); });
          if ( lookup.status == services::FunctionLookupStatus::InvalidAddress )
            return Error(rpc::ErrorCode::InvalidAddress, "function address is not mapped");
          if ( lookup.status == services::FunctionLookupStatus::NotFound )
            return Error(rpc::ErrorCode::NotFound, "function was not found at the address");
          if ( lookup.status == services::FunctionLookupStatus::OutputLimit )
          {
            return Error(
                rpc::ErrorCode::OutputLimit,
                "function analysis exceeds the configured limit");
          }
          if ( !lookup.info )
            throw std::runtime_error("function lookup did not return a result");
          return services::ToJson(*lookup.info);
        }
        catch ( const IdaTimeoutError & )
        {
          return Error(rpc::ErrorCode::Timeout, "IDA request timed out", true);
        }
        catch ( const IdaBusyError & )
        {
          return Error(rpc::ErrorCode::IdaBusy, "IDA is busy", true);
        }
        catch ( const std::range_error & )
        {
          return Error(
              rpc::ErrorCode::OutputLimit,
              "function statistics exceed the output limit");
        }
      });
  handlers.emplace(
      "function.search",
      [&executor, &function_service](const rpc::Request &request)
          -> Dispatcher::MethodResult
      {
        for ( auto field = request.params.begin(); field != request.params.end(); ++field )
        {
          if ( field.key() != "name" && field.key() != "address"
            && field.key() != "limit" && field.key() != "cursor" )
          {
            return Error(
                rpc::ErrorCode::InvalidArgument,
                "function.search contains an unknown parameter");
          }
        }
        const bool has_name = request.params.contains("name");
        const bool has_address = request.params.contains("address");
        const std::optional<std::uint32_t> limit = ReadLimit(request.params);
        if ( has_name == has_address || !limit )
        {
          return Error(
              rpc::ErrorCode::InvalidArgument,
              "function.search requires one filter and a limit from 1 to 100");
        }

        std::optional<std::string> cursor;
        if ( request.params.contains("cursor") )
        {
          if ( !request.params["cursor"].is_string() )
            return Error(rpc::ErrorCode::InvalidArgument, "function.search cursor is invalid");
          cursor = request.params["cursor"].get<std::string>();
        }

        try
        {
          services::FunctionSearchOutcome outcome;
          if ( has_name )
          {
            if ( !request.params["name"].is_string() )
              return Error(rpc::ErrorCode::InvalidArgument, "function.search name is invalid");
            const std::string name = request.params["name"].get<std::string>();
            if ( Utf8Length(name) > 256 )
              return Error(rpc::ErrorCode::InvalidArgument, "function.search name is too long");
            outcome = executor.ReadFor(
                std::chrono::milliseconds(request.timeout_ms),
                [&function_service, &name, &cursor, limit]()
                {
                  return function_service.SearchByName(name, *limit, cursor);
                });
          }
          else
          {
            if ( cursor || !request.params["address"].is_string() )
            {
              return Error(
                  rpc::ErrorCode::InvalidArgument,
                  "address search does not accept a cursor");
            }
            std::uint64_t address = 0;
            try
            {
              address = rpc::ParseAddress(request.params["address"].get<std::string>());
            }
            catch ( const std::invalid_argument & )
            {
              return Error(rpc::ErrorCode::InvalidAddress, "function address is invalid");
            }
            outcome = executor.ReadFor(
                std::chrono::milliseconds(request.timeout_ms),
                [&function_service, address]()
                {
                  return function_service.SearchByAddress(address);
                });
          }

          if ( outcome.status == services::FunctionSearchStatus::InvalidAddress )
            return Error(rpc::ErrorCode::InvalidAddress, "function address is not mapped");
          if ( outcome.status == services::FunctionSearchStatus::InvalidCursor )
            return Error(rpc::ErrorCode::InvalidArgument, "function.search cursor is invalid");
          if ( outcome.status == services::FunctionSearchStatus::OutputLimit )
            return Error(rpc::ErrorCode::OutputLimit, "function name exceeds the configured limit");
          if ( !outcome.result )
            throw std::runtime_error("function search did not return a result");
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
      "xref.query",
      [&executor, &xref_service](const rpc::Request &request)
          -> Dispatcher::MethodResult
      {
        for ( auto field = request.params.begin(); field != request.params.end(); ++field )
        {
          if ( field.key() != "address" && field.key() != "direction"
            && field.key() != "category" && field.key() != "includeFlow"
            && field.key() != "limit" && field.key() != "cursor" )
          {
            return Error(
                rpc::ErrorCode::InvalidArgument,
                "xref.query contains an unknown parameter");
          }
        }
        if ( !request.params.contains("address")
          || !request.params["address"].is_string()
          || !request.params.contains("direction")
          || !request.params["direction"].is_string() )
        {
          return Error(
              rpc::ErrorCode::InvalidArgument,
              "xref.query requires string address and direction parameters");
        }

        std::uint64_t address = 0;
        try
        {
          address = rpc::ParseAddress(request.params["address"].get<std::string>());
        }
        catch ( const std::invalid_argument & )
        {
          return Error(rpc::ErrorCode::InvalidAddress, "xref query address is invalid");
        }

        const std::string direction_name = request.params["direction"].get<std::string>();
        services::XrefDirection direction;
        if ( direction_name == "incoming" )
          direction = services::XrefDirection::Incoming;
        else if ( direction_name == "outgoing" )
          direction = services::XrefDirection::Outgoing;
        else
          return Error(rpc::ErrorCode::InvalidArgument, "xref direction is invalid");

        services::XrefCategory category = services::XrefCategory::All;
        if ( request.params.contains("category") )
        {
          if ( !request.params["category"].is_string() )
            return Error(rpc::ErrorCode::InvalidArgument, "xref category is invalid");
          const std::string category_name = request.params["category"].get<std::string>();
          if ( category_name == "code" )
            category = services::XrefCategory::Code;
          else if ( category_name == "data" )
            category = services::XrefCategory::Data;
          else if ( category_name != "all" )
            return Error(rpc::ErrorCode::InvalidArgument, "xref category is invalid");
        }

        bool include_flow = false;
        if ( request.params.contains("includeFlow") )
        {
          if ( !request.params["includeFlow"].is_boolean() )
            return Error(rpc::ErrorCode::InvalidArgument, "includeFlow must be boolean");
          include_flow = request.params["includeFlow"].get<bool>();
        }
        const std::optional<std::uint32_t> limit = ReadLimit(request.params);
        if ( !limit )
          return Error(rpc::ErrorCode::InvalidArgument, "xref limit must be from 1 to 100");

        std::optional<std::string> cursor;
        if ( request.params.contains("cursor") )
        {
          if ( !request.params["cursor"].is_string() )
            return Error(rpc::ErrorCode::InvalidArgument, "xref cursor is invalid");
          cursor = request.params["cursor"].get<std::string>();
        }

        try
        {
          const services::XrefQueryOutcome outcome = executor.ReadFor(
              std::chrono::milliseconds(request.timeout_ms),
              [&xref_service, address, direction, category, include_flow, limit, cursor]()
              {
                return xref_service.Query(services::XrefQuery{
                    address,
                    direction,
                    category,
                    include_flow,
                    *limit,
                    cursor,
                });
              });
          if ( outcome.status == services::XrefQueryStatus::InvalidAddress )
            return Error(rpc::ErrorCode::InvalidAddress, "xref query address is not mapped");
          if ( outcome.status == services::XrefQueryStatus::InvalidCursor )
            return Error(rpc::ErrorCode::InvalidArgument, "xref query cursor is invalid");
          if ( outcome.status == services::XrefQueryStatus::OutputLimit )
          {
            return Error(
                rpc::ErrorCode::OutputLimit,
                "xref query exceeds the phase pagination limit");
          }
          if ( !outcome.result )
            throw std::runtime_error("xref query did not return a result");
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
      "memory.read",
      [&executor, &memory_service](const rpc::Request &request)
          -> Dispatcher::MethodResult
      {
        for ( auto field = request.params.begin(); field != request.params.end(); ++field )
        {
          if ( field.key() != "address" && field.key() != "format"
            && field.key() != "length" && field.key() != "widthBits" )
          {
            return Error(
                rpc::ErrorCode::InvalidArgument,
                "memory.read contains an unknown parameter");
          }
        }
        if ( !request.params.contains("address")
          || !request.params["address"].is_string()
          || !request.params.contains("format")
          || !request.params["format"].is_string() )
        {
          return Error(
              rpc::ErrorCode::InvalidArgument,
              "memory.read requires string address and format parameters");
        }

        std::uint64_t address = 0;
        try
        {
          address = rpc::ParseAddress(request.params["address"].get<std::string>());
        }
        catch ( const std::invalid_argument & )
        {
          return Error(rpc::ErrorCode::InvalidAddress, "memory address is invalid");
        }

        services::MemoryReadQuery query{address, services::MemoryFormat::Bytes, 0, 0};
        const std::string format = request.params["format"].get<std::string>();
        if ( format == "bytes" || format == "string" )
        {
          if ( request.params.size() != 3 || !request.params.contains("length") )
          {
            return Error(
                rpc::ErrorCode::InvalidArgument,
                "bytes and string reads require only a length");
          }
          const auto length = ReadBoundedInteger(request.params["length"], 1, 4096);
          if ( !length )
            return Error(rpc::ErrorCode::InvalidArgument, "memory length must be from 1 to 4096");
          query.format = format == "bytes"
              ? services::MemoryFormat::Bytes
              : services::MemoryFormat::String;
          query.length = *length;
        }
        else if ( format == "integer" )
        {
          if ( request.params.size() != 3 || !request.params.contains("widthBits") )
          {
            return Error(
                rpc::ErrorCode::InvalidArgument,
                "integer reads require only widthBits");
          }
          const auto width = ReadBoundedInteger(request.params["widthBits"], 8, 64);
          if ( !width || (*width != 8 && *width != 16 && *width != 32 && *width != 64) )
            return Error(rpc::ErrorCode::InvalidArgument, "integer widthBits is invalid");
          query.format = services::MemoryFormat::Integer;
          query.width_bits = *width;
        }
        else if ( format == "pointer" )
        {
          if ( request.params.size() != 2 )
            return Error(rpc::ErrorCode::InvalidArgument, "pointer reads do not accept options");
          query.format = services::MemoryFormat::Pointer;
        }
        else
        {
          return Error(rpc::ErrorCode::InvalidArgument, "memory format is invalid");
        }

        try
        {
          const services::MemoryReadOutcome outcome = executor.ReadFor(
              std::chrono::milliseconds(request.timeout_ms),
              [&memory_service, query]() { return memory_service.Read(query); });
          if ( outcome.status == services::MemoryReadStatus::InvalidAddress )
            return Error(rpc::ErrorCode::InvalidAddress, "memory range is invalid");
          if ( outcome.status == services::MemoryReadStatus::Unreadable )
            return Error(rpc::ErrorCode::NotFound, "memory bytes are not initialized in the database");
          if ( outcome.status == services::MemoryReadStatus::UnsupportedProcessor )
          {
            return Error(
                rpc::ErrorCode::CapabilityUnavailable,
                "memory.read requires an 8-bit-byte processor");
          }
          if ( outcome.status == services::MemoryReadStatus::InvalidEncoding )
            return Error(rpc::ErrorCode::InvalidArgument, "memory string is not valid UTF-8");
          if ( !outcome.result )
            throw std::runtime_error("memory read did not return a result");
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
      "function.decompile",
      [&executor, &decompiler_service](const rpc::Request &request)
          -> Dispatcher::MethodResult
      {
        for ( auto field = request.params.begin(); field != request.params.end(); ++field )
        {
          if ( field.key() != "address" && field.key() != "offset"
            && field.key() != "maxBytes" )
          {
            return Error(
                rpc::ErrorCode::InvalidArgument,
                "function.decompile contains an unknown parameter");
          }
        }
        if ( !request.params.contains("address") || !request.params["address"].is_string() )
        {
          return Error(
              rpc::ErrorCode::InvalidArgument,
              "function.decompile requires a string address");
        }

        std::uint64_t address = 0;
        try
        {
          address = rpc::ParseAddress(request.params["address"].get<std::string>());
        }
        catch ( const std::invalid_argument & )
        {
          return Error(rpc::ErrorCode::InvalidAddress, "decompile address is invalid");
        }
        std::uint32_t offset = 0;
        if ( request.params.contains("offset") )
        {
          const auto parsed = ReadBoundedInteger(request.params["offset"], 0, 16 * 1024 * 1024);
          if ( !parsed )
            return Error(rpc::ErrorCode::InvalidArgument, "decompile offset is invalid");
          offset = *parsed;
        }
        std::uint32_t max_bytes = 32 * 1024;
        if ( request.params.contains("maxBytes") )
        {
          const auto parsed = ReadBoundedInteger(request.params["maxBytes"], 4, 64 * 1024);
          if ( !parsed )
            return Error(rpc::ErrorCode::InvalidArgument, "decompile maxBytes is invalid");
          max_bytes = *parsed;
        }

        try
        {
          const services::DecompileOutcome outcome = executor.ReadFor(
              std::chrono::milliseconds(request.timeout_ms),
              [&decompiler_service, address, offset, max_bytes]()
              {
                return decompiler_service.Decompile({address, offset, max_bytes});
              });
          switch ( outcome.status )
          {
            case services::DecompileStatus::InvalidAddress:
              return Error(rpc::ErrorCode::InvalidAddress, "decompile address is not mapped");
            case services::DecompileStatus::NotFound:
              return Error(rpc::ErrorCode::NotFound, "function was not found at the address");
            case services::DecompileStatus::CapabilityUnavailable:
              return Error(rpc::ErrorCode::CapabilityUnavailable, "Hex-Rays decompiler is unavailable");
            case services::DecompileStatus::InvalidArgument:
              return Error(rpc::ErrorCode::InvalidArgument, "decompile continuation is invalid");
            case services::DecompileStatus::Busy:
              return Error(rpc::ErrorCode::IdaBusy, "Hex-Rays decompiler is busy", true);
            case services::DecompileStatus::Failed:
              return Error(rpc::ErrorCode::DecompileFailed, "function decompilation failed");
            case services::DecompileStatus::OutputLimit:
              return Error(rpc::ErrorCode::OutputLimit, "decompiled text exceeds the configured limit");
            case services::DecompileStatus::Success:
              break;
          }
          if ( !outcome.result )
            throw std::runtime_error("function decompile did not return a result");
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
