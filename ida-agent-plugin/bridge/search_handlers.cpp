#include "search_handlers.hpp"

#include "ida_executor.hpp"
#include "rpc/address.hpp"
#include "services/search_service.hpp"

#include <chrono>
#include <optional>
#include <string>

namespace ida_agent::bridge
{
namespace
{

constexpr std::size_t MaxSearchResultBytes = 500 * 1024;

Dispatcher::MethodResult Error(rpc::ErrorCode code, const char *message, bool retryable = false)
{
  return rpc::RpcError{code, message, retryable};
}

std::optional<std::uint32_t> Limit(const nlohmann::json &params, const char *name, std::uint32_t fallback, std::uint32_t maximum)
{
  if ( !params.contains(name) ) return fallback;
  const auto &encoded = params[name];
  if ( encoded.is_number_unsigned() )
  {
    const std::uint64_t value = encoded.get<std::uint64_t>();
    return value >= 1 && value <= maximum ? std::optional<std::uint32_t>(static_cast<std::uint32_t>(value)) : std::nullopt;
  }
  if ( !encoded.is_number_integer() ) return std::nullopt;
  const std::int64_t value = encoded.get<std::int64_t>();
  return value >= 1 && value <= maximum ? std::optional<std::uint32_t>(static_cast<std::uint32_t>(value)) : std::nullopt;
}

bool Address(const nlohmann::json &params, const char *name, std::uint64_t *value)
{
  if ( !params.contains(name) || !params[name].is_string() ) return false;
  try { *value = rpc::ParseAddress(params[name].get<std::string>()); return true; }
  catch ( const std::invalid_argument & ) { return false; }
}

std::optional<bool> Boolean(const nlohmann::json &params, const char *name, bool fallback)
{
  if ( !params.contains(name) ) return fallback;
  if ( !params[name].is_boolean() ) return std::nullopt;
  return params[name].get<bool>();
}

std::optional<services::SignatureMode> SignatureMode(const nlohmann::json &params)
{
  if ( !params.contains("mode") ) return services::SignatureMode::Address;
  if ( !params["mode"].is_string() ) return std::nullopt;
  const std::string value = params["mode"].get<std::string>();
  if ( value == "address" ) return services::SignatureMode::Address;
  if ( value == "function" ) return services::SignatureMode::Function;
  if ( value == "range" ) return services::SignatureMode::Range;
  return std::nullopt;
}

std::optional<services::SignatureFormat> SignatureFormat(const nlohmann::json &params)
{
  if ( !params.contains("format") ) return services::SignatureFormat::Ida;
  if ( !params["format"].is_string() ) return std::nullopt;
  const std::string value = params["format"].get<std::string>();
  if ( value == "ida" ) return services::SignatureFormat::Ida;
  if ( value == "x64dbg" ) return services::SignatureFormat::X64Dbg;
  if ( value == "mask" ) return services::SignatureFormat::Mask;
  if ( value == "bitmask" ) return services::SignatureFormat::Bitmask;
  return std::nullopt;
}

template <typename Operation>
Dispatcher::MethodResult Run(IdaExecutor &executor, const rpc::Request &request, Operation operation)
{
  try
  {
    auto outcome = executor.ReadFor(std::chrono::milliseconds(request.timeout_ms), std::move(operation));
    switch ( outcome.status )
    {
      case services::SearchStatus::InvalidAddress: return Error(rpc::ErrorCode::InvalidAddress, "search range is invalid");
      case services::SearchStatus::InvalidCursor: return Error(rpc::ErrorCode::InvalidArgument, "search cursor is invalid");
      case services::SearchStatus::InvalidPattern: return Error(rpc::ErrorCode::InvalidArgument, "search pattern is invalid");
      case services::SearchStatus::NotFound: return Error(rpc::ErrorCode::NotFound, "search target was not found");
      case services::SearchStatus::OutputLimit: return Error(rpc::ErrorCode::OutputLimit, "search output limit exceeded");
      case services::SearchStatus::Success: break;
    }
    if ( !outcome.result ) return Error(rpc::ErrorCode::InternalError, "search result is unavailable");
    nlohmann::json result = services::ToJson(*outcome.result);
    if ( result.dump().size() > MaxSearchResultBytes )
      return Error(rpc::ErrorCode::OutputLimit, "search output exceeds the output budget");
    return result;
  }
  catch ( const IdaTimeoutError & ) { return Error(rpc::ErrorCode::Timeout, "IDA request timed out", true); }
  catch ( const IdaBusyError & ) { return Error(rpc::ErrorCode::IdaBusy, "IDA is busy", true); }
}

bool Known(const nlohmann::json &params, std::initializer_list<const char *> names)
{
  for ( auto field = params.begin(); field != params.end(); ++field )
  {
    bool found = false;
    for ( const char *name : names ) found = found || field.key() == name;
    if ( !found ) return false;
  }
  return true;
}

} // namespace

Dispatcher::MethodHandlers BuildSearchHandlers(
    IdaExecutor &executor,
    const services::SearchService &search_service)
{
  Dispatcher::MethodHandlers handlers;
  handlers.emplace("memory.search_bytes", [&executor, &search_service](const rpc::Request &request) -> Dispatcher::MethodResult
  {
    if ( !Known(request.params, {"pattern", "start", "end", "limit"})
      || !request.params.contains("pattern") || !request.params["pattern"].is_string() )
      return Error(rpc::ErrorCode::InvalidArgument, "memory.search_bytes params are invalid");
    const std::string pattern = request.params["pattern"].get<std::string>();
    std::uint64_t start = 0, end = 0;
    const auto limit = Limit(request.params, "limit", 20, 100);
    if ( pattern.empty() || pattern.size() > 1024 || !Address(request.params, "start", &start)
      || !Address(request.params, "end", &end) || !limit )
      return Error(rpc::ErrorCode::InvalidArgument, "memory.search_bytes params are invalid");
    return Run(executor, request, [&search_service, pattern, start, end, limit]() { return search_service.Bytes(pattern, start, end, *limit); });
  });
  handlers.emplace("instruction.search", [&executor, &search_service](const rpc::Request &request) -> Dispatcher::MethodResult
  {
    if ( !Known(request.params, {"start", "end", "mnemonic", "operand", "limit", "cursor"}) )
      return Error(rpc::ErrorCode::InvalidArgument, "instruction.search contains an unknown parameter");
    std::uint64_t start = 0, end = 0;
    const auto limit = Limit(request.params, "limit", 20, 100);
    std::optional<std::string> cursor;
    std::string mnemonic, operand;
    if ( request.params.contains("mnemonic") ) { if ( !request.params["mnemonic"].is_string() ) return Error(rpc::ErrorCode::InvalidArgument, "mnemonic is invalid"); mnemonic = request.params["mnemonic"].get<std::string>(); }
    if ( request.params.contains("operand") ) { if ( !request.params["operand"].is_string() ) return Error(rpc::ErrorCode::InvalidArgument, "operand is invalid"); operand = request.params["operand"].get<std::string>(); }
    if ( request.params.contains("cursor") )
    {
      if ( !request.params["cursor"].is_string() ) return Error(rpc::ErrorCode::InvalidArgument, "instruction cursor is invalid");
      cursor = request.params["cursor"].get<std::string>();
    }
    if ( mnemonic.size() > 256 || operand.size() > 256
      || (cursor && cursor->size() > 128)
      || !Address(request.params, "start", &start) || !Address(request.params, "end", &end) || !limit )
      return Error(rpc::ErrorCode::InvalidArgument, "instruction.search params are invalid");
    return Run(executor, request, [&search_service, start, end, mnemonic, operand, limit, cursor]() { return search_service.Instructions(start, end, mnemonic, operand, *limit, cursor); });
  });
  handlers.emplace("instruction.query", handlers.at("instruction.search"));
  handlers.emplace("listing.search", [&executor, &search_service](const rpc::Request &request) -> Dispatcher::MethodResult
  {
    if ( !Known(request.params, {"start", "end", "query", "limit"})
      || !request.params.contains("query") || !request.params["query"].is_string() )
      return Error(rpc::ErrorCode::InvalidArgument, "listing.search params are invalid");
    const std::string query = request.params["query"].get<std::string>();
    std::uint64_t start = 0, end = 0;
    const auto limit = Limit(request.params, "limit", 20, 100);
    if ( query.empty() || query.size() > 1024 || !Address(request.params, "start", &start)
      || !Address(request.params, "end", &end) || !limit )
      return Error(rpc::ErrorCode::InvalidArgument, "listing.search params are invalid");
    return Run(executor, request, [&search_service, start, end, query, limit]() { return search_service.Listing(start, end, query, false, true, false, *limit, std::nullopt); });
  });
  handlers.emplace("listing.search_text", [&executor, &search_service](const rpc::Request &request) -> Dispatcher::MethodResult
  {
    if ( !Known(request.params, {"start", "end", "query", "regex", "includeDisassembly", "includeComments", "limit", "cursor"}) )
      return Error(rpc::ErrorCode::InvalidArgument, "listing.search_text contains an unknown parameter");
    const bool has_query = request.params.contains("query");
    const bool has_regex = request.params.contains("regex");
    if ( has_query == has_regex || (has_query && !request.params["query"].is_string())
      || (has_regex && !request.params["regex"].is_string()) )
      return Error(rpc::ErrorCode::InvalidArgument, "listing.search_text requires exactly one string query or regex");
    const std::string pattern = request.params[has_regex ? "regex" : "query"].get<std::string>();
    const auto disassembly = Boolean(request.params, "includeDisassembly", true);
    const auto comments = Boolean(request.params, "includeComments", true);
    const auto limit = Limit(request.params, "limit", 20, 100);
    std::uint64_t start = 0, end = 0;
    std::optional<std::string> cursor;
    if ( request.params.contains("cursor") )
    {
      if ( !request.params["cursor"].is_string() ) return Error(rpc::ErrorCode::InvalidArgument, "listing cursor is invalid");
      cursor = request.params["cursor"].get<std::string>();
    }
    if ( pattern.empty() || pattern.size() > 1024 || (has_regex && pattern.size() > 256)
      || !disassembly || !comments
      || (!*disassembly && !*comments) || (cursor && cursor->size() > 128)
      || !Address(request.params, "start", &start) || !Address(request.params, "end", &end) || !limit )
      return Error(rpc::ErrorCode::InvalidArgument, "listing.search_text params are invalid");
    return Run(executor, request, [&search_service, start, end, pattern, has_regex, disassembly, comments, limit, cursor]()
    {
      return search_service.Listing(
          start, end, pattern, has_regex, *disassembly, *comments, *limit, cursor);
    });
  });
  handlers.emplace("signature.make", [&executor, &search_service](const rpc::Request &request) -> Dispatcher::MethodResult
  {
    if ( !Known(request.params, {"mode", "address", "start", "end", "format", "wildcardOperands", "maxLength"}) )
      return Error(rpc::ErrorCode::InvalidArgument, "signature.make contains an unknown parameter");
    const auto mode = SignatureMode(request.params);
    const auto format = SignatureFormat(request.params);
    const auto wildcard_operands = Boolean(request.params, "wildcardOperands", true);
    const auto length = Limit(request.params, "maxLength", 1000, 1000);
    if ( !mode || !format || !wildcard_operands || !length )
      return Error(rpc::ErrorCode::InvalidArgument, "signature.make params are invalid");

    std::uint64_t address = 0;
    std::optional<std::uint64_t> end;
    if ( *mode == services::SignatureMode::Range )
    {
      std::uint64_t range_end = 0;
      if ( request.params.contains("address") || !Address(request.params, "start", &address)
        || !Address(request.params, "end", &range_end) )
      {
        return Error(rpc::ErrorCode::InvalidArgument, "signature.make range params are invalid");
      }
      end = range_end;
    }
    else if ( request.params.contains("start") || request.params.contains("end")
      || !Address(request.params, "address", &address) )
    {
      return Error(rpc::ErrorCode::InvalidArgument, "signature.make address params are invalid");
    }
    return Run(executor, request, [&search_service, mode, address, end, format, wildcard_operands, length]()
    {
      return search_service.MakeSignature(*mode, address, end, *format, *wildcard_operands, *length);
    });
  });
  handlers.emplace("signature.xrefs", [&executor, &search_service](const rpc::Request &request) -> Dispatcher::MethodResult
  {
    if ( !Known(request.params, {"address", "format", "wildcardOperands", "maxLength", "top"}) )
      return Error(rpc::ErrorCode::InvalidArgument, "signature.xrefs contains an unknown parameter");
    std::uint64_t address = 0;
    const auto format = SignatureFormat(request.params);
    const auto wildcard_operands = Boolean(request.params, "wildcardOperands", true);
    const auto length = Limit(request.params, "maxLength", 250, 1000);
    const auto top = Limit(request.params, "top", 5, 32);
    if ( !Address(request.params, "address", &address) || !format || !wildcard_operands || !length || !top )
      return Error(rpc::ErrorCode::InvalidArgument, "signature.xrefs params are invalid");
    return Run(executor, request, [&search_service, address, format, wildcard_operands, length, top]()
    {
      return search_service.XrefSignatures(address, *format, *wildcard_operands, *length, *top);
    });
  });
  handlers.emplace("patch.assemble", [&executor, &search_service](const rpc::Request &request) -> Dispatcher::MethodResult
  {
    if ( !Known(request.params, {"address", "instruction"}) || request.params.size() != 2
      || !request.params.contains("instruction") || !request.params["instruction"].is_string() )
      return Error(rpc::ErrorCode::InvalidArgument, "patch.assemble params are invalid");
    std::uint64_t address = 0; const std::string instruction = request.params["instruction"].get<std::string>();
    if ( !Address(request.params, "address", &address) || instruction.empty() || instruction.size() > 4096 )
      return Error(rpc::ErrorCode::InvalidArgument, "patch.assemble params are invalid");
    return Run(executor, request, [&search_service, address, instruction]() { return search_service.Assemble(address, instruction); });
  });
  return handlers;
}

} // namespace ida_agent::bridge
