#include "symbol_handlers.hpp"
#include "query_handler_support.hpp"
#include "services/symbol_service.hpp"

namespace ida_agent::bridge
{
Dispatcher::MethodHandlers BuildSymbolHandlers(IdaExecutor &executor, const services::SymbolService &service)
{
  Dispatcher::MethodHandlers handlers;
  handlers.emplace("name.demangle", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( !query::Fields(request.params, {"address", "name"}) || request.params.contains("address") == request.params.contains("name") ) return query::Error(rpc::ErrorCode::InvalidArgument, "name.demangle parameters are invalid");
    try { const auto address = query::Address(request.params, "address", false); std::optional<std::string> name; if ( request.params.contains("name") ) { const auto parsed = query::Text(request.params, "name", true, 4096); if ( !parsed ) throw std::invalid_argument("name"); name = *parsed; } return query::Run(executor, request, [&service, address, name]() { return service.Demangle(address, name); }); }
    catch ( const std::invalid_argument & ) { return query::Error(rpc::ErrorCode::InvalidArgument, "name.demangle parameters are invalid"); }
  });
  return handlers;
}
}
