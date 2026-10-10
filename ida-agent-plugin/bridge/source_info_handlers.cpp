#include "source_info_handlers.hpp"
#include "query_handler_support.hpp"
#include "services/source_info_service.hpp"

namespace ida_agent::bridge
{
Dispatcher::MethodHandlers BuildSourceInfoHandlers(IdaExecutor &executor, const services::SourceInfoService &service)
{
  Dispatcher::MethodHandlers handlers;
  handlers.emplace("source.files", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( !query::Fields(request.params, {"limit", "cursor"}) ) return query::Error(rpc::ErrorCode::InvalidArgument, "source.files parameters are invalid");
    const auto limit = query::Integer(request.params, "limit", 20, 1, 100); const auto cursor = query::Integer(request.params, "cursor", 0, 0, 1000000);
    if ( !limit || !cursor ) return query::Error(rpc::ErrorCode::InvalidArgument, "source.files parameters are invalid");
    return query::Run(executor, request, [&service, limit, cursor]() { return service.SourceFiles(*limit, *cursor); });
  });
  handlers.emplace("source.lines", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( !query::Fields(request.params, {"start", "end", "limit", "cursor"}) ) return query::Error(rpc::ErrorCode::InvalidArgument, "source.lines parameters are invalid");
    try { const auto start = query::Address(request.params, "start", true); const auto end = query::Address(request.params, "end", true); const auto cursor = query::Address(request.params, "cursor", false); const auto limit = query::Integer(request.params, "limit", 20, 1, 100); if ( !limit || *start >= *end || cursor && (*cursor < *start || *cursor >= *end) ) throw std::invalid_argument("range"); return query::Run(executor, request, [&service, start, end, cursor, limit]() { return service.SourceLines(*start, *end, *limit, cursor); }); }
    catch ( const std::invalid_argument & ) { return query::Error(rpc::ErrorCode::InvalidArgument, "source.lines parameters are invalid"); }
  });
  return handlers;
}
}
