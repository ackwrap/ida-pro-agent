#include "decompiler_inspection_handlers.hpp"
#include "query_handler_support.hpp"
#include "services/decompiler_inspection_service.hpp"

namespace ida_agent::bridge
{
Dispatcher::MethodHandlers BuildDecompilerInspectionHandlers(IdaExecutor &executor, const services::DecompilerInspectionService &service)
{
  Dispatcher::MethodHandlers handlers;
  handlers.emplace("decompiler.locals", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( !query::Fields(request.params, {"address", "maxItems"}) ) return query::Error(rpc::ErrorCode::InvalidArgument, "decompiler.locals parameters are invalid"); try { const auto address = query::Address(request.params, "address", true); const auto maximum = query::Integer(request.params, "maxItems", 100, 1, 512); if ( !maximum ) throw std::invalid_argument("maximum"); return query::Run(executor, request, [&service, address, maximum]() { return service.DecompilerLocals(*address, *maximum); }); } catch ( const std::invalid_argument & ) { return query::Error(rpc::ErrorCode::InvalidArgument, "decompiler.locals parameters are invalid"); }
  });
  handlers.emplace("decompiler.ctree", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( !query::Fields(request.params, {"address", "maxDepth", "maxNodes"}) ) return query::Error(rpc::ErrorCode::InvalidArgument, "decompiler.ctree parameters are invalid"); try { const auto address = query::Address(request.params, "address", true); const auto depth = query::Integer(request.params, "maxDepth", 8, 1, 32); const auto nodes = query::Integer(request.params, "maxNodes", 200, 1, 1000); if ( !depth || !nodes ) throw std::invalid_argument("bounds"); return query::Run(executor, request, [&service, address, depth, nodes]() { return service.DecompilerCtree(*address, *depth, *nodes); }); } catch ( const std::invalid_argument & ) { return query::Error(rpc::ErrorCode::InvalidArgument, "decompiler.ctree parameters are invalid"); }
  });
  handlers.emplace("decompiler.local_xrefs", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( !query::Fields(request.params, {"address", "localIndex", "maxDepth", "maxNodes", "maxItems"}) ) return query::Error(rpc::ErrorCode::InvalidArgument, "decompiler.local_xrefs parameters are invalid"); try { const auto address = query::Address(request.params, "address", true); const auto index = query::Integer(request.params, "localIndex", 0, 0, 1000000); const auto depth = query::Integer(request.params, "maxDepth", 16, 1, 32); const auto nodes = query::Integer(request.params, "maxNodes", 1000, 1, 5000); const auto items = query::Integer(request.params, "maxItems", 100, 1, 512); if ( !request.params.contains("localIndex") || !index || !depth || !nodes || !items ) throw std::invalid_argument("bounds"); return query::Run(executor, request, [&service, address, index, depth, nodes, items]() { return service.DecompilerLocalXrefs(*address, *index, *depth, *nodes, *items); }); } catch ( const std::invalid_argument & ) { return query::Error(rpc::ErrorCode::InvalidArgument, "decompiler.local_xrefs parameters are invalid"); }
  });
  return handlers;
}
}
