#include "annotation_handlers.hpp"
#include "query_handler_support.hpp"
#include "services/annotation_service.hpp"

namespace ida_agent::bridge
{
Dispatcher::MethodHandlers BuildAnnotationHandlers(IdaExecutor &executor, const services::AnnotationService &service)
{
  Dispatcher::MethodHandlers handlers;
  handlers.emplace("comment.get", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( !query::Fields(request.params, {"address", "scope", "repeatable"}) ) return query::Error(rpc::ErrorCode::InvalidArgument, "comment.get parameters are invalid");
    try { const auto address = query::Address(request.params, "address", true); std::string scope = "item"; bool repeatable = false; if ( request.params.contains("scope") ) { if ( !request.params["scope"].is_string() ) throw std::invalid_argument("scope"); scope = request.params["scope"].get<std::string>(); } if ( scope != "item" && scope != "function" ) throw std::invalid_argument("scope"); if ( request.params.contains("repeatable") ) { if ( !request.params["repeatable"].is_boolean() ) throw std::invalid_argument("repeatable"); repeatable = request.params["repeatable"].get<bool>(); } return query::Run(executor, request, [&service, address, scope, repeatable]() { return service.CommentGet(*address, scope, repeatable); }); }
    catch ( const std::invalid_argument & ) { return query::Error(rpc::ErrorCode::InvalidArgument, "comment.get parameters are invalid"); }
  });
  handlers.emplace("bookmark.list", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult {
    if ( !query::Fields(request.params, {"limit", "cursor"}) ) return query::Error(rpc::ErrorCode::InvalidArgument, "bookmark.list parameters are invalid"); const auto limit = query::Integer(request.params, "limit", 20, 1, 100); const auto cursor = query::Integer(request.params, "cursor", 0, 0, 1024); if ( !limit || !cursor ) return query::Error(rpc::ErrorCode::InvalidArgument, "bookmark.list parameters are invalid"); return query::Run(executor, request, [&service, limit, cursor]() { return service.BookmarkList(*limit, *cursor); });
  });
  return handlers;
}
}
