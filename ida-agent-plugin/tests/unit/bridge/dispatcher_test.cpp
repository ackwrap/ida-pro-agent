#include "dispatcher.hpp"

#include <stdexcept>
#include <utility>

namespace
{

void Require(bool condition, const char *message)
{
  if ( !condition )
    throw std::runtime_error(message);
}

ida_agent::rpc::Request Request(std::string method, nlohmann::json params = nlohmann::json::object())
{
  return ida_agent::rpc::Request{
      std::string(ida_agent::rpc::ProtocolVersion),
      "req-0001",
      "session-0001",
      std::move(method),
      std::move(params),
      5000,
  };
}

} // namespace

int main()
{
  ida_agent::bridge::Dispatcher::MethodHandlers handlers;
  handlers.emplace(
      "database.info",
      [](const ida_agent::rpc::Request &request)
          -> ida_agent::bridge::Dispatcher::MethodResult
      {
        if ( !request.params.empty() )
        {
          return ida_agent::rpc::RpcError{
              ida_agent::rpc::ErrorCode::InvalidArgument,
              "database.info params must be empty",
              false,
          };
        }
        return nlohmann::json{
            {"database", "test.exe"},
            {"processor", "metapc"},
            {"architecture", "x86_64"},
            {"addressBits", 64},
        };
      });
  handlers.emplace(
      "function.get",
      [](const ida_agent::rpc::Request &request)
          -> ida_agent::bridge::Dispatcher::MethodResult
      {
        if ( request.params.size() != 1 || !request.params.contains("address") )
        {
          return ida_agent::rpc::RpcError{
              ida_agent::rpc::ErrorCode::InvalidArgument,
              "invalid function params",
              false,
          };
        }
        return nlohmann::json{
            {"entryAddress", "0x140001000"},
            {"name", "sub_140001000"},
        };
      });
  handlers.emplace(
      "function.search",
      [](const ida_agent::rpc::Request &)
          -> ida_agent::bridge::Dispatcher::MethodResult
      {
        return nlohmann::json{
            {"items", nlohmann::json::array({
                {{"entryAddress", "0x140001000"}, {"name", "sub_140001000"}},
            })},
            {"nextCursor", nullptr},
            {"hasMore", false},
        };
      });
  handlers.emplace(
      "xref.query",
      [](const ida_agent::rpc::Request &)
          -> ida_agent::bridge::Dispatcher::MethodResult
      {
        return nlohmann::json{
            {"items", nlohmann::json::array({
                {
                    {"from", "0x140001000"},
                    {"to", "0x140002000"},
                    {"type", "call_near"},
                    {"code", true},
                    {"userDefined", false},
                },
            })},
            {"nextCursor", nullptr},
            {"hasMore", false},
          };
      });
  handlers.emplace(
      "memory.read",
      [](const ida_agent::rpc::Request &)
          -> ida_agent::bridge::Dispatcher::MethodResult
      {
        return nlohmann::json{
            {"address", "0x140001000"},
            {"format", "bytes"},
            {"bytesRead", 4},
            {"value", "4883ec28"},
        };
      });
  handlers.emplace(
      "function.decompile",
      [](const ida_agent::rpc::Request &)
          -> ida_agent::bridge::Dispatcher::MethodResult
      {
        return nlohmann::json{
            {"entryAddress", "0x140001000"},
            {"pseudocode", "int main() {}"},
            {"offset", 0},
            {"returnedSize", 13},
            {"originalSize", 13},
            {"truncated", false},
            {"nextOffset", nullptr},
        };
      });
  const ida_agent::bridge::Dispatcher dispatcher(
      "session-0001",
      std::move(handlers));

  const auto ping = dispatcher.Dispatch(Request("system.ping"));
  Require(ping.result.has_value(), "ping result missing");
  Require((*ping.result)["status"] == "ok", "ping status mismatch");

  const auto invalid_ping = dispatcher.Dispatch(Request("system.ping", {{"unexpected", true}}));
  Require(invalid_ping.error.has_value(), "invalid ping error missing");
  Require(
      invalid_ping.error->code == ida_agent::rpc::ErrorCode::InvalidArgument,
      "invalid ping code mismatch");

  const auto database = dispatcher.Dispatch(Request("database.info"));
  Require(database.result.has_value(), "database result missing");
  Require((*database.result)["database"] == "test.exe", "database name mismatch");

  const auto invalid_database = dispatcher.Dispatch(
      Request("database.info", {{"unexpected", true}}));
  Require(invalid_database.error.has_value(), "invalid database error missing");
  Require(
      invalid_database.error->code == ida_agent::rpc::ErrorCode::InvalidArgument,
      "invalid database code mismatch");

  const auto function = dispatcher.Dispatch(
      Request("function.get", {{"address", "0x140001010"}}));
  Require(function.result.has_value(), "function result missing");
  Require((*function.result)["entryAddress"] == "0x140001000", "function entry mismatch");

  const auto invalid_function = dispatcher.Dispatch(Request("function.get"));
  Require(invalid_function.error.has_value(), "invalid function error missing");
  Require(
      invalid_function.error->code == ida_agent::rpc::ErrorCode::InvalidArgument,
      "invalid function code mismatch");

  const auto function_search = dispatcher.Dispatch(
      Request("function.search", {{"name", "sub_"}, {"limit", 20}}));
  Require(function_search.result.has_value(), "function search result missing");
  Require((*function_search.result)["items"].size() == 1, "function search items mismatch");

  const auto xrefs = dispatcher.Dispatch(
      Request("xref.query", {{"address", "0x140001000"}, {"direction", "outgoing"}}));
  Require(xrefs.result.has_value(), "xref result missing");
  Require((*xrefs.result)["items"].size() == 1, "xref items mismatch");

  const auto memory = dispatcher.Dispatch(
      Request("memory.read", {{"address", "0x140001000"}, {"format", "bytes"}, {"length", 4}}));
  Require(memory.result.has_value(), "memory result missing");
  Require((*memory.result)["value"] == "4883ec28", "memory value mismatch");

  const auto decompile = dispatcher.Dispatch(
      Request("function.decompile", {{"address", "0x140001000"}}));
  Require(decompile.result.has_value(), "decompile result missing");
  Require((*decompile.result)["originalSize"] == 13, "decompile size mismatch");

  const auto missing = dispatcher.Dispatch(Request("symbol.lookup"));
  Require(missing.error.has_value(), "missing method error missing");
  Require(missing.error->code == ida_agent::rpc::ErrorCode::NotFound, "missing method code mismatch");

  auto wrong_session = Request("system.ping");
  wrong_session.session_id = "session-other";
  const auto denied = dispatcher.Dispatch(wrong_session);
  Require(denied.error.has_value(), "wrong session error missing");
  Require(
      denied.error->code == ida_agent::rpc::ErrorCode::PermissionDenied,
      "wrong session code mismatch");
  return 0;
}
