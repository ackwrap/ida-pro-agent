#include "ai/agent_tool_registry.hpp"

#include <nlohmann/json.hpp>

#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace
{
using namespace ida_agent::ai;
using Json = nlohmann::json;

void Require(bool condition, const char *message)
{
  if ( !condition ) throw std::runtime_error(message);
}

AgentToolCall Call(std::string name, std::string arguments)
{
  return {"file-call", std::move(name), std::move(arguments)};
}

void Invalid(AgentToolRegistry &registry, AgentToolCall call)
{
  const AgentToolResult result = registry.Invoke(call);
  Require(!result.success && result.output.empty(), "invalid file call succeeded");
}
} // namespace

void RunAgentFileRegistryTests()
{
  const auto &definitions = AgentToolDefinitions();
  Require(definitions.size() == 79, "read-only tool count mismatch");
  Require(definitions[68].name == "ida_file_list"
      && definitions[69].name == "ida_file_stat"
      && definitions[70].name == "ida_file_read", "file tool order mismatch");
  for ( std::size_t index = 68; index < 71; ++index )
  {
    const Json &schema = definitions[index].parameters;
    Require(schema.at("additionalProperties") == false
        && schema.at("required").size() == schema.at("properties").size(),
        "file schema is not strict");
    Require(!schema.at("properties").contains("root"), "file schema exposed a root selector");
  }

  int calls = 0;
  AgentToolInvokers invokers;
  invokers.file_list = [&](const AgentFileListArguments &args)
  {
    Require(args.path == "sub" && args.limit == 7, "file list dispatch mismatch");
    ++calls;
    return Json{{"items",Json::array({Json{{"path","sub/a.txt"},{"name","a.txt"},
        {"type","file"},{"size",1}}})},{"hasMore",false}};
  };
  invokers.file_stat = [&](std::string_view path)
  {
    Require(path == "a.txt", "file stat dispatch mismatch");
    ++calls;
    return Json{{"path",path},{"name","a.txt"},{"type","file"},{"size",1}};
  };
  invokers.file_read = [&](const AgentFileReadArguments &args)
  {
    Require(args.path == "a.txt" && args.offset == 2 && args.max_bytes == 9,
        "file read dispatch mismatch");
    ++calls;
    return Json{{"path",args.path},{"content","x"},{"bytesRead",1},
        {"hasMore",false},{"nextOffset",nullptr}};
  };
  AgentToolRegistry registry = AgentToolRegistry::ForTesting(std::move(invokers));
  registry.SetAvailable(true);
  Require(registry.Invoke(Call("ida_file_list", R"({"path":"sub","limit":7})")).success,
      "file list dispatch failed");
  Require(registry.Invoke(Call("ida_file_stat", R"({"path":"a.txt"})")).success,
      "file stat dispatch failed");
  Require(registry.Invoke(Call("ida_file_read", R"({"path":"a.txt","offset":2,"maxBytes":9})")).success,
      "file read dispatch failed");
  Require(calls == 3, "file invoker count mismatch");
  Invalid(registry, Call("ida_file_list", R"({"path":"","limit":0})"));
  Invalid(registry, Call("ida_file_stat", R"({"path":""})"));
  Invalid(registry, Call("ida_file_read", R"({"path":"a.txt","offset":0,"maxBytes":131073})"));

  AgentToolInvokers large_invokers;
  large_invokers.file_read = [](const AgentFileReadArguments &args)
  {
    return Json{{"path",args.path},{"content",std::string(128 * 1024, '\"')},
        {"bytesRead",128 * 1024},{"hasMore",false},{"nextOffset",nullptr}};
  };
  AgentToolRegistry large = AgentToolRegistry::ForTesting(std::move(large_invokers));
  large.SetAvailable(true);
  const AgentToolResult large_read = large.Invoke(Call("ida_file_read",
      R"({"path":"large.txt","offset":0,"maxBytes":131072})"));
  Require(large_read.success && large_read.output.size() > MaxAgentToolResultBytes
      && large_read.output.size() <= MaxAgentFileToolResultBytes,
      "maximum escaped file read result was rejected");
}
