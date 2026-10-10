#include "ai/agent_tool_registry.hpp"
#include <stdexcept>

void RunSemanticAgentToolTests()
{
  using namespace ida_agent::ai;
  int calls = 0;
  AgentToolInvokers invokers;
  invokers.argument_analysis = [&](const ida_agent::services::semantic::Request &request, bool guards) {
    if (request.call_address != 0x1020 || request.argument_index != 2 || request.max_work != 20000)
      throw std::runtime_error("semantic tool argument dispatch mismatch");
    ++calls;
    return nlohmann::json{{"guardsRequested", guards}};
  };
  invokers.argument_callers = [&](const ida_agent::services::semantic::CallersRequest &request) {
    if (request.max_depth != 0 || request.max_contexts != 16 || request.call_address != 0x1020)
      throw std::runtime_error("caller tool argument dispatch mismatch");
    return nlohmann::json{{"ok", true}};
  };
  auto registry = AgentToolRegistry::ForTesting(std::move(invokers));
  registry.SetAvailable(true);
  for (const char *name : {"ida_analysis_trace_argument", "ida_analysis_guard_evidence"})
  {
    auto result = registry.Invoke({"semantic-call", name, R"({"callAddress":"0x1020","argumentIndex":2,"maxNodes":200,"maxWork":20000,"maxGuards":32})"});
    if (!result.success) throw std::runtime_error("semantic tool invocation failed");
    const auto output = nlohmann::json::parse(result.output);
    if (output["guardsRequested"] != (std::string(name) == "ida_analysis_guard_evidence"))
      throw std::runtime_error("semantic tool selected wrong operation");
    result = registry.Invoke({"semantic-call", name, R"({"callAddress":"0x1020","argumentIndex":2,"unexpected":true})"});
    if (result.success) throw std::runtime_error("semantic tool accepted unknown field");
  }
  auto caller = registry.Invoke({"caller", "ida_analysis_trace_argument_callers", R"({"callAddress":"0x1020","argumentIndex":0,"maxDepth":0,"maxContexts":16,"maxCallers":8,"maxNodes":1000,"maxWork":100000})"});
  if (!caller.success) throw std::runtime_error("caller tool failed");
  caller = registry.Invoke({"caller", "ida_analysis_trace_argument_callers", R"({"callAddress":"0x1020","argumentIndex":0,"unknown":1})"});
  if (caller.success) throw std::runtime_error("caller tool accepted unknown field");
  if (calls != 2) throw std::runtime_error("invalid semantic call reached service");
}
