#include "ai/agent_tool_registry.hpp"
#include <stdexcept>
void RunAgentDebuggerRegistryTests()
{
  using namespace ida_agent::ai; using Json=nlohmann::json;
  const auto check=[](bool value){if(!value)throw std::runtime_error("debugger readonly registry invariant failed");};
  int calls=0;AgentToolInvokers invokers;
  invokers.debugger_backends=[&](){++calls;return Json{{"items",Json::array()},{"current",""},{"remote",false}};};
  invokers.debugger_configuration=[&](){++calls;return Json{{"hasPassword",true}};};
  invokers.debugger_processes=[&](std::uint32_t limit){check(limit==2);++calls;return Json{{"items",Json::array()},{"total",0},{"truncated",false}};};
  auto registry=AgentToolRegistry::ForTesting(std::move(invokers));registry.SetAvailable(true);
  for(const auto name:{"ida_debugger_backends","ida_debugger_configuration"})check(registry.Invoke({"read",name,"{}"}).success);
  check(registry.Invoke({"read","ida_debugger_processes",R"({"limit":2})"}).success);
  check(!registry.Invoke({"read","ida_debugger_processes",R"({"limit":1001})"}).success);
  check(!registry.Invoke({"read","ida_debugger_backends",R"({"unknown":true})"}).success);
  for(const auto name:{"ida_debugger_select","ida_debugger_configure","ida_debugger_attach","ida_debugger_detach","ida_debugger_suspend"})
    check(!registry.Invoke({"write",name,"{}"}).success);
  check(calls==3);
}
