#include "ai/agent_effect_service.hpp"
#include <stdexcept>
namespace ai = ida_agent::ai;
namespace services = ida_agent::services;
using Json = nlohmann::json;
void RunAgentDebuggerSetupTests()
{
  const auto check = [](bool value) { if (!value) throw std::runtime_error("debugger setup AI invariant failed"); };
  std::string state = "not_running"; int writes = 0; bool unavailable = true;
  ai::AgentEffectServiceCallbacks callbacks;
  callbacks.debugger_info = [&]() -> services::DebuggerInfoOutcome {
    if(unavailable) return {services::DebuggerStatus::Unavailable,std::nullopt};
    return {services::DebuggerStatus::Success,services::DebuggerInfo{state,state=="running",state=="suspended",std::nullopt,std::nullopt}};
  };
  const auto accepted = [&]() { ++writes; return services::DebuggerActionOutcome{services::DebuggerStatus::Success,
      services::DebuggerAction{true,state,state=="running",state=="suspended",std::nullopt,std::nullopt}}; };
  callbacks.debugger_select = [&](const services::DebuggerSelectRequest &p) { check(p.name=="win32" && p.remote); return accepted(); };
  callbacks.debugger_configure = [&](const services::DebuggerConfigureRequest &p) { check(p.password=="fixture-password" && !p.path && !p.port); return accepted(); };
  callbacks.debugger_attach = [&](int pid) { check(pid==1234);return accepted(); };
  callbacks.debugger_detach = accepted; callbacks.debugger_suspend = accepted;
  auto service = ai::AgentEffectService::ForTesting(callbacks);
  ai::AgentToolCall select{"select","ida_debugger_select",R"({"name":"win32","remote":true})"};
  auto plan=service.Prepare(ai::AgentEffectName::DebuggerSelect,select);check(!plan.opaque_payload.empty() && writes==0);
  check(service.Execute(ai::AgentEffectName::DebuggerSelect,select,plan.opaque_payload).success && writes==1);
  ai::AgentToolCall configure{"configure","ida_debugger_configure",R"({"path":null,"arguments":null,"directory":null,"host":null,"port":null,"password":"fixture-password"})"};
  plan=service.Prepare(ai::AgentEffectName::DebuggerConfigure,configure);check(!plan.opaque_payload.empty() && plan.safe_summary.find("fixture-password")==std::string::npos);
  configure.arguments_json=R"({"password":"changed-after-prepare"})";
  const auto result=service.Execute(ai::AgentEffectName::DebuggerConfigure,configure,plan.opaque_payload);
  check(result.success && writes==2 && result.output.find("fixture-password")==std::string::npos);
  check(!service.Execute(ai::AgentEffectName::DebuggerSelect,select,plan.opaque_payload).success);
  unavailable=false; state="running";
  check(service.Prepare(ai::AgentEffectName::DebuggerSelect,select).opaque_payload.empty());
  check(service.Prepare(ai::AgentEffectName::DebuggerConfigure,configure).opaque_payload.empty());
  for(const auto effect:{ai::AgentEffectName::DebuggerAttach,ai::AgentEffectName::DebuggerDetach,ai::AgentEffectName::DebuggerSuspend})
  {
    const char *name=effect==ai::AgentEffectName::DebuggerAttach ? "ida_debugger_attach" : effect==ai::AgentEffectName::DebuggerDetach ? "ida_debugger_detach" : "ida_debugger_suspend";
    state=effect==ai::AgentEffectName::DebuggerAttach ? "not_running" : effect==ai::AgentEffectName::DebuggerDetach ? "suspended" : "running";
    ai::AgentToolCall call{name,name,effect==ai::AgentEffectName::DebuggerAttach ? R"({"pid":1234})" : "{}"};
    plan=service.Prepare(effect,call);check(!plan.opaque_payload.empty());
    check(service.Execute(effect,call,plan.opaque_payload).success);
    state=effect==ai::AgentEffectName::DebuggerAttach ? "running" : "not_running";
    check(service.Prepare(effect,call).opaque_payload.empty());
  }
  state="not_running";configure.arguments_json=R"({"password":null})";
  check(service.Prepare(ai::AgentEffectName::DebuggerConfigure,configure).opaque_payload.empty());
  callbacks.debugger_attach=[](int)->services::DebuggerActionOutcome {throw std::runtime_error("secret failure");};
  service=ai::AgentEffectService::ForTesting(callbacks);
  ai::AgentToolCall attach{"attach","ida_debugger_attach",R"({"pid":1234})"};plan=service.Prepare(ai::AgentEffectName::DebuggerAttach,attach);
  bool uncertain=false;try{service.Execute(ai::AgentEffectName::DebuggerAttach,attach,plan.opaque_payload);}catch(const ai::AgentEffectStateUncertain &){uncertain=true;}
  check(uncertain);
}
