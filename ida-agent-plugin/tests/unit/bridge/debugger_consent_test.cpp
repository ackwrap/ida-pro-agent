#include "debugger_consent.hpp"
#include "bridge.hpp"
#include <stdexcept>

namespace
{
void Require(bool condition) { if ( !condition ) throw std::runtime_error("debugger consent invariant failed"); }
}

int main()
{
  using Consent = ida_agent::bridge::DebuggerConsent;
  using Decision = Consent::Decision;
  Consent pipe;
  Require(pipe.Begin() == Decision::New);
  Require(pipe.Begin() == Decision::Pending); // A modal dialog must not spawn another.
  pipe.Complete(true);
  Require(pipe.Begin() == Decision::Allowed);
  Require(pipe.Begin() == Decision::Allowed); // A second client shares the Pipe grant.
  pipe.Complete(false);
  Require(pipe.Begin() == Decision::Allowed); // No late duplicate callback can revoke it.
  Consent other_pipe;
  Require(other_pipe.Begin() == Decision::New);
  other_pipe.Complete(false);
  Require(other_pipe.Begin() == Decision::Denied);
  Require(other_pipe.Begin() == Decision::Denied); // Denial does not repeatedly prompt.
  Consent recreated_pipe;
  Require(recreated_pipe.Begin() == Decision::New);
  bool loaded = false;
  int probes = 0;
  auto info = ida_agent::bridge::BuildInstanceInfoHandler({}, [&](std::uint32_t timeout) {
    Require(timeout == 5000);
    ++probes;
    return ida_agent::rpc::Capabilities{false, loaded, false, 64};
  });
  const ida_agent::rpc::Request request{std::string(ida_agent::rpc::ProtocolVersion),
      "req-1", "session-1", "instance.info", nlohmann::json::object(), 5000};
  Require(!std::get<nlohmann::json>(info(request))["capabilities"]["debugger"].get<bool>());
  loaded = true;
  Require(std::get<nlohmann::json>(info(request))["capabilities"]["debugger"].get<bool>());
  loaded = false;
  Require(!std::get<nlohmann::json>(info(request))["capabilities"]["debugger"].get<bool>());
  Require(probes == 3);
  auto invalid = request;
  invalid.params["unexpected"] = true;
  Require(std::holds_alternative<ida_agent::rpc::RpcError>(info(invalid)));
  Require(probes == 3);
}
