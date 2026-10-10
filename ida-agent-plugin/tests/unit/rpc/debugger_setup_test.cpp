#include "../../../services/debugger_setup.hpp"
#include "test_support.hpp"
#include <fstream>
#include <iostream>
int main() try
{
  using namespace ida_agent::services;
  using Json = nlohmann::json;
  std::ifstream stream(std::string(IDA_AGENT_PROTOCOL_TESTDATA_DIR) + "/debugger-setup-cases.json");
  const auto cases = Json::parse(stream);
  for ( const auto &item : cases )
  {
    const auto &p = item.at("params"); const auto name = item.at("method").get<std::string>();
    bool valid = false;
    if ( name == "select" ) valid = ParseDebuggerSelect(p).has_value();
    else if ( name == "configure" ) valid = ParseDebuggerConfigure(p).has_value();
    else if ( name == "attach" ) valid = ParseDebuggerAttach(p).has_value();
    else if ( name == "processes" ) valid = ParseDebuggerProcesses(p).has_value();
    Require(valid == item.at("valid").get<bool>(), "debugger request fixture mismatch: " + item.dump());
  }
  for ( const auto action : {"select", "configure", "attach", "processes"} )
  {
    Require(DebuggerSetupStateAllows(action, false, false), "idle operation rejected");
    Require(!DebuggerSetupStateAllows(action, true, false), "running operation accepted");
    Require(!DebuggerSetupStateAllows(action, true, true), "suspended operation accepted");
  }
  Require(DebuggerSetupStateAllows("suspend", true, false), "running pause rejected");
  Require(!DebuggerSetupStateAllows("suspend", false, false), "idle pause accepted");
  Require(!DebuggerSetupStateAllows("suspend", true, true), "paused pause accepted");
  Require(DebuggerSetupStateAllows("detach", true, true), "paused detach rejected");
  Require(!DebuggerSetupStateAllows("detach", true, false), "running detach accepted");
  Require(!DebuggerSetupStateAllows("detach", false, false), "idle detach accepted");
  const auto clear = ParseDebuggerConfigure(Json{{"password", ""}});
  Require(clear && clear->password && clear->password->empty() && !clear->host && !clear->port, "clear/omit distinction lost");
  Require(!ParseDebuggerConfigure(Json{{"host", std::string(1025, 'a')}}), "host byte bound omitted");
  return 0;
}
catch ( const std::exception &e ) { std::cerr << e.what() << '\n'; return 1; }
