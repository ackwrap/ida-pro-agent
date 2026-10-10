#include "services/semantic_analysis/callers.hpp"
#include <iostream>
#include <fstream>
#include <map>
#include <stdexcept>
using namespace ida_agent::services;
using namespace ida_agent::services::semantic;
using Json = nlohmann::json;
namespace
{
void Check(bool value, const char *message) { if (!value) throw std::runtime_error(message); }
Snapshot Sample(std::uint64_t entry, std::uint64_t call, std::uint64_t callee, bool parameter, const char *value = "0x2a")
{
  Snapshot s; s.entry_address = entry; s.signature = "test_abi";
  s.parameters = {{"register", 1, 8}}; s.blocks.resize(1);
  Instruction i; i.call = true; i.address = call; i.callee = callee; i.signature = "test_abi";
  Value v; v.bits = 64; v.kind = parameter ? "location" : "constant";
  v.location = s.parameters[0]; v.literal = value; i.arguments = {v};
  i.argument_types = {"unsigned __int64"};
  s.blocks[0].instructions.push_back(i); return s;
}
bool Reason(const Json &j, const char *reason)
{
  for (const auto &b : j["boundaries"]) if (b["reason"] == reason) return true;
  return false;
}
}
int main()
{
  try
  {
    std::map<std::uint64_t, Snapshot> snapshots{{0x1010, Sample(0x1000, 0x1010, 0x9000, true)},
        {0x2010, Sample(0x2000, 0x2010, 0x1000, true)}, {0x3010, Sample(0x3000, 0x3010, 0x2000, false)},
        {0x4010, Sample(0x4000, 0x4010, 0x1000, false, "0x63")}};
    std::map<std::uint64_t, std::vector<std::uint64_t>> callers{{0x1000, {0x2010, 0x4010}}, {0x2000, {0x3010}}};
    CallersProvider p;
    p.load = [&](auto address, auto) { return SnapshotResult{QueryStatus::Success, std::make_shared<Snapshot>(snapshots.at(address)), 1}; };
    p.callers = [&](auto entry, auto limit, auto) {
      CallerSites out; out.addresses = callers[entry]; out.work = 1;
      if (out.addresses.size() > limit) { out.addresses.resize(limit); out.truncated = true; }
      return out;
    };
    CallersRequest r; r.call_address = 0x1010;
    auto run = [&]() { auto out = TraceCallers(r, p); Check(out.status == QueryStatus::Success, "trace failed"); return out.value; };
    auto out = run();
    Check(out["contexts"].size() == 4 && out["links"].size() == 3, "two-hop and multiple callers");
    Check(out["contexts"][2]["trace"]["nodes"][0]["value"] == "0x2a", "upstream constant missing");
    Check(out["contexts"][3]["trace"]["nodes"][0]["value"] == "0x63", "caller contexts were merged");
    Check(out["status"] == "partial" && !out["truncated"].get<bool>(), "unknown callers must remain explicit");
    r.max_depth = 1; Check(Reason(run(), "depth_budget"), "depth budget"); r.max_depth = 2;
    r.max_contexts = 1; out = run(); Check(out["contexts"].size() == 1 && Reason(out, "context_budget"), "context budget"); r.max_contexts = 16;
    r.max_callers = 1; Check(Reason(run(), "caller_budget"), "caller fanout budget"); r.max_callers = 8;
    r.max_nodes = 1; out = run(); Check(out["totalNodes"] == 1 && out["truncated"].get<bool>(), "global node budget"); r.max_nodes = 1000;
    r.max_work = 1; out = run(); Check(out["visitedWork"] == 1 && out["truncated"].get<bool>(), "global work budget"); r.max_work = 100000;
    snapshots[0x2010].blocks[0].instructions[0].signature = "wrong_abi";
    Check(Reason(run(), "prototype_mismatch"), "ABI mismatch was linked");
    snapshots[0x2010].blocks[0].instructions[0].signature = "test_abi";
    snapshots[0x2010].entry_address = 0x1000;
    Check(Reason(run(), "recursive_call"), "recursion boundary"); snapshots[0x2010].entry_address = 0x2000;
    snapshots[0x1000] = {};
    snapshots[0x1010].signature.clear(); Check(Reason(run(), "parameter_abi_unavailable"), "unknown ABI");
    snapshots[0x1010].signature = "test_abi";
    callers[0x1000].clear(); Check(Reason(run(), "no_known_callers"), "no callers boundary");
    r.call_address = 0x3010; out = run(); Check(out["status"] == "complete" && out["contexts"].size() == 1, "constant should stop locally");
    auto params = Json{{"callAddress", "0x1010"}, {"argumentIndex", 0}, {"maxDepth", 0}};
    Check(ParseCallersRequest(params).max_depth == 0, "explicit zero depth");
    for (const auto &bad : {"maxDepth", "maxContexts", "maxCallers", "maxNodes", "maxWork", "unknown"})
    {
      auto invalid = params; invalid[bad] = 1000001;
      bool rejected = false;
      try { ParseCallersRequest(invalid); } catch (const std::invalid_argument &) { rejected = true; }
      Check(rejected, "invalid bound accepted");
    }
    std::ifstream request_file(std::string(IDA_AGENT_PROTOCOL_TESTDATA_DIR) + "/valid/request-analysis-trace-argument-callers.json");
    std::ifstream response_file(std::string(IDA_AGENT_PROTOCOL_TESTDATA_DIR) + "/valid/response-analysis-trace-argument-callers.json");
    Json fixture_request, fixture_response; request_file >> fixture_request; response_file >> fixture_response;
    r = ParseCallersRequest(fixture_request["params"]);
    snapshots[0x1020] = Sample(0x1000, 0x1020, 0x9000, true);
    snapshots[0x2020] = Sample(0x2000, 0x2020, 0x1000, false, "0xffffffffffffffff");
    callers[0x1000] = {0x2020};
    out = run();
    auto expected = fixture_response["result"];
    expected["visitedWork"] = out["visitedWork"];
    for (std::size_t i = 0; i < out["contexts"].size(); ++i)
      expected["contexts"][i]["trace"]["visitedStates"] = out["contexts"][i]["trace"]["visitedStates"];
    Check(out == expected, "shared caller response fixture diverged");
    auto load = p.load;
    int attempts = 0;
    p.load = [&](auto address, auto budget) {
      ++attempts;
      return address == r.call_address ? load(address, budget) : SnapshotResult{QueryStatus::DecompileFailed, {}, 0};
    };
    callers[0x1000] = {0x2020, 0x3010, 0x4010}; r.max_contexts = 2;
    out = run();
    Check(attempts == 2 && Reason(out, "context_budget"), "failed SDK calls bypassed context budget");
    std::cout << "caller tracing tests passed\n";
  }
  catch (const std::exception &e) { std::cerr << e.what() << '\n'; return 1; }
}
