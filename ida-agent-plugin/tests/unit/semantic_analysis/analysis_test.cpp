#include "services/semantic_analysis/model.hpp"
#include "services/semantic_analysis/request.hpp"
#include <fstream>
#include <iostream>
#include <stdexcept>

using namespace ida_agent::services::semantic;
using Json = nlohmann::json;
void Check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
Location Reg(std::uint64_t offset = 1, std::uint32_t bytes = 8) { return {"register", offset, bytes}; }
Value Read(Location loc = Reg()) { Value v; v.kind = "location"; v.bits = loc.bytes * 8; v.location = loc; return v; }
Value Number(const char *n) { Value v; v.kind = "constant"; v.bits = 64; v.literal = n; return v; }
Instruction Call(Value arg = Read()) { Instruction i; i.address = 0x1020; i.call = true; i.arguments = {arg}; return i; }
Snapshot Checked()
{
  Snapshot s; s.entry_address = 0x1000; s.blocks.resize(4); s.parameters = {Reg()};
  s.blocks[0].successors = {1, 2};
  Instruction branch; branch.address = 0x1004;
  Value condition; condition.kind = "operation"; condition.operation = "unsigned_gt";
  condition.bits = 64; condition.inputs = {Read(), Number("0x40")};
  branch.condition = condition; branch.true_block = 1; branch.false_block = 2;
  s.blocks[0].instructions.push_back(branch);
  s.blocks[1].successors = {3};
  s.blocks[2].instructions.push_back(Call()); s.blocks[2].successors = {3};
  return s;
}
int main()
{
  try
  {
    Request r; r.call_address = 0x1020;
    auto s = Checked(); auto result = Analyze(s, r, true);
    Check(result["guards"][0]["requiredBranch"] == "false", "early return must require false branch");
    Check(result["guards"][0]["valueRelation"] == "same_value", "parameter identity");
    s.blocks[1].successors = {2}; result = Analyze(s, r, true);
    Check(result["guards"][0]["requiredBranch"] == "neither", "diamond must not claim branch protection");
    s = Checked(); Instruction overwrite; overwrite.address = 0x1010; overwrite.destination = Reg(); overwrite.value = Number("0x100");
    s.blocks[2].instructions.insert(s.blocks[2].instructions.begin(), overwrite); result = Analyze(s, r, true);
    Check(result["guards"][0]["valueRelation"] == "unrelated", "old value must not check replacement");
    s = Checked(); Value cast; cast.kind = "operation"; cast.operation = "zero_extend"; cast.bits = 64; cast.inputs = {Read(Reg(1,4))};
    s.parameters = {Reg(1,4)}; s.blocks[0].instructions[0].condition->inputs[0] = Read(Reg(1,4));
    s.blocks[2].instructions[0] = Call(cast); result = Analyze(s, r, true);
    Check(result["guards"][0]["valueRelation"] == "derived_value", "cast must preserve derived relation");
    s = Checked(); s.blocks[1].successors = {2}; overwrite.value = Number("0xffffffffffffffff");
    s.blocks[1].instructions.push_back(overwrite); result = Analyze(s, r, false);
    Check(result["nodes"][result["root"].get<int>()]["kind"] == "merge", "multiple reaching definitions");
    Check(result.dump().find("0xffffffffffffffff") != std::string::npos, "64-bit constant precision");
    s = Checked(); overwrite.destination = Reg(1,4); s.blocks[2].instructions.insert(s.blocks[2].instructions.begin(), overwrite);
    result = Analyze(s, r, false); Check(result["status"] == "partial", "partial writes require unknown boundary");
    s = Checked(); s.blocks[2].successors = {0}; result = Analyze(s, r, true);
    Check(result["status"] == "partial", "loop must terminate conservatively");
    s = Checked(); s.cfg_complete = false; result = Analyze(s, r, true);
    Check(result["guards"][0]["requiredBranch"] == "unknown", "incomplete CFG cannot prove a branch");
    s = Checked(); s.blocks[2].instructions[0] = Call(Read(Reg(1,4)));
    result = Analyze(s, r, true);
    Check(result["guards"][0]["valueRelation"] == "derived_value", "low bytes must retain the wider parameter dependency");
    Check(result["nodes"][result["root"].get<int>()]["address"].is_null(), "synthetic low-byte projection cannot fabricate an address");
    s.little_endian = false; result = Analyze(s, r, true);
    Check(result["status"] == "partial", "unsupported endian projection must remain uncertain");
    s = Checked(); Instruction effect; effect.address = 0x1010; effect.clobbers = {Reg()};
    s.blocks[2].instructions.insert(s.blocks[2].instructions.begin(), effect);
    result = Analyze(s, r, true);
    Check(result["guards"][0]["valueRelation"] == "unknown", "clobbered argument relation cannot be called unrelated");
    s = Checked(); Location stack{"stack", 32, 8}; s.parameters = {stack};
    s.blocks[0].instructions[0].condition->inputs[0] = Read(stack);
    s.blocks[2].instructions[0] = Call(Read(stack)); effect.clobbers.clear(); effect.memory_barrier = true;
    s.blocks[2].instructions.insert(s.blocks[2].instructions.begin(), effect);
    result = Analyze(s, r, true);
    Check(result["status"] == "partial" && result["guards"][0]["valueRelation"] == "unknown", "memory side effects must invalidate stack evidence");
    s = Checked(); auto late = s.blocks[0].instructions[0];
    s.blocks[0].instructions.clear(); s.blocks[0].successors = {2};
    s.blocks[2].instructions.push_back(late); s.blocks[2].successors = {1, 3};
    result = Analyze(s, r, true);
    Check(result["guards"].empty(), "conditions after the call cannot protect that invocation");
    r.max_work = 1; result = Analyze(Checked(), r, true);
    Check(result["truncated"] && result["status"] == "partial", "work budget must report partial output");
    r.max_work = 20000; r.max_nodes = 1; result = Analyze(Checked(), r, true);
    Check(result["truncated"], "node budget");
    r.max_nodes = 200; r.argument_index = 1; bool rejected = false;
    try { Analyze(Checked(), r, false); } catch (const std::invalid_argument &) { rejected = true; }
    Check(rejected, "invalid argument index");
    for (const auto &bad : {Json{{"callAddress", "0x1020"}}, Json{{"callAddress", "0x1020"}, {"argumentIndex", -1}},
        Json{{"callAddress", "0x1020"}, {"argumentIndex", 0}, {"extra", true}}})
    {
      rejected = false; try { ParseRequest(bad); } catch (const std::invalid_argument &) { rejected = true; }
      Check(rejected, "strict request fields");
    }
    std::cout << "semantic analysis tests passed\n";
    for (const char *method : {"trace-argument", "guard-evidence"})
    {
      const std::string base = std::string(IDA_AGENT_PROTOCOL_TESTDATA_DIR) + "/valid/";
      std::ifstream request_file(base + "request-analysis-" + method + ".json");
      Json wire; request_file >> wire;
      auto params = ParseRequest(wire.at("params"));
      auto actual = Analyze(Checked(), params, std::string(method) == "guard-evidence");
      std::ifstream response_file(base + "response-analysis-" + method + ".json");
      Json expected; response_file >> expected;
      Check(actual["model"] == expected["result"]["model"] && actual["argumentIndex"] == expected["result"]["argumentIndex"], "shared wire contract");
    }
    return 0;
  }
  catch (const std::exception &error) { std::cerr << error.what() << '\n'; return 1; }
}
