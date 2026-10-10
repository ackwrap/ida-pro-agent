#pragma once

#include <nlohmann/json.hpp>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ida_agent::services::semantic
{
struct Request
{
  std::uint64_t call_address = 0;
  std::uint32_t argument_index = 0;
  std::uint32_t max_nodes = 200;
  std::uint32_t max_work = 20000;
  std::uint32_t max_guards = 32;
};

struct Location
{
  std::string space;
  std::uint64_t offset = 0;
  std::uint32_t bytes = 0;
  bool operator==(const Location &other) const;
  bool Overlaps(const Location &other) const;
  std::string Key() const;
};

struct Value
{
  std::string kind = "unknown";
  std::string operation;
  std::uint32_t bits = 0;
  std::string literal;
  bool synthetic = false;
  Location location;
  std::vector<Value> inputs;
};

struct Instruction
{
  std::optional<std::uint64_t> callee;
  std::string signature;
  std::optional<std::uint64_t> address;
  std::optional<Location> destination;
  Value value;
  std::vector<Location> clobbers;
  bool memory_barrier = false;
  bool register_barrier = false;
  bool call = false;
  std::vector<Value> arguments;
  std::vector<std::string> argument_types;
  std::optional<Value> condition;
  int true_block = -1;
  int false_block = -1;
};

struct Block
{
  std::vector<Instruction> instructions;
  std::vector<int> successors;
};

struct Snapshot
{
  // Nonempty only when recovered parameter positions agree with the IDB ABI.
  std::string signature;
  std::uint64_t entry_address = 0;
  std::vector<Block> blocks;
  std::vector<Location> parameters;
  bool little_endian = true;
  bool cfg_complete = true;
  std::vector<std::string> limitations;
};

// The core owns all its data and can be tested without loading IDA.
nlohmann::json Analyze(const Snapshot &snapshot, const Request &request, bool guards);
bool ValidRequest(const Request &request);
std::string Hex(std::uint64_t value);
}
