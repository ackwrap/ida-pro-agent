#pragma once
#include "query_result.hpp"
#include "debugger_setup.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ida_agent::services
{
enum class DebuggerStatus { Success, Unavailable, AlreadyRunning, NotRunning, NotSuspended, InvalidAddress, InvalidArgument, NotFound, Failed, StateUncertain, OutputLimit };
struct DebuggerInfo
{
  std::string state;
  bool running;
  bool suspended;
  std::optional<std::uint64_t> instruction_pointer;
  std::optional<std::int64_t> thread_id;
};
struct BreakpointInfo
{
  std::uint64_t address;
  bool enabled;
  std::string type;
  std::uint32_t size;
  std::uint32_t pass_count;
  bool low_level;
  std::string condition;
  std::optional<std::string> condition_language;
  bool compiled;
  bool active;
};
struct BreakpointMutation
{
  std::optional<bool> enabled;
  std::optional<std::string> condition;
  std::optional<std::string> type;
  std::optional<std::uint32_t> size;
  std::optional<std::string> language;
  std::optional<bool> low_level;
  std::optional<std::uint32_t> pass_count;
};
struct RegisterValue { std::string name; std::string value; };
struct ThreadRegisters { std::int64_t thread_id; std::vector<RegisterValue> registers; };
struct RegisterRequest
{
  std::string thread_mode;
  std::vector<std::int64_t> thread_ids;
  std::string register_mode;
  std::vector<std::string> names;
};
struct StackTraceFrame
{
  std::uint64_t call_address;
  std::uint64_t function_address;
  std::uint64_t frame_pointer;
  bool function_known;
  std::string module;
  std::string symbol;
};
struct DebuggerMemory { std::uint64_t address; std::string bytes; };
struct DebuggerAction
{
  bool accepted;
  std::string state;
  bool running;
  bool suspended;
  std::optional<std::uint64_t> instruction_pointer;
  std::optional<std::int64_t> thread_id;
};
template <typename Result> struct DebuggerOutcome { DebuggerStatus status; std::optional<Result> result; };
using DebuggerInfoOutcome = DebuggerOutcome<DebuggerInfo>;
using BreakpointsOutcome = DebuggerOutcome<std::vector<BreakpointInfo>>;
using RegistersOutcome = DebuggerOutcome<std::vector<ThreadRegisters>>;
using StackTraceOutcome = DebuggerOutcome<std::vector<StackTraceFrame>>;
using DebuggerMemoryOutcome = DebuggerOutcome<DebuggerMemory>;
using DebuggerActionOutcome = DebuggerOutcome<DebuggerAction>;
using DebuggerSetupOutcome = DebuggerOutcome<nlohmann::json>;
inline nlohmann::json ToJson(const nlohmann::json &result) { return result; }

class DebuggerService
{
public:
  QueryResult DebuggerThreads(std::uint32_t limit, std::uint32_t cursor) const;
  QueryResult DebuggerModules(std::uint32_t limit, std::uint32_t cursor) const;
  DebuggerSetupOutcome Backends() const;
  DebuggerSetupOutcome Configuration() const;
  DebuggerSetupOutcome Processes(std::uint32_t limit) const;
  DebuggerActionOutcome Select(const DebuggerSelectRequest &request) const;
  DebuggerActionOutcome Configure(const DebuggerConfigureRequest &request) const;
  DebuggerActionOutcome Attach(int pid) const;
  DebuggerActionOutcome Detach() const;
  DebuggerActionOutcome Suspend() const;
  DebuggerInfoOutcome Info() const;
  DebuggerActionOutcome Start() const;
  DebuggerActionOutcome Exit() const;
  DebuggerActionOutcome Control(std::string_view action, std::optional<std::uint64_t> address) const;
  BreakpointsOutcome Breakpoints() const;
  DebuggerActionOutcome Breakpoint(std::string_view action, std::uint64_t address, const BreakpointMutation &mutation) const;
  RegistersOutcome Registers(const RegisterRequest &request) const;
  StackTraceOutcome StackTrace(std::optional<std::int64_t> thread_id, std::uint32_t limit) const;
  DebuggerMemoryOutcome ReadMemory(std::uint64_t address, std::uint32_t length) const;
  DebuggerActionOutcome WriteMemory(std::uint64_t address, std::string_view bytes) const;
};

nlohmann::json ToJson(const DebuggerInfo &result);
nlohmann::json ToJson(const std::vector<BreakpointInfo> &result);
nlohmann::json ToJson(const std::vector<ThreadRegisters> &result);
nlohmann::json ToJson(const std::vector<StackTraceFrame> &result);
nlohmann::json ToJson(const DebuggerMemory &result);
nlohmann::json ToJson(const DebuggerAction &result);
} // namespace ida_agent::services
