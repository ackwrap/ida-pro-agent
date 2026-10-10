#include "debugger_service.hpp"

#include "address.hpp"
#include "debugger_internal.hpp"

#include <dbg.hpp>

#include <algorithm>
#include <cctype>
#include <limits>

namespace ida_agent::services
{
namespace
{
std::string State(int state)
{
  if ( state == DSTATE_SUSP )
    return "suspended";
  if ( state == DSTATE_RUN )
    return "running";
  if ( state == DSTATE_NOTASK )
    return "not_running";
  return "unknown";
}

DebuggerInfo StateSnapshot()
{
  const int process_state = get_process_state();
  DebuggerInfo result{
      State(process_state),
      process_state == DSTATE_RUN,
      process_state == DSTATE_SUSP,
      std::nullopt,
      std::nullopt,
  };
  if ( result.suspended )
  {
    const thid_t tid = get_current_thread();
    if ( tid != NO_THREAD )
      result.thread_id = static_cast<std::int64_t>(tid);
    ea_t ip = BADADDR;
    if ( get_ip_val(&ip) && ip != BADADDR )
      result.instruction_pointer = static_cast<std::uint64_t>(ip);
  }
  return result;
}

std::optional<std::string> BreakpointLanguage(const bpt_t &bpt)
{
  const char *language = bpt.get_cnd_elang();
  if ( language == nullptr || *language == '\0' )
    return std::nullopt;
  return std::string(language);
}

BreakpointInfo CopyBreakpoint(const bpt_t &bpt)
{
  const int size = bpt.get_size();
  return {
      static_cast<std::uint64_t>(bpt.ea),
      bpt.enabled(),
      bpt.is_hwbpt() ? "hardware" : "software",
      size > 0 ? static_cast<std::uint32_t>(size) : 0,
      bpt.pass_count > 0 ? static_cast<std::uint32_t>(bpt.pass_count) : 0,
      bpt.is_low_level(),
      bpt.cndbody.c_str(),
      BreakpointLanguage(bpt),
      bpt.is_compiled(),
      bpt.is_active(),
  };
}

bool MutationEmpty(const BreakpointMutation &mutation)
{
  return !mutation.enabled && !mutation.condition && !mutation.type && !mutation.size
      && !mutation.language && !mutation.low_level && !mutation.pass_count;
}

bool ValidHardwareSize(std::uint32_t size)
{
  return size == 1 || size == 2 || size == 4 || size == 8;
}

std::string NormalizeLanguage(std::string language)
{
  const std::string lowered = detail::Lower(language);
  if ( lowered == "idc" )
    return "IDC";
  if ( lowered == "python" )
    return "Python";
  return language;
}

} // namespace

namespace detail
{
std::string Lower(std::string value)
{
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return value;
}

bool Available()
{
  return dbg != nullptr;
}

DebuggerActionOutcome Action(bool accepted)
{
  if ( !accepted )
    return {DebuggerStatus::Failed, std::nullopt};
  DebuggerInfo snapshot = StateSnapshot();
  return {
      DebuggerStatus::Success,
      DebuggerAction{
          true,
          std::move(snapshot.state),
          snapshot.running,
          snapshot.suspended,
          snapshot.instruction_pointer,
          snapshot.thread_id,
      },
  };
}
} // namespace detail

DebuggerInfoOutcome DebuggerService::Info() const
{
  if ( !detail::Available() )
    return {DebuggerStatus::Unavailable, std::nullopt};
  return {DebuggerStatus::Success, StateSnapshot()};
}

DebuggerActionOutcome DebuggerService::Start() const
{
  if ( !detail::Available() )
    return {DebuggerStatus::Unavailable, std::nullopt};
  if ( get_process_state() != DSTATE_NOTASK )
    return {DebuggerStatus::AlreadyRunning, std::nullopt};

  // start_process() is asynchronous: its positive result means the command was
  // accepted, not that a process-start/suspend notification has already arrived.
  return detail::Action(start_process() == 1);
}

DebuggerActionOutcome DebuggerService::Exit() const
{
  if ( !detail::Available() )
    return {DebuggerStatus::Unavailable, std::nullopt};
  if ( get_process_state() == DSTATE_NOTASK )
    return {DebuggerStatus::NotRunning, std::nullopt};
  return detail::Action(exit_process());
}

DebuggerActionOutcome DebuggerService::Control(std::string_view action, std::optional<std::uint64_t> address) const
{
  if ( !detail::Available() )
    return {DebuggerStatus::Unavailable, std::nullopt};
  const int state = get_process_state();
  if ( state == DSTATE_NOTASK )
    return {DebuggerStatus::NotRunning, std::nullopt};
  if ( state != DSTATE_SUSP )
    return {DebuggerStatus::NotSuspended, std::nullopt};
  if ( action == "continue" )
    return detail::Action(continue_process());
  if ( action == "step_into" )
    return detail::Action(step_into());
  if ( action == "step_over" )
    return detail::Action(step_over());
  if ( action == "step_until_return" )
    return detail::Action(step_until_ret());
  if ( action == "run_to" && address )
  {
    const ea_t ea = static_cast<ea_t>(*address);
    if ( static_cast<std::uint64_t>(ea) != *address || ea == BADADDR )
      return {DebuggerStatus::InvalidAddress, std::nullopt};
    return detail::Action(run_to(ea));
  }
  return {DebuggerStatus::InvalidArgument, std::nullopt};
}

BreakpointsOutcome DebuggerService::Breakpoints() const
{
  if ( !detail::Available() )
    return {DebuggerStatus::Unavailable, std::nullopt};
  const int count = get_bpt_qty();
  if ( count < 0 )
    return {DebuggerStatus::Failed, std::nullopt};
  if ( count > 1000 )
    return {DebuggerStatus::OutputLimit, std::nullopt};
  std::vector<BreakpointInfo> result;
  result.reserve(static_cast<std::size_t>(count));
  for ( int index = 0; index < count; ++index )
  {
    bpt_t bpt;
    if ( !getn_bpt(index, &bpt) )
      return {DebuggerStatus::Failed, std::nullopt};
    result.push_back(CopyBreakpoint(bpt));
  }
  std::sort(result.begin(), result.end(), [](const auto &left, const auto &right) {
    return left.address < right.address;
  });
  return {DebuggerStatus::Success, std::move(result)};
}

DebuggerActionOutcome DebuggerService::Breakpoint(
    std::string_view action,
    std::uint64_t address,
    const BreakpointMutation &mutation) const
{
  if ( !detail::Available() )
    return {DebuggerStatus::Unavailable, std::nullopt};
  const ea_t ea = static_cast<ea_t>(address);
  if ( static_cast<std::uint64_t>(ea) != address || ea == BADADDR )
    return {DebuggerStatus::InvalidAddress, std::nullopt};

  if ( action == "add" )
  {
    if ( mutation.enabled || mutation.condition || mutation.language || mutation.low_level || mutation.pass_count )
      return {DebuggerStatus::InvalidArgument, std::nullopt};
    const std::string type = mutation.type.value_or("software");
    if ( type != "software" && type != "hardware" )
      return {DebuggerStatus::InvalidArgument, std::nullopt};
    const std::uint32_t size = mutation.size.value_or(type == "hardware" ? 1U : 0U);
    if ( (type == "software" && size > 1) || (type == "hardware" && !ValidHardwareSize(size)) )
      return {DebuggerStatus::InvalidArgument, std::nullopt};
    const bpttype_t sdk_type = type == "hardware" ? BPT_EXEC : BPT_SOFT;
    if ( !add_bpt(ea, static_cast<asize_t>(size), sdk_type) )
      return {DebuggerStatus::Failed, std::nullopt};
    bpt_t added;
    if ( !get_bpt(ea, &added)
      || (type == "hardware") != added.is_hwbpt()
      || (type == "hardware" && added.get_size() != static_cast<int>(size)) )
      return {DebuggerStatus::Failed, std::nullopt};
    return detail::Action(true);
  }

  if ( action == "delete" )
  {
    if ( !MutationEmpty(mutation) )
      return {DebuggerStatus::InvalidArgument, std::nullopt};
    if ( !exist_bpt(ea) )
      return {DebuggerStatus::NotFound, std::nullopt};
    return detail::Action(del_bpt(ea));
  }

  if ( action == "toggle" )
  {
    if ( !mutation.enabled || mutation.condition || mutation.type || mutation.size
      || mutation.language || mutation.low_level || mutation.pass_count )
      return {DebuggerStatus::InvalidArgument, std::nullopt};
    if ( !exist_bpt(ea) )
      return {DebuggerStatus::NotFound, std::nullopt};
    return detail::Action(enable_bpt(ea, *mutation.enabled));
  }

  if ( action != "condition" || mutation.enabled || mutation.type || mutation.size
    || (!mutation.condition && !mutation.language && !mutation.low_level && !mutation.pass_count) )
    return {DebuggerStatus::InvalidArgument, std::nullopt};
  if ( mutation.condition && mutation.condition->size() > 4096 )
    return {DebuggerStatus::InvalidArgument, std::nullopt};
  if ( mutation.language && (mutation.language->empty() || mutation.language->size() > 128) )
    return {DebuggerStatus::InvalidArgument, std::nullopt};
  if ( mutation.pass_count && *mutation.pass_count > static_cast<std::uint32_t>(std::numeric_limits<int>::max()) )
    return {DebuggerStatus::InvalidArgument, std::nullopt};

  bpt_t bpt;
  if ( !get_bpt(ea, &bpt) )
    return {DebuggerStatus::NotFound, std::nullopt};
  const bpt_t original = bpt;
  const auto original_language = BreakpointLanguage(original);
  const auto restore = [&original, &original_language, ea]()
  {
    bpt_t saved = original;
    if ( !update_bpt(&saved) )
      return false;
    bpt_t restored;
    return get_bpt(ea, &restored)
        && std::string(restored.cndbody.c_str()) == std::string(original.cndbody.c_str())
        && BreakpointLanguage(restored) == original_language
        && restored.is_low_level() == original.is_low_level()
        && restored.pass_count == original.pass_count;
  };
  const auto failed = [&restore]() -> DebuggerActionOutcome
  {
    return {
        restore() ? DebuggerStatus::Failed : DebuggerStatus::StateUncertain,
        std::nullopt,
    };
  };
  const std::string desired_condition = mutation.condition.value_or(std::string(bpt.cndbody.c_str()));
  const std::optional<std::string> desired_language = mutation.language
    ? std::optional<std::string>(NormalizeLanguage(*mutation.language))
    : std::nullopt;
  const std::optional<std::string> current_language = BreakpointLanguage(bpt);
  if ( desired_language && current_language != desired_language )
  {
    if ( !bpt.cndbody.empty() )
    {
      bpt.cndbody.clear();
      if ( !update_bpt(&bpt) || !get_bpt(ea, &bpt) )
        return failed();
    }
    if ( !bpt.set_cnd_elang(desired_language->c_str()) || !update_bpt(&bpt) || !get_bpt(ea, &bpt) )
      return failed();
  }

  bpt.cndbody = desired_condition.c_str();
  if ( mutation.low_level )
  {
    if ( *mutation.low_level )
      bpt.flags |= BPT_LOWCND;
    else
      bpt.flags &= ~BPT_LOWCND;
  }
  if ( mutation.pass_count )
    bpt.pass_count = static_cast<int>(*mutation.pass_count);
  if ( !update_bpt(&bpt) )
    return failed();

  bpt_t updated;
  if ( !get_bpt(ea, &updated)
    || std::string(updated.cndbody.c_str()) != desired_condition
    || (mutation.low_level && updated.is_low_level() != *mutation.low_level)
    || (mutation.pass_count && updated.pass_count != static_cast<int>(*mutation.pass_count))
    || (desired_language && BreakpointLanguage(updated) != desired_language)
    || (!desired_condition.empty() && !updated.is_compiled()) )
  {
    return failed();
  }
  return detail::Action(true);
}

nlohmann::json ToJson(const DebuggerInfo &result)
{
  return {
      {"state", result.state},
      {"running", result.running},
      {"suspended", result.suspended},
      {"instructionPointer", result.instruction_pointer ? nlohmann::json(rpc::FormatAddress(*result.instruction_pointer)) : nlohmann::json(nullptr)},
      {"threadId", result.thread_id ? nlohmann::json(*result.thread_id) : nlohmann::json(nullptr)},
  };
}

nlohmann::json ToJson(const std::vector<BreakpointInfo> &result)
{
  nlohmann::json items = nlohmann::json::array();
  for ( const auto &value : result )
  {
    items.push_back({
        {"address", rpc::FormatAddress(value.address)},
        {"enabled", value.enabled},
        {"type", value.type},
        {"size", value.size},
        {"passCount", value.pass_count},
        {"lowLevel", value.low_level},
        {"condition", value.condition},
        {"conditionLanguage", value.condition_language ? nlohmann::json(*value.condition_language) : nlohmann::json(nullptr)},
        {"compiled", value.compiled},
        {"active", value.active},
    });
  }
  return {{"items", std::move(items)}};
}

nlohmann::json ToJson(const std::vector<ThreadRegisters> &result)
{
  nlohmann::json items = nlohmann::json::array();
  for ( const auto &thread : result )
  {
    nlohmann::json registers = nlohmann::json::array();
    for ( const auto &value : thread.registers )
      registers.push_back({{"name", value.name}, {"value", value.value}});
    items.push_back({{"threadId", thread.thread_id}, {"registers", std::move(registers)}});
  }
  return {{"items", std::move(items)}};
}

nlohmann::json ToJson(const std::vector<StackTraceFrame> &result)
{
  nlohmann::json items = nlohmann::json::array();
  for ( const auto &value : result )
  {
    items.push_back({
        {"callAddress", rpc::FormatAddress(value.call_address)},
        {"functionAddress", rpc::FormatAddress(value.function_address)},
        {"framePointer", rpc::FormatAddress(value.frame_pointer)},
        {"functionKnown", value.function_known},
        {"module", value.module},
        {"symbol", value.symbol},
    });
  }
  return {{"items", std::move(items)}};
}

nlohmann::json ToJson(const DebuggerMemory &result)
{
  return {{"address", rpc::FormatAddress(result.address)}, {"bytes", result.bytes}};
}

nlohmann::json ToJson(const DebuggerAction &result)
{
  return {
      {"accepted", result.accepted},
      {"state", result.state},
      {"running", result.running},
      {"suspended", result.suspended},
      {"instructionPointer", result.instruction_pointer ? nlohmann::json(rpc::FormatAddress(*result.instruction_pointer)) : nlohmann::json(nullptr)},
      {"threadId", result.thread_id ? nlohmann::json(*result.thread_id) : nlohmann::json(nullptr)},
  };
}
} // namespace ida_agent::services
