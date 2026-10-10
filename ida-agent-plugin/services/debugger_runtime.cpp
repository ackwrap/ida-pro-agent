#include "debugger_service.hpp"

#include "debugger_internal.hpp"

#include <dbg.hpp>
#include <name.hpp>

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <unordered_set>

namespace ida_agent::services
{
namespace
{
constexpr int kMaxThreads = 1024;
constexpr int kMaxRegisters = 4096;
constexpr std::size_t kMaxRegisterValues = 65536;

std::string Hex(const void *data, std::size_t size)
{
  const auto *bytes = static_cast<const unsigned char *>(data);
  std::ostringstream output;
  output << std::hex << std::setfill('0');
  for ( std::size_t index = 0; index < size; ++index )
    output << std::setw(2) << static_cast<unsigned>(bytes[index]);
  return output.str();
}

std::string RegisterText(const regval_t &value)
{
  if ( value.rvtype == RVT_UNAVAILABLE )
    return "unavailable";
  if ( value.rvtype == RVT_INT )
  {
    std::ostringstream output;
    output << "0x" << std::hex << value.ival;
    return output.str();
  }
  return Hex(value.get_data(), value.get_data_size());
}

std::optional<std::vector<unsigned char>> DecodeHex(std::string_view value)
{
  if ( value.empty() || value.size() % 2 != 0 || value.size() > 131072 )
    return std::nullopt;
  std::vector<unsigned char> result;
  result.reserve(value.size() / 2);
  for ( std::size_t index = 0; index < value.size(); index += 2 )
  {
    unsigned byte = 0;
    std::istringstream input(std::string(value.substr(index, 2)));
    input >> std::hex >> byte;
    if ( input.fail() || !input.eof() )
      return std::nullopt;
    result.push_back(static_cast<unsigned char>(byte));
  }
  return result;
}

std::optional<thid_t> ThreadId(std::int64_t value)
{
  if ( value <= 0 )
    return std::nullopt;
  const thid_t tid = static_cast<thid_t>(value);
  if ( tid == NO_THREAD || static_cast<std::int64_t>(tid) != value )
    return std::nullopt;
  return tid;
}

DebuggerStatus EnumerateThreads(std::vector<thid_t> *threads)
{
  const int count = get_thread_qty();
  if ( count <= 0 )
    return DebuggerStatus::NotFound;
  if ( count > kMaxThreads )
    return DebuggerStatus::OutputLimit;
  threads->reserve(static_cast<std::size_t>(count));
  for ( int index = 0; index < count; ++index )
  {
    const thid_t tid = getn_thread(index);
    if ( tid == NO_THREAD )
      return DebuggerStatus::Failed;
    threads->push_back(tid);
  }
  return DebuggerStatus::Success;
}

int GeneralRegisterClassMask()
{
  if ( dbg->regclasses == nullptr )
    return 0;
  for ( int index = 0; index < 8 && dbg->regclasses[index] != nullptr; ++index )
  {
    const std::string name = detail::Lower(dbg->regclasses[index]);
    if ( name.find("general") != std::string::npos || name == "integer" )
      return 1 << index;
  }
  return 0;
}

bool KnownGeneralPurposeRegister(const register_info_t &info)
{
  static const std::unordered_set<std::string> names{
      "EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP",
      "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "RIP",
      "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
      "PC", "SP", "FP", "LR",
  };
  if ( (info.flags & (REGISTER_IP | REGISTER_SP | REGISTER_FP)) != 0 )
    return true;
  if ( info.name == nullptr )
    return false;
  const std::string name = info.name;
  if ( names.find(name) != names.end() )
    return true;
  if ( name.size() >= 2 && (name[0] == 'R' || name[0] == 'X' || name[0] == 'W') )
    return std::all_of(name.begin() + 1, name.end(), [](unsigned char ch) { return std::isdigit(ch) != 0; });
  return false;
}

std::string ModuleName(ea_t address)
{
  modinfo_t module;
  if ( address == BADADDR || !get_module_info(address, &module) )
    return "<unknown>";
  const std::string path = module.name.c_str();
  const std::size_t separator = path.find_last_of("/\\");
  return separator == std::string::npos ? path : path.substr(separator + 1);
}

std::string SymbolName(ea_t address)
{
  if ( address == BADADDR )
    return "<unnamed>";
  qstring name;
  constexpr int flags = GNCN_NOCOLOR | GNCN_NOLABEL | GNCN_NOSEG | GNCN_PREFDBG;
  if ( get_nice_colored_name(&name, address, flags) <= 0 || name.empty() )
    return "<unnamed>";
  return name.c_str();
}
} // namespace

RegistersOutcome DebuggerService::Registers(const RegisterRequest &request) const
{
  if ( !detail::Available() )
    return {DebuggerStatus::Unavailable, std::nullopt};
  if ( get_process_state() != DSTATE_SUSP )
    return {DebuggerStatus::NotSuspended, std::nullopt};
  if ( request.thread_mode != "current" && request.thread_mode != "specified" && request.thread_mode != "all" )
    return {DebuggerStatus::InvalidArgument, std::nullopt};
  if ( request.register_mode != "all" && request.register_mode != "named" && request.register_mode != "general-purpose" )
    return {DebuggerStatus::InvalidArgument, std::nullopt};
  if ( (request.thread_mode == "specified") != !request.thread_ids.empty()
    || (request.register_mode == "named") != !request.names.empty() )
    return {DebuggerStatus::InvalidArgument, std::nullopt};

  std::vector<thid_t> available_threads;
  const DebuggerStatus thread_status = EnumerateThreads(&available_threads);
  if ( thread_status != DebuggerStatus::Success )
    return {thread_status, std::nullopt};
  std::vector<thid_t> selected_threads;
  if ( request.thread_mode == "current" )
  {
    const thid_t current = get_current_thread();
    if ( current == NO_THREAD || std::find(available_threads.begin(), available_threads.end(), current) == available_threads.end() )
      return {DebuggerStatus::NotFound, std::nullopt};
    selected_threads.push_back(current);
  }
  else if ( request.thread_mode == "all" )
  {
    selected_threads = available_threads;
  }
  else
  {
    selected_threads.reserve(request.thread_ids.size());
    for ( const std::int64_t value : request.thread_ids )
    {
      const std::optional<thid_t> tid = ThreadId(value);
      if ( !tid )
        return {DebuggerStatus::InvalidArgument, std::nullopt};
      if ( std::find(available_threads.begin(), available_threads.end(), *tid) == available_threads.end() )
        return {DebuggerStatus::NotFound, std::nullopt};
      selected_threads.push_back(*tid);
    }
  }

  if ( dbg->registers == nullptr || dbg->nregisters <= 0 )
    return {DebuggerStatus::Unavailable, std::nullopt};
  if ( dbg->nregisters > kMaxRegisters
    || selected_threads.size() * static_cast<std::size_t>(dbg->nregisters) > kMaxRegisterValues )
    return {DebuggerStatus::OutputLimit, std::nullopt};

  std::unordered_set<std::string> requested_names(request.names.begin(), request.names.end());
  std::vector<int> register_indexes;
  int class_mask = 0;
  const int general_class_mask = request.register_mode == "general-purpose" ? GeneralRegisterClassMask() : 0;
  for ( int index = 0; index < dbg->nregisters; ++index )
  {
    const register_info_t &info = dbg->regs(index);
    if ( info.name == nullptr )
      return {DebuggerStatus::Failed, std::nullopt};
    const bool selected = request.register_mode == "all"
      || (request.register_mode == "named" && requested_names.erase(info.name) != 0)
      || (request.register_mode == "general-purpose"
          && ((general_class_mask != 0 && (info.register_class_mask & general_class_mask) != 0)
              || KnownGeneralPurposeRegister(info)));
    if ( selected )
    {
      register_indexes.push_back(index);
      class_mask |= info.register_class_mask;
    }
  }
  if ( !requested_names.empty() )
    return {DebuggerStatus::InvalidArgument, std::nullopt};
  if ( register_indexes.empty() )
    return {DebuggerStatus::NotFound, std::nullopt};

  std::vector<ThreadRegisters> result;
  result.reserve(selected_threads.size());
  for ( const thid_t tid : selected_threads )
  {
    regvals_t values;
    values.resize(static_cast<std::size_t>(dbg->nregisters));
    if ( get_reg_vals(tid, class_mask == 0 ? -1 : class_mask, values.begin()) <= 0 )
      return {DebuggerStatus::Failed, std::nullopt};
    ThreadRegisters thread{static_cast<std::int64_t>(tid), {}};
    thread.registers.reserve(register_indexes.size());
    for ( const int index : register_indexes )
      thread.registers.push_back({dbg->regs(index).name, RegisterText(values[index])});
    result.push_back(std::move(thread));
  }
  return {DebuggerStatus::Success, std::move(result)};
}

StackTraceOutcome DebuggerService::StackTrace(std::optional<std::int64_t> thread_id, std::uint32_t limit) const
{
  if ( !detail::Available() )
    return {DebuggerStatus::Unavailable, std::nullopt};
  if ( get_process_state() != DSTATE_SUSP )
    return {DebuggerStatus::NotSuspended, std::nullopt};
  if ( limit == 0 || limit > 1000 )
    return {DebuggerStatus::InvalidArgument, std::nullopt};

  std::vector<thid_t> threads;
  const DebuggerStatus thread_status = EnumerateThreads(&threads);
  if ( thread_status != DebuggerStatus::Success )
    return {thread_status, std::nullopt};
  thid_t tid = get_current_thread();
  if ( thread_id )
  {
    const std::optional<thid_t> converted = ThreadId(*thread_id);
    if ( !converted )
      return {DebuggerStatus::InvalidArgument, std::nullopt};
    tid = *converted;
  }
  if ( tid == NO_THREAD || std::find(threads.begin(), threads.end(), tid) == threads.end() )
    return {DebuggerStatus::NotFound, std::nullopt};

  call_stack_t stack;
  if ( !collect_stack_trace(tid, &stack) )
    return {DebuggerStatus::Failed, std::nullopt};
  std::vector<StackTraceFrame> result;
  result.reserve(std::min<std::size_t>(stack.size(), limit));
  for ( std::size_t index = 0; index < stack.size() && index < limit; ++index )
  {
    const call_stack_info_t &frame = stack[index];
    result.push_back({
        static_cast<std::uint64_t>(frame.callea),
        static_cast<std::uint64_t>(frame.funcea),
        static_cast<std::uint64_t>(frame.fp),
        frame.funcok,
        ModuleName(frame.callea),
        SymbolName(frame.callea),
    });
  }
  return {DebuggerStatus::Success, std::move(result)};
}

DebuggerMemoryOutcome DebuggerService::ReadMemory(std::uint64_t address, std::uint32_t length) const
{
  if ( !detail::Available() )
    return {DebuggerStatus::Unavailable, std::nullopt};
  if ( get_process_state() != DSTATE_SUSP )
    return {DebuggerStatus::NotSuspended, std::nullopt};
  const ea_t ea = static_cast<ea_t>(address);
  if ( static_cast<std::uint64_t>(ea) != address || ea == BADADDR )
    return {DebuggerStatus::InvalidAddress, std::nullopt};
  if ( length == 0 || length > 65536 )
    return {DebuggerStatus::InvalidArgument, std::nullopt};
  if ( ea > BADADDR - static_cast<ea_t>(length - 1) )
    return {DebuggerStatus::InvalidAddress, std::nullopt};
  std::vector<unsigned char> bytes(length);
  if ( read_dbg_memory(ea, bytes.data(), bytes.size()) != static_cast<ssize_t>(bytes.size()) )
    return {DebuggerStatus::Failed, std::nullopt};
  return {DebuggerStatus::Success, DebuggerMemory{address, Hex(bytes.data(), bytes.size())}};
}

DebuggerActionOutcome DebuggerService::WriteMemory(std::uint64_t address, std::string_view bytes) const
{
  if ( !detail::Available() )
    return {DebuggerStatus::Unavailable, std::nullopt};
  if ( get_process_state() != DSTATE_SUSP )
    return {DebuggerStatus::NotSuspended, std::nullopt};
  const ea_t ea = static_cast<ea_t>(address);
  if ( static_cast<std::uint64_t>(ea) != address || ea == BADADDR )
    return {DebuggerStatus::InvalidAddress, std::nullopt};
  const auto decoded = DecodeHex(bytes);
  if ( !decoded )
    return {DebuggerStatus::InvalidArgument, std::nullopt};
  if ( ea > BADADDR - static_cast<ea_t>(decoded->size() - 1) )
    return {DebuggerStatus::InvalidAddress, std::nullopt};
  return detail::Action(write_dbg_memory(ea, decoded->data(), decoded->size()) == static_cast<ssize_t>(decoded->size()));
}
} // namespace ida_agent::services
