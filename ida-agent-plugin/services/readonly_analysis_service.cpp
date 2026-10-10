#include "readonly_analysis_service.hpp"

#include "address.hpp"

#include <auto.hpp>
#include <bytes.hpp>
#include <fixup.hpp>
#include <funcs.hpp>
#include <ida.hpp>
#include <lines.hpp>
#include <nalt.hpp>
#include <problems.hpp>
#include <tryblks.hpp>
#include <ua.hpp>
#include <xref.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <iomanip>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <tuple>
#include <vector>

namespace ida_agent::services
{
namespace
{

constexpr std::size_t MaxInstructionBytes = 4096;
constexpr std::size_t MaxInstructionTextBytes = 4096;
constexpr std::size_t MaxOperandTextBytes = 1024;
constexpr std::size_t MaxDescriptionBytes = 4096;
constexpr std::size_t MaxFunctionChunks = 1024;
constexpr std::size_t MaxSwitchCases = 4096;
constexpr std::size_t MaxTryBlocks = 1024;
constexpr std::size_t MaxTryRanges = 64;
constexpr std::size_t MaxHandlers = 64;

bool StableAddress(std::uint64_t value, ea_t *address)
{
  *address = static_cast<ea_t>(value);
  return static_cast<std::uint64_t>(*address) == value && *address != BADADDR;
}

std::string HexBytes(ea_t address, std::size_t size)
{
  std::vector<std::uint8_t> bytes(size);
  if ( get_bytes(bytes.data(), size, address) != static_cast<ssize_t>(size) )
    throw std::runtime_error("instruction bytes are unavailable");
  std::ostringstream encoded;
  encoded << std::hex << std::setfill('0');
  for ( std::uint8_t byte : bytes )
    encoded << std::setw(2) << static_cast<unsigned>(byte);
  return encoded.str();
}

const char *OperandTypeName(optype_t type)
{
  switch ( type )
  {
    case o_reg: return "register";
    case o_mem: return "memory";
    case o_phrase: return "phrase";
    case o_displ: return "displacement";
    case o_imm: return "immediate";
    case o_far: return "far_address";
    case o_near: return "near_address";
    default: return "processor_specific";
  }
}

const char *FixupTypeName(fixup_type_t type)
{
  switch ( type )
  {
    case FIXUP_OFF8: return "offset8";
    case FIXUP_OFF16: return "offset16";
    case FIXUP_SEG16: return "segment16";
    case FIXUP_PTR16: return "pointer16";
    case FIXUP_OFF32: return "offset32";
    case FIXUP_PTR32: return "pointer32";
    case FIXUP_HI8: return "high8";
    case FIXUP_HI16: return "high16";
    case FIXUP_LOW8: return "low8";
    case FIXUP_LOW16: return "low16";
    case FIXUP_OFF64: return "offset64";
    case FIXUP_OFF8S: return "signed_offset8";
    case FIXUP_OFF16S: return "signed_offset16";
    case FIXUP_OFF32S: return "signed_offset32";
    default: return is_fixup_custom(type) ? "custom" : "other";
  }
}

nlohmann::json FixupJson(ea_t source, const fixup_data_t &fixup)
{
  qstring ida_description;
  const char *raw = fixup.get_desc(&ida_description, source);
  std::string description = raw == nullptr ? std::string() : std::string(raw);
  if ( description.size() > MaxDescriptionBytes || !is_valid_utf8(description.c_str()) )
    throw std::length_error("fixup description exceeds the configured limit");
  const ea_t target = fixup.get_base() + fixup.off;
  return {
      {"source", rpc::FormatAddress(source)},
      {"target", rpc::FormatAddress(target)},
      {"type", FixupTypeName(fixup.get_type())},
      {"description", description},
      {"relative", fixup.has_base()},
      {"external", fixup.is_extdef()},
      {"unused", fixup.is_unused()},
      {"created", fixup.was_created()},
  };
}

nlohmann::json RangeJson(const range_t &range)
{
  return {
      {"start", rpc::FormatAddress(range.start_ea)},
      {"end", range.end_ea == BADADDR ? nlohmann::json(nullptr) : nlohmann::json(rpc::FormatAddress(range.end_ea))},
  };
}

template <typename Ranges>
nlohmann::json RangesJson(const Ranges &ranges)
{
  if ( ranges.size() > MaxTryRanges )
    throw std::length_error("exception range list exceeds the configured limit");
  nlohmann::json result = nlohmann::json::array();
  for ( const range_t &range : ranges )
    result.push_back(RangeJson(range));
  return result;
}

const char *AutoQueueName(atype_t type)
{
  switch ( type )
  {
    case AU_NONE: return "none";
    case AU_UNK: return "unknown";
    case AU_CODE: return "code";
    case AU_WEAK: return "weak_code";
    case AU_PROC: return "procedure";
    case AU_TAIL: return "tail";
    case AU_FCHUNK: return "function_chunk";
    case AU_USED: return "reanalyze";
    case AU_USD2: return "reanalyze_second_pass";
    case AU_TYPE: return "type";
    case AU_LIBF: return "signature";
    case AU_LBF2: return "signature_second_pass";
    case AU_LBF3: return "signature_third_pass";
    case AU_CHLB: return "signature_load";
    case AU_FINAL: return "final";
    default: return "other";
  }
}

const char *IdaStateName(idastate_t state)
{
  switch ( state )
  {
    case st_Ready: return "ready";
    case st_Think: return "thinking";
    case st_Waiting: return "waiting";
    case st_Work: return "busy";
    default: return "other";
  }
}

struct ProblemType
{
  const char *name;
  problist_id_t id;
};

constexpr std::array<ProblemType, 16> ProblemTypes{{
    {"no_base", PR_NOBASE}, {"no_name", PR_NONAME},
    {"no_forced_operand", PR_NOFOP}, {"no_comment", PR_NOCMT},
    {"no_xrefs", PR_NOXREFS}, {"jump_table", PR_JUMP},
    {"disassembly", PR_DISASM}, {"head", PR_HEAD},
    {"illegal_address", PR_ILLADDR}, {"many_lines", PR_MANYLINES},
    {"bad_stack", PR_BADSTACK}, {"attention", PR_ATTN},
    {"final_decision", PR_FINAL}, {"rolled_back", PR_ROLLED},
    {"flair_collision", PR_COLLISION}, {"flair_indecision", PR_DECIMP},
}};

std::optional<ProblemType> ParseProblemType(std::string_view name)
{
  for ( const ProblemType &type : ProblemTypes )
  {
    if ( name == type.name )
      return type;
  }
  return std::nullopt;
}

} // namespace

ReadonlyResult ReadonlyAnalysisService::InstructionGet(std::uint64_t address) const
{
  ea_t requested = BADADDR;
  if ( !StableAddress(address, &requested) || !is_mapped(requested) )
    return {ReadonlyStatus::InvalidAddress, {}};
  const ea_t head = get_item_head(requested);
  if ( head == BADADDR || !is_mapped(head) )
    return {ReadonlyStatus::InvalidAddress, {}};
  const ea_t end = get_item_end(head);
  if ( end == BADADDR || end <= head )
    throw std::runtime_error("item range is unavailable");
  const std::uint64_t size = end - head;
  const flags64_t flags = get_flags(head);
  const char *kind = is_code(flags) ? "code" : is_data(flags) ? "data" : "unknown";
  nlohmann::json result{
      {"requestedAddress", rpc::FormatAddress(requested)},
      {"address", rpc::FormatAddress(head)},
      {"end", rpc::FormatAddress(end)},
      {"size", size},
      {"kind", kind},
  };
  if ( !is_code(flags) )
    return {ReadonlyStatus::Success, std::move(result)};
  if ( size > MaxInstructionBytes )
    return {ReadonlyStatus::OutputLimit, {}};
  insn_t instruction;
  if ( decode_insn(&instruction, head) <= 0 || instruction.size == 0 )
    throw std::runtime_error("code item cannot be decoded");
  qstring ida_mnemonic;
  print_insn_mnem(&ida_mnemonic, head);
  qstring generated;
  if ( !generate_disasm_line(&generated, head, GENDSM_REMOVE_TAGS) )
    throw std::runtime_error("instruction text is unavailable");
  const std::string mnemonic(ida_mnemonic.c_str(), ida_mnemonic.length());
  const std::string text(generated.c_str(), generated.length());
  if ( mnemonic.size() > 128 || text.size() > MaxInstructionTextBytes
    || !is_valid_utf8(mnemonic.c_str()) || !is_valid_utf8(text.c_str()) )
  {
    return {ReadonlyStatus::OutputLimit, {}};
  }
  nlohmann::json operands = nlohmann::json::array();
  for ( int index = 0; index < UA_MAXOP; ++index )
  {
    if ( instruction.ops[index].type == o_void )
      break;
    qstring ida_operand;
    if ( !print_operand(&ida_operand, head, index) )
      throw std::runtime_error("instruction operand text is unavailable");
    std::string operand(ida_operand.c_str(), ida_operand.length());
    if ( operand.size() > MaxOperandTextBytes || !is_valid_utf8(operand.c_str()) )
      return {ReadonlyStatus::OutputLimit, {}};
    operands.push_back({
        {"index", index},
        {"type", OperandTypeName(instruction.ops[index].type)},
        {"text", std::move(operand)},
    });
  }
  result["bytes"] = HexBytes(head, static_cast<std::size_t>(size));
  result["mnemonic"] = mnemonic;
  result["text"] = text;
  result["operands"] = std::move(operands);
  return {ReadonlyStatus::Success, std::move(result)};
}

ReadonlyResult ReadonlyAnalysisService::FunctionChunks(
    std::uint64_t address,
    std::uint32_t offset,
    std::uint32_t limit) const
{
  ea_t requested = BADADDR;
  if ( !StableAddress(address, &requested) || !is_mapped(requested) )
    return {ReadonlyStatus::InvalidAddress, {}};
  const ea_t entry = get_func_start(requested);
  if ( entry == BADADDR )
    return {ReadonlyStatus::NotFound, {}};
  rangeset_t ranges;
  if ( get_func_ranges_ea(&ranges, entry) == BADADDR || ranges.empty() )
    throw std::runtime_error("function chunks are unavailable");
  if ( ranges.nranges() > MaxFunctionChunks )
    return {ReadonlyStatus::OutputLimit, {}};
  const std::size_t begin = (std::min)(static_cast<std::size_t>(offset), ranges.nranges());
  const std::size_t finish = (std::min)(begin + limit, ranges.nranges());
  nlohmann::json items = nlohmann::json::array();
  for ( std::size_t index = begin; index < finish; ++index )
  {
    const range_t &range = ranges.getrange(index);
    items.push_back({
        {"start", rpc::FormatAddress(range.start_ea)},
        {"end", rpc::FormatAddress(range.end_ea)},
        {"kind", range.contains(entry) ? "entry" : "tail"},
    });
  }
  const bool has_more = finish < ranges.nranges();
  return {ReadonlyStatus::Success, {
      {"entryAddress", rpc::FormatAddress(entry)},
      {"items", std::move(items)},
      {"nextOffset", has_more ? nlohmann::json(offset + static_cast<std::uint32_t>(finish - begin)) : nlohmann::json(nullptr)},
      {"hasMore", has_more},
  }};
}

ReadonlyResult ReadonlyAnalysisService::FixupGet(std::uint64_t source) const
{
  ea_t address = BADADDR;
  if ( !StableAddress(source, &address) )
    return {ReadonlyStatus::InvalidAddress, {}};
  fixup_data_t fixup;
  if ( !get_fixup(&fixup, address) )
    return {ReadonlyStatus::NotFound, {}};
  try
  {
    return {ReadonlyStatus::Success, FixupJson(address, fixup)};
  }
  catch ( const std::length_error & )
  {
    return {ReadonlyStatus::OutputLimit, {}};
  }
}

ReadonlyResult ReadonlyAnalysisService::FixupList(
    const std::optional<std::uint64_t> &start,
    const std::optional<std::uint64_t> &end,
    std::uint32_t limit,
    const std::optional<std::uint64_t> &next_address) const
{
  ea_t lower = 0;
  ea_t upper = BADADDR;
  ea_t continuation = BADADDR;
  if ( start && !StableAddress(*start, &lower) )
    return {ReadonlyStatus::InvalidAddress, {}};
  if ( end && !StableAddress(*end, &upper) )
    return {ReadonlyStatus::InvalidAddress, {}};
  if ( next_address && !StableAddress(*next_address, &continuation) )
    return {ReadonlyStatus::InvalidAddress, {}};
  ea_t current = BADADDR;
  if ( next_address )
  {
    current = continuation;
    if ( !exists_fixup(current) )
      return {ReadonlyStatus::InvalidAddress, {}};
  }
  else if ( start )
  {
    current = exists_fixup(lower) ? lower : get_next_fixup_ea(lower);
  }
  else
  {
    current = get_first_fixup_ea();
  }
  if ( start && current != BADADDR && current < lower )
    return {ReadonlyStatus::InvalidAddress, {}};
  nlohmann::json items = nlohmann::json::array();
  try
  {
    while ( current != BADADDR && (!end || current < upper) && items.size() < limit )
    {
      fixup_data_t fixup;
      if ( !get_fixup(&fixup, current) )
        throw std::runtime_error("fixup enumeration is inconsistent");
      items.push_back(FixupJson(current, fixup));
      current = get_next_fixup_ea(current);
    }
  }
  catch ( const std::length_error & )
  {
    return {ReadonlyStatus::OutputLimit, {}};
  }
  const bool has_more = current != BADADDR && (!end || current < upper);
  return {ReadonlyStatus::Success, {
      {"items", std::move(items)},
      {"nextAddress", has_more ? nlohmann::json(rpc::FormatAddress(current)) : nlohmann::json(nullptr)},
      {"hasMore", has_more},
  }};
}

ReadonlyResult ReadonlyAnalysisService::SwitchGet(std::uint64_t address) const
{
  ea_t requested = BADADDR;
  if ( !StableAddress(address, &requested) || !is_mapped(requested) )
    return {ReadonlyStatus::InvalidAddress, {}};
  const ea_t head = get_item_head(requested);
  switch_info_t info;
  if ( get_switch_info(&info, head) <= 0 )
    return {ReadonlyStatus::NotFound, {}};
  if ( info.ncases > MaxSwitchCases )
    return {ReadonlyStatus::OutputLimit, {}};
  casevec_t values;
  eavec_t targets;
  if ( !calc_switch_cases(&values, &targets, head, info) || values.size() != targets.size() )
    throw std::runtime_error("switch cases are unavailable");
  if ( targets.size() > MaxSwitchCases )
    return {ReadonlyStatus::OutputLimit, {}};
  nlohmann::json cases = nlohmann::json::array();
  for ( std::size_t index = 0; index < targets.size(); ++index )
  {
    nlohmann::json item_values = nlohmann::json::array();
    if ( values[index].size() > MaxSwitchCases )
      return {ReadonlyStatus::OutputLimit, {}};
    for ( sval_t value : values[index] )
      item_values.push_back(std::to_string(value));
    cases.push_back({
        {"values", std::move(item_values)},
        {"target", rpc::FormatAddress(targets[index])},
    });
  }
  return {ReadonlyStatus::Success, {
      {"address", rpc::FormatAddress(head)},
      {"cases", std::move(cases)},
      {"defaultTarget", info.has_default() ? nlohmann::json(rpc::FormatAddress(info.defjump)) : nlohmann::json(nullptr)},
      {"flags", {
          {"sparse", info.is_sparse()}, {"custom", info.is_custom()},
          {"indirect", info.is_indirect()}, {"subtract", info.is_subtract()},
          {"userDefined", info.is_user_defined()},
      }},
      {"jumpTable", info.jumps == BADADDR ? nlohmann::json(nullptr) : nlohmann::json(rpc::FormatAddress(info.jumps))},
      {"caseCount", info.ncases},
      {"lowCase", std::to_string(info.get_lowcase())},
      {"truncated", false},
  }};
}

ReadonlyResult ReadonlyAnalysisService::ExceptionTryBlocks(
    std::uint64_t address,
    std::uint32_t limit) const
{
  ea_t requested = BADADDR;
  if ( !StableAddress(address, &requested) || !is_mapped(requested) )
    return {ReadonlyStatus::InvalidAddress, {}};
  const ea_t entry = get_func_start(requested);
  if ( entry == BADADDR )
    return {ReadonlyStatus::NotFound, {}};
  rangeset_t function_ranges;
  if ( get_func_ranges_ea(&function_ranges, entry) == BADADDR || function_ranges.empty() )
    throw std::runtime_error("function ranges are unavailable");
  if ( function_ranges.nranges() > MaxFunctionChunks )
    return {ReadonlyStatus::OutputLimit, {}};
  nlohmann::json items = nlohmann::json::array();
  std::set<std::tuple<ea_t, uchar, uchar>> seen;
  bool truncated = false;
  try
  {
    for ( std::size_t chunk = 0; chunk < function_ranges.nranges() && !truncated; ++chunk )
    {
      tryblks_t blocks;
      get_tryblks(&blocks, function_ranges.getrange(chunk));
      for ( const tryblk_t &block : blocks )
      {
        if ( block.empty() )
          continue;
        const auto key = std::make_tuple(block.front().start_ea, block.get_kind(), block.level);
        if ( !seen.insert(key).second )
          continue;
        if ( seen.size() > MaxTryBlocks || items.size() == limit )
        {
          truncated = true;
          break;
        }
        nlohmann::json handlers = nlohmann::json::array();
        if ( block.is_cpp() )
        {
          if ( block.cpp().size() > MaxHandlers )
            return {ReadonlyStatus::OutputLimit, {}};
          for ( const catch_t &handler : block.cpp() )
          {
            const char *kind = handler.type_id == CATCH_ID_CLEANUP ? "cleanup" : "catch";
            handlers.push_back({
                {"kind", kind},
                {"ranges", RangesJson(handler)},
                {"catchAll", handler.type_id == CATCH_ID_ALL},
            });
          }
        }
        else if ( block.is_seh() )
        {
          const seh_t &handler = block.seh();
          const char *kind = handler.filter.empty() && handler.seh_code == SEH_SEARCH ? "finally" : "seh";
          handlers.push_back({
              {"kind", kind},
              {"ranges", RangesJson(handler)},
              {"filterRanges", RangesJson(handler.filter)},
              {"catchAll", false},
          });
        }
        items.push_back({
            {"ranges", RangesJson(block)},
            {"kind", block.is_cpp() ? "cpp" : "seh"},
            {"level", block.level},
            {"handlers", std::move(handlers)},
        });
      }
    }
  }
  catch ( const std::length_error & )
  {
    return {ReadonlyStatus::OutputLimit, {}};
  }
  return {ReadonlyStatus::Success, {
      {"functionAddress", rpc::FormatAddress(entry)},
      {"items", std::move(items)},
      {"truncated", truncated},
  }};
}

ReadonlyResult ReadonlyAnalysisService::AnalysisStatus() const
{
  auto_display_t display;
  const bool has_display = get_auto_display(&display);
  const atype_t queue = has_display ? display.type : get_auto_state();
  const idastate_t state = has_display ? display.state : st_Ready;
  nlohmann::json current = nullptr;
  if ( has_display && display.ea != BADADDR )
    current = rpc::FormatAddress(display.ea);
  return {ReadonlyStatus::Success, {
      {"queue", AutoQueueName(queue)},
      {"state", IdaStateName(state)},
      {"enabled", is_auto_enabled()},
      {"complete", auto_is_ok()},
      {"currentAddress", std::move(current)},
  }};
}

ReadonlyResult ReadonlyAnalysisService::AnalysisPlan(std::uint64_t start, std::uint64_t end) const
{
  constexpr std::uint64_t MaxPlanSpan = 16ULL * 1024 * 1024;
  if ( start >= end || end - start > MaxPlanSpan ) return {ReadonlyStatus::OutputLimit, {}};
  const ea_t first = static_cast<ea_t>(start);
  const ea_t finish = static_cast<ea_t>(end);
  if ( static_cast<std::uint64_t>(first) != start || static_cast<std::uint64_t>(finish) != end
    || first == BADADDR || finish == BADADDR || finish <= first )
    return {ReadonlyStatus::InvalidAddress, {}};
  for ( ea_t cursor = first; cursor < finish; )
  {
    segment_t *segment = getseg(cursor);
    if ( segment == nullptr || !is_mapped(cursor) ) return {ReadonlyStatus::InvalidAddress, {}};
    const ea_t covered_end = (std::min)(finish, segment->end_ea);
    if ( covered_end <= cursor || !is_mapped(covered_end - 1) ) return {ReadonlyStatus::InvalidAddress, {}};
    cursor = covered_end;
  }
  auto_mark_range(first, finish, AU_USED);
  return {ReadonlyStatus::Success, {
      {"accepted", true}, {"start", rpc::FormatAddress(first)},
      {"end", rpc::FormatAddress(finish)}, {"queue", "used"},
  }};
}

ReadonlyResult ReadonlyAnalysisService::AnalysisProblems(
    const std::string &type,
    const std::optional<std::uint64_t> &start,
    std::uint32_t limit,
    const std::optional<std::uint64_t> &next_address) const
{
  const auto problem_type = ParseProblemType(type);
  if ( !problem_type )
    throw std::invalid_argument("analysis problem type is invalid");
  ea_t lower = 0;
  ea_t continuation = 0;
  if ( start && !StableAddress(*start, &lower) )
    return {ReadonlyStatus::InvalidAddress, {}};
  if ( next_address && !StableAddress(*next_address, &continuation) )
    return {ReadonlyStatus::InvalidAddress, {}};
  if ( next_address )
    lower = continuation;
  ea_t current = get_problem(problem_type->id, lower);
  nlohmann::json items = nlohmann::json::array();
  while ( current != BADADDR && items.size() < limit )
  {
    qstring ida_description;
    const ssize_t length = get_problem_desc(&ida_description, problem_type->id, current);
    const char *raw_name = get_problem_name(problem_type->id, true);
    std::string name = raw_name == nullptr ? problem_type->name : raw_name;
    std::string description = length >= 0
        ? std::string(ida_description.c_str(), ida_description.length())
        : name;
    if ( name.size() > 1024 || description.size() > MaxDescriptionBytes
      || !is_valid_utf8(name.c_str()) || !is_valid_utf8(description.c_str()) )
    {
      return {ReadonlyStatus::OutputLimit, {}};
    }
    items.push_back({
        {"address", rpc::FormatAddress(current)},
        {"type", problem_type->name},
        {"name", std::move(name)},
        {"description", std::move(description)},
    });
    if ( current == (std::numeric_limits<ea_t>::max)() )
    {
      current = BADADDR;
      break;
    }
    current = get_problem(problem_type->id, current + 1);
  }
  const bool has_more = current != BADADDR;
  return {ReadonlyStatus::Success, {
      {"items", std::move(items)},
      {"nextAddress", has_more ? nlohmann::json(rpc::FormatAddress(current)) : nlohmann::json(nullptr)},
      {"hasMore", has_more},
  }};
}

} // namespace ida_agent::services
