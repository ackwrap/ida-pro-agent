#include "model.hpp"
#include "service.hpp"
#include "callers.hpp"
#include "microcode_signature.hpp"

#include <bytes.hpp>
#include <funcs.hpp>
#include <hexrays.hpp>
#include <typeinf.hpp>
#include <tryblks.hpp>
#include <memory>
#include <stdexcept>

namespace ida_agent::services
{
namespace
{
using namespace semantic;
struct ExtractionLimit {};

std::optional<Location> Locate(const mop_t &m)
{
  if (m.size <= 0 || m.size > 16) return std::nullopt;
  const auto size = static_cast<std::uint32_t>(m.size);
  if (m.t == mop_r) return Location{"register", static_cast<std::uint64_t>(m.r), size};
  if (m.t == mop_S) return Location{"stack", static_cast<std::uint64_t>(m.s->off), size};
  if (m.t == mop_v) return Location{"global", static_cast<std::uint64_t>(m.g), size};
  return std::nullopt;
}

const char *Operation(mcode_t code)
{
  switch (code)
  {
    case m_mov: case m_ldc: return "mov";
    case m_neg: return "neg"; case m_lnot: return "logical_not"; case m_bnot: return "bitwise_not";
    case m_xds: return "sign_extend"; case m_xdu: return "zero_extend";
    case m_low: return "low"; case m_high: return "high";
    case m_add: return "add"; case m_sub: return "sub"; case m_mul: return "mul";
    case m_udiv: return "unsigned_div"; case m_sdiv: return "signed_div";
    case m_umod: return "unsigned_mod"; case m_smod: return "signed_mod";
    case m_or: return "or"; case m_and: return "and"; case m_xor: return "xor";
    case m_shl: return "shift_left"; case m_shr: return "logical_shift_right"; case m_sar: return "arithmetic_shift_right";
    case m_jnz: case m_setnz: return "ne"; case m_jz: case m_setz: return "eq";
    case m_jae: case m_setae: return "unsigned_ge"; case m_jb: case m_setb: return "unsigned_lt";
    case m_ja: case m_seta: return "unsigned_gt"; case m_jbe: case m_setbe: return "unsigned_le";
    case m_jg: case m_setg: return "signed_gt"; case m_jge: case m_setge: return "signed_ge";
    case m_jl: case m_setl: return "signed_lt"; case m_jle: case m_setle: return "signed_le";
    case m_jcnd: return "nonzero";
    default: return "unsupported";
  }
}

class Extractor
{
public:
  explicit Extractor(std::uint32_t limit) : limit(limit) {}
  std::uint32_t Work() const { return work; }
  Snapshot Extract(mba_t &mba)
  {
    if (mba.qty <= 0 || mba.qty > 1024) throw ExtractionLimit{};
    Snapshot result;
    result.entry_address = mba.entry_ea;
    result.little_endian = !inf_is_be();
    result.blocks.resize(mba.qty);
    rangeset_t ranges;
    if (get_func_ranges_ea(&ranges, mba.entry_ea) == BADADDR || ranges.empty())
      result.cfg_complete = false;
    if (ranges.nranges() > 1024) throw ExtractionLimit{};
    for (std::size_t i = 0; i < ranges.nranges(); ++i)
    {
      Tick();
      const auto count = get_tryblks(nullptr, ranges.getrange(i));
      if (count > 1024) throw ExtractionLimit{};
      if (count == 0) continue;
      tryblks_t regions;
      get_tryblks(&regions, ranges.getrange(i));
      if (regions.size() > 1024) throw ExtractionLimit{};
      for (const auto &region : regions)
      {
        Tick();
        // ELF unwind metadata can describe a region with no local handler or
        // filter. It adds no intra-function exception edge. Real handlers and
        // unknown handler forms must still make branch claims conservative.
        if (region.is_seh() && region.seh().empty() && region.seh().filter.empty()
            && region.seh().seh_code == SEH_SEARCH) continue;
        result.cfg_complete = false;
        result.limitations.push_back("exception_edges_not_modeled");
        break;
      }
      if (!result.cfg_complete) break;
    }
    for (int index : mba.argidx)
    {
      Tick();
      Location location;
      if (index >= 0 && index < static_cast<int>(mba.vars.size()))
      {
        const auto &var = mba.vars[index];
        if (var.width > 0 && var.width <= 16 && var.is_reg_var() && !var.is_scattered())
          location = {"register", static_cast<std::uint64_t>(var.get_reg1()), static_cast<std::uint32_t>(var.width)};
        else if (var.width > 0 && var.width <= 16 && var.is_stk_var())
          location = {"stack", static_cast<std::uint64_t>(var.get_stkoff()), static_cast<std::uint32_t>(var.width)};
      }
      result.parameters.push_back(location);
    }
    if (result.parameters.empty())
    {
      func_type_data_t signature;
      if (mba.idb_type.get_func_details(&signature))
        for (const auto &arg : signature)
        {
          Tick();
          Location location;
          const auto size = arg.type.get_size();
          if (size > 0 && size <= 16)
          {
            const auto loc = mba.idaloc2vd(arg.argloc, static_cast<int>(size));
            if (loc.is_reg1()) location = {"register", static_cast<std::uint64_t>(loc.reg1()), static_cast<std::uint32_t>(size)};
            else if (loc.is_stkoff()) location = {"stack", static_cast<std::uint64_t>(loc.stkoff()), static_cast<std::uint32_t>(size)};
          }
          result.parameters.push_back(location);
        }
    }
    result.signature = ParameterSignature(mba, result);
    for (int b = 0; b < mba.qty; ++b)
    {
      Tick();
      mblock_t &block = *mba.get_mblock(b);
      auto &out = result.blocks[b];
      for (int i = 0; i < block.nsucc(); ++i) { Tick(); out.successors.push_back(block.succ(i)); }
      for (const minsn_t *ins = block.head; ins; ins = ins->next)
      {
        Tick();
        Instruction record;
        if (ins->ea != BADADDR) record.address = ins->ea;
        std::vector<const minsn_t *> calls;
        FindCalls(*ins, calls, 0);
        if (calls.size() > 1)
        {
          record.memory_barrier = record.register_barrier = true;
          result.limitations.push_back("multiple_calls_in_instruction");
        }
        else if (calls.size() == 1)
        {
          const auto &call = *calls[0];
          if (call.ea != BADADDR) record.address = call.ea;
          record.call = true;
          record.memory_barrier = true;
          if (call.d.t == mop_f)
          {
            const auto &info = *call.d.f;
            if (call.opcode == m_call && info.callee != BADADDR)
            {
              record.callee = info.callee;
              record.signature = SignatureKey(info.return_type, info.cc, info.args);
            }
            if (info.args.size() > 256) throw ExtractionLimit{};
            for (const auto &arg : info.args)
            {
              record.arguments.push_back(Operand(arg, 0));
              qstring printed;
              arg.type.print(&printed);
              if (printed.length() > 4096) throw ExtractionLimit{};
              record.argument_types.emplace_back(printed.c_str(), printed.length());
            }
            for (auto it = info.spoiled.reg.begin(); it != info.spoiled.reg.end(); info.spoiled.reg.inc(it))
            {
              Tick();
              record.clobbers.push_back({"register", static_cast<std::uint64_t>(*it), 1});
            }
            if (&call != ins)
            {
              record.destination = Locate(ins->d);
              record.value = Expression(*ins, 0);
            }
            else if (info.retregs.size() == 1)
            {
              record.destination = Locate(info.retregs[0]);
              record.value.kind = "call_return";
              record.value.bits = record.destination ? record.destination->bytes * 8 : 0;
            }
            if (is_eh_role(info.role)) result.cfg_complete = false;
          }
          else record.register_barrier = true;
        }
        else if (is_mcode_jcond(ins->opcode))
        {
          record.condition = Expression(*ins, 0);
          record.condition->bits = ins->l.size > 0 && ins->l.size <= 16 ? ins->l.size * 8 : 0;
          if (ins->d.t == mop_b && out.successors.size() == 2)
          {
            record.true_block = ins->d.b;
            for (int next : out.successors) if (next != record.true_block) record.false_block = next;
          }
          else result.cfg_complete = false;
        }
        else if (ins->opcode == m_stx)
          record.memory_barrier = true;
        else if (ins->opcode == m_ext)
        {
          record.memory_barrier = record.register_barrier = true;
          result.cfg_complete = false;
        }
        else if (ins->opcode == m_ijmp || ins->opcode == m_jtbl)
          result.cfg_complete = false;
        else if (ins->opcode != m_goto && ins->opcode != m_ret && ins->opcode != m_nop)
        {
          record.destination = Locate(ins->d);
          record.value = Expression(*ins, 0);
          if (!record.destination) record.memory_barrier = record.register_barrier = true;
        }
        out.instructions.push_back(std::move(record));
      }
    }
    if (!result.cfg_complete) result.limitations.push_back("unsupported_control_flow");
    return result;
  }
private:
  std::uint32_t limit, work = 0;
  void Tick() { if (++work > limit) throw ExtractionLimit{}; }
  void FindCalls(const minsn_t &ins, std::vector<const minsn_t *> &calls, int depth)
  {
    Tick();
    if (depth > 32) throw ExtractionLimit{};
    if (is_mcode_call(ins.opcode)) calls.push_back(&ins);
    for (const mop_t *op : {&ins.l, &ins.r, &ins.d})
      if (op->t == mop_d) FindCalls(*op->d, calls, depth + 1);
      else if (op->t == mop_f)
        for (const auto &arg : op->f->args)
          if (arg.t == mop_d) FindCalls(*arg.d, calls, depth + 1);
  }
  Value Operand(const mop_t &m, int depth)
  {
    Tick();
    if (depth > 32) throw ExtractionLimit{};
    Value value;
    value.bits = m.size > 0 && m.size <= 16 ? static_cast<std::uint32_t>(m.size * 8) : 0;
    if (auto location = Locate(m)) { value.kind = "location"; value.location = *location; }
    else if (m.t == mop_n)
    {
      value.kind = "constant";
      value.literal = Hex(m.nnn->value);
    }
    else if (m.t == mop_d) return Expression(*m.d, depth + 1);
    else if (m.t == mop_a)
    {
      if (auto location = Locate(*m.a)) { value.kind = "address"; value.literal = location->Key(); }
    }
    return value;
  }
  Value Expression(const minsn_t &ins, int depth)
  {
    Tick();
    if (depth > 32) throw ExtractionLimit{};
    Value value;
    value.operation = Operation(ins.opcode);
    value.kind = value.operation == "unsupported" ? "unknown" : "operation";
    value.bits = ins.d.size > 0 && ins.d.size <= 16 ? ins.d.size * 8 : 0;
    if (ins.opcode == m_ldx)
    {
      value.kind = "memory_read";
      value.operation = "load";
      value.inputs.push_back(Operand(ins.r, depth + 1));
    }
    else if (is_mcode_call(ins.opcode))
    {
      value.kind = "call_return"; value.operation = "call";
      value.literal = Hex(ins.ea);
    }
    else
    {
      if (ins.l.t != mop_z) value.inputs.push_back(Operand(ins.l, depth + 1));
      if (ins.r.t != mop_z) value.inputs.push_back(Operand(ins.r, depth + 1));
    }
    return value;
  }
};
}

semantic::SnapshotResult semantic::LoadMicrocodeSnapshot(std::uint64_t call_address, std::uint32_t max_work)
{
  if (!max_work || max_work > 100000) return {QueryStatus::InvalidArgument, {}};
  const ea_t address = static_cast<ea_t>(call_address);
  if (address == BADADDR || static_cast<std::uint64_t>(address) != call_address || !is_mapped(address))
    return {QueryStatus::InvalidAddress, {}};
  const ea_t entry = get_func_start(address);
  if (entry == BADADDR) return {QueryStatus::NotFound, {}};
  insn_t instruction;
  if (decode_insn(&instruction, address) <= 0 || !is_call_insn(instruction))
    return {QueryStatus::InvalidArgument, {}};
  Extractor extractor(max_work);
  try
  {
    hexrays_failure_t failure;
    std::unique_ptr<mba_t> mba(gen_microcode(decomp_ranges_t(entry), &failure, nullptr,
        DECOMP_NO_WAIT | DECOMP_GXREFS_NOUPD, MMAT_CALLS));
    if (!mba)
    {
      if (failure.code == MERR_BUSY) return {QueryStatus::Busy, {}};
      if (failure.code == MERR_LICENSE || failure.code == MERR_ONLY32 || failure.code == MERR_ONLY64)
        return {QueryStatus::CapabilityUnavailable, {}};
      return {QueryStatus::DecompileFailed, {}};
    }
    auto snapshot = std::make_shared<Snapshot>(extractor.Extract(*mba));
    return {QueryStatus::Success, std::move(snapshot), extractor.Work()};
  }
  catch (const ExtractionLimit &) { return {QueryStatus::OutputLimit, {}, max_work}; }
  catch (const vd_failure_t &) { return {QueryStatus::DecompileFailed, {}, extractor.Work()}; }
  catch (const std::out_of_range &) { return {QueryStatus::NotFound, {}}; }
  catch (const std::invalid_argument &) { return {QueryStatus::InvalidArgument, {}}; }
}

QueryResult SemanticAnalysisService::AnalyzeArgument(const semantic::Request &request, bool guards) const
{
  if (!decompiler_available_) return {QueryStatus::CapabilityUnavailable, {}};
  if (!semantic::ValidRequest(request)) return {QueryStatus::InvalidArgument, {}};
  auto loaded = semantic::LoadMicrocodeSnapshot(request.call_address, request.max_work);
  if (loaded.status != QueryStatus::Success) return {loaded.status, {}};
  try
  {
    auto result = semantic::Analyze(*loaded.snapshot, request, guards);
    if (result.dump().size() > 256 * 1024) return {QueryStatus::OutputLimit, {}};
    return {QueryStatus::Success, std::move(result)};
  }
  catch (const std::out_of_range &) { return {QueryStatus::NotFound, {}}; }
  catch (const std::invalid_argument &) { return {QueryStatus::InvalidArgument, {}}; }
}
}
