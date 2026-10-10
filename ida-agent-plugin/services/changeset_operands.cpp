#include "changeset_operands.hpp"

#include "address.hpp"

#include <ida.hpp>
#include <bytes.hpp>
#include <xref.hpp>
#include <offset.hpp>
#include <typeinf.hpp>
#include <ua.hpp>

#include <charconv>
#include <stdexcept>

namespace ida_agent::services::detail
{
namespace
{
std::optional<int> OperandIndex(std::string_view value)
{
  if ( value.empty() ) return std::nullopt;
  unsigned parsed = 0;
  const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed, 10);
  if ( result.ec != std::errc{} || result.ptr != value.data() + value.size() || parsed >= UA_MAXOP ) return std::nullopt;
  return static_cast<int>(parsed);
}
} // namespace

std::optional<std::string> CurrentOperandState(const ChangeOperation &operation)
{
  const auto operand = OperandIndex(operation.value);
  const ea_t ea = static_cast<ea_t>(operation.address);
  insn_t instruction;
  if ( !operand || decode_insn(&instruction, ea) <= 0 || instruction.ops[*operand].type == o_void ) return std::nullopt;
  const uint8 type = get_optype_flags(get_flags(ea), *operand);
  switch ( type )
  {
    case FF_N_VOID: return "default";
    case FF_N_NUMH: return "hex";
    case FF_N_NUMD: return "decimal";
    case FF_N_CHAR: return "character";
    case FF_N_OFF:
    {
      const ea_t base = get_offbase(ea, *operand);
      return base == BADADDR ? std::optional<std::string>("offset") : std::optional<std::string>("offset:" + rpc::FormatAddress(base));
    }
    case FF_N_NUMB: return "binary";
    case FF_N_NUMO: return "octal";
    case FF_N_STRO:
    {
      tid_t path[MAXSTRUCPATH]{}; adiff_t delta = 0;
      const int length = get_stroff_path(path, &delta, ea, *operand);
      return length > 0 ? std::optional<std::string>("struct_offset:" + std::to_string(path[0]) + ":" + std::to_string(delta))
                        : std::optional<std::string>("struct_offset");
    }
    case FF_N_STK: return "stack_variable";
    case FF_N_SEG: return "segment";
    case FF_N_ENUM: return "enum";
    case FF_N_FOP: return "forced";
    case FF_N_FLT: return "float";
    case FF_N_CUST: return "custom";
  }
  return std::nullopt;
}

std::optional<std::string> DesiredOperandState(const ChangeOperation &operation)
{
  if ( !OperandIndex(operation.value) ) return std::nullopt;
  if ( operation.kind == ChangeKind::OperandHex ) return "hex";
  if ( operation.kind == ChangeKind::OperandDec ) return "decimal";
  if ( operation.kind == ChangeKind::OperandChar ) return "character";
  if ( operation.kind == ChangeKind::OperandBinary ) return "binary";
  if ( operation.kind == ChangeKind::OperandOctal ) return "octal";
  if ( operation.kind == ChangeKind::OperandStackVariable ) return "stack_variable";
  if ( operation.kind == ChangeKind::OperandOffset )
  {
    ea_t base = 0;
    if ( operation.subject )
    {
      try { base = static_cast<ea_t>(rpc::ParseAddress(*operation.subject)); }
      catch ( const std::invalid_argument & ) { return std::nullopt; }
    }
    return "offset:" + rpc::FormatAddress(base);
  }
  if ( operation.kind != ChangeKind::OperandStructOffset || !operation.subject ) return std::nullopt;
  tinfo_t structure;
  if ( !structure.get_named_type(operation.subject->c_str()) ) return std::nullopt;
  const tid_t tid = structure.get_tid();
  if ( tid == BADNODE ) return std::nullopt;
  return "struct_offset:" + std::to_string(tid) + ":" + std::to_string(operation.offset.value_or(0));
}

bool ApplyOperand(const ChangeOperation &operation)
{
  const auto parsed_operand = OperandIndex(operation.value);
  if ( !parsed_operand ) return false;
  const ea_t ea = static_cast<ea_t>(operation.address);
  const int operand = *parsed_operand;
  if ( operation.kind == ChangeKind::OperandHex ) return op_hex(ea, operand);
  if ( operation.kind == ChangeKind::OperandDec ) return op_dec(ea, operand);
  if ( operation.kind == ChangeKind::OperandChar ) return op_chr(ea, operand);
  if ( operation.kind == ChangeKind::OperandBinary ) return op_bin(ea, operand);
  if ( operation.kind == ChangeKind::OperandOctal ) return op_oct(ea, operand);
  if ( operation.kind == ChangeKind::OperandStackVariable ) return op_stkvar(ea, operand);
  if ( operation.kind == ChangeKind::OperandOffset )
  {
    ea_t base = 0;
    if ( operation.subject )
    {
      try { base = static_cast<ea_t>(rpc::ParseAddress(*operation.subject)); }
      catch ( const std::invalid_argument & ) { return false; }
    }
    return op_plain_offset(ea, operand, base);
  }
  if ( !operation.subject ) return false;
  tinfo_t structure;
  if ( !structure.get_named_type(operation.subject->c_str()) ) return false;
  const tid_t tid = structure.get_tid();
  insn_t instruction;
  return tid != BADNODE && decode_insn(&instruction, ea) > 0
      && op_stroff(instruction, operand, &tid, 1, operation.offset.value_or(0));
}

} // namespace ida_agent::services::detail
