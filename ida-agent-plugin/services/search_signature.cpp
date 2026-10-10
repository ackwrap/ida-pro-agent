#include "search_service.hpp"

#include "search_internal.hpp"

#include <bytes.hpp>
#include <funcs.hpp>
#include <ida.hpp>
#include <idp.hpp>
#include <ua.hpp>
#include <xref.hpp>

#include <algorithm>
#include <array>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <utility>
#include <vector>

namespace ida_agent::services
{
namespace
{

constexpr std::size_t MaxXrefCandidates = 256;
constexpr std::array<std::size_t, 3> UniqueCheckThresholds = {32, 128, 512};

struct SignatureByte
{
  unsigned char value;
  bool wildcard;
};

using Signature = std::vector<SignatureByte>;

const char *ModeName(SignatureMode mode)
{
  switch ( mode )
  {
    case SignatureMode::Address: return "address";
    case SignatureMode::Function: return "function";
    case SignatureMode::Range: return "range";
  }
  return "address";
}

const char *FormatName(SignatureFormat format)
{
  switch ( format )
  {
    case SignatureFormat::Ida: return "ida";
    case SignatureFormat::X64Dbg: return "x64dbg";
    case SignatureFormat::Mask: return "mask";
    case SignatureFormat::Bitmask: return "bitmask";
  }
  return "ida";
}

bool AppendBytes(Signature *signature, ea_t address, std::size_t size, bool wildcard)
{
  if ( size == 0 ) return true;
  std::vector<unsigned char> bytes(size);
  if ( get_bytes(bytes.data(), static_cast<ssize_t>(bytes.size()), address) != static_cast<ssize_t>(bytes.size()) )
    return false;
  for ( unsigned char byte : bytes ) signature->push_back({byte, wildcard});
  return true;
}

bool IsWildcardableOperand(optype_t type)
{
  if ( PH.id == PLFM_386 )
  {
    return type == o_mem || type == o_phrase || type == o_displ
        || type == o_far || type == o_near || type >= o_idpspec0;
  }
  return type == o_mem || type == o_phrase || type == o_displ
      || type == o_imm || type == o_far || type == o_near;
}

bool OperandSpan(const insn_t &instruction, std::size_t *offset, std::size_t *length)
{
  for ( int index = 0; index < UA_MAXOP; ++index )
  {
    const op_t &operand = instruction.ops[index];
    if ( operand.type == o_void ) break;
    if ( !IsWildcardableOperand(operand.type) ) continue;
    const std::size_t operand_offset = static_cast<unsigned char>(operand.offb);
    if ( PH.id == PLFM_ARM )
    {
      const std::size_t operand_length = instruction.size == 4 ? 3 : instruction.size == 8 ? 7 : 0;
      if ( operand_length == 0 || operand_offset >= instruction.size ) continue;
      *offset = operand_offset;
      *length = (std::min)(operand_length, static_cast<std::size_t>(instruction.size) - operand_offset);
      return *length != 0;
    }
    if ( operand_offset == 0 || operand_offset >= instruction.size ) continue;
    *offset = operand_offset;
    *length = static_cast<std::size_t>(instruction.size) - operand_offset;
    return true;
  }
  return false;
}

bool AppendInstruction(Signature *signature, ea_t address, const insn_t &instruction, bool wildcard_operands)
{
  const std::size_t size = instruction.size;
  if ( !wildcard_operands ) return AppendBytes(signature, address, size, false);
  std::size_t offset = 0, length = 0;
  if ( !OperandSpan(instruction, &offset, &length) ) return AppendBytes(signature, address, size, false);
  return AppendBytes(signature, address, offset, false)
      && AppendBytes(signature, address + offset, length, true)
      && AppendBytes(signature, address + offset + length, size - offset - length, false);
}

void TrimSignature(Signature *signature)
{
  while ( !signature->empty() && signature->back().wildcard ) signature->pop_back();
}

std::size_t WildcardCount(const Signature &signature)
{
  return static_cast<std::size_t>(std::count_if(signature.begin(), signature.end(), [](const SignatureByte &byte)
  {
    return byte.wildcard;
  }));
}

bool IsUniqueAt(const Signature &signature, ea_t address)
{
  if ( signature.empty() ) return false;
  std::vector<unsigned char> image, mask;
  image.reserve(signature.size());
  mask.reserve(signature.size());
  for ( const SignatureByte &byte : signature )
  {
    image.push_back(byte.value);
    mask.push_back(byte.wildcard ? 0 : 1);
  }
  const int flags = BIN_SEARCH_FORWARD | BIN_SEARCH_NOSHOW | BIN_SEARCH_CASE;
  const ea_t end = inf_get_max_ea();
  const ea_t first = bin_search(inf_get_min_ea(), end, image.data(), mask.data(), image.size(), flags);
  if ( first != address ) return false;
  if ( first == (std::numeric_limits<ea_t>::max)() ) return false;
  return bin_search(first + 1, end, image.data(), mask.data(), image.size(), flags) == BADADDR;
}

SearchStatus GenerateUniqueSignature(ea_t start, bool wildcard_operands, std::size_t max_length, Signature *signature)
{
  if ( !is_code_ea(start) ) return SearchStatus::NotFound;
  std::optional<std::size_t> last_checked_length;
  const auto check_candidate = [&]()
  {
    Signature candidate = *signature;
    TrimSignature(&candidate);
    if ( candidate.empty()
      || (last_checked_length && *last_checked_length == candidate.size()) )
    {
      return false;
    }
    last_checked_length = candidate.size();
    if ( !IsUniqueAt(candidate, start) ) return false;
    *signature = std::move(candidate);
    return true;
  };

  ea_t current = start;
  while ( signature->size() < max_length )
  {
    insn_t instruction;
    const int decoded = decode_insn(&instruction, current);
    if ( decoded <= 0 || instruction.size == 0 )
    {
      if ( signature->empty() ) return SearchStatus::InvalidPattern;
      return check_candidate() ? SearchStatus::Success : SearchStatus::OutputLimit;
    }
    const std::size_t size = static_cast<std::size_t>(instruction.size);
    if ( size > max_length - signature->size() )
      return check_candidate() ? SearchStatus::Success : SearchStatus::OutputLimit;
    const std::size_t previous_length = signature->size();
    if ( !AppendInstruction(signature, current, instruction, wildcard_operands) ) return SearchStatus::InvalidAddress;

    const bool crossed_threshold = std::any_of(
        UniqueCheckThresholds.begin(), UniqueCheckThresholds.end(),
        [previous_length, signature, max_length](std::size_t threshold)
        {
          return threshold <= max_length
              && previous_length < threshold && signature->size() >= threshold;
        });
    if ( (crossed_threshold || signature->size() == max_length) && check_candidate() )
    {
      return SearchStatus::Success;
    }
    if ( current > (std::numeric_limits<ea_t>::max)() - size )
      return check_candidate() ? SearchStatus::Success : SearchStatus::OutputLimit;
    current += size;
  }
  return check_candidate() ? SearchStatus::Success : SearchStatus::OutputLimit;
}

SearchStatus GenerateRangeSignature(
    ea_t start,
    ea_t end,
    bool wildcard_operands,
    std::size_t max_length,
    Signature *signature)
{
  const std::uint64_t length = static_cast<std::uint64_t>(end - start);
  if ( length == 0 || length > max_length || length > search_detail::MaxSignatureBytes )
    return SearchStatus::OutputLimit;
  if ( !is_mapped(start) ) return SearchStatus::InvalidAddress;
  if ( !is_code_ea(start) )
  {
    if ( !AppendBytes(signature, start, static_cast<std::size_t>(length), false) ) return SearchStatus::InvalidAddress;
    return SearchStatus::Success;
  }

  ea_t current = start;
  while ( current < end )
  {
    insn_t instruction;
    const int decoded = decode_insn(&instruction, current);
    const std::size_t remaining = static_cast<std::size_t>(end - current);
    if ( decoded <= 0 || instruction.size == 0 || instruction.size > remaining )
    {
      if ( !AppendBytes(signature, current, remaining, false) ) return SearchStatus::InvalidAddress;
      break;
    }
    if ( !AppendInstruction(signature, current, instruction, wildcard_operands) ) return SearchStatus::InvalidAddress;
    current += instruction.size;
  }
  TrimSignature(signature);
  return signature->empty() ? SearchStatus::InvalidPattern : SearchStatus::Success;
}

std::string FormatSignature(const Signature &signature, SignatureFormat format)
{
  std::ostringstream output;
  output << std::hex << std::uppercase << std::setfill('0');
  if ( format == SignatureFormat::Ida || format == SignatureFormat::X64Dbg )
  {
    for ( std::size_t index = 0; index < signature.size(); ++index )
    {
      if ( index != 0 ) output << ' ';
      if ( signature[index].wildcard ) output << (format == SignatureFormat::Ida ? "?" : "??");
      else output << std::setw(2) << static_cast<unsigned>(signature[index].value);
    }
    return output.str();
  }
  if ( format == SignatureFormat::Mask )
  {
    for ( const SignatureByte &byte : signature )
    {
      output << "\\x";
      if ( byte.wildcard ) output << "00";
      else output << std::setw(2) << static_cast<unsigned>(byte.value);
    }
    output << ' ';
    for ( const SignatureByte &byte : signature ) output << (byte.wildcard ? '?' : 'x');
    return output.str();
  }
  for ( std::size_t index = 0; index < signature.size(); ++index )
  {
    if ( index != 0 ) output << ", ";
    output << "0x" << std::setw(2) << static_cast<unsigned>(signature[index].wildcard ? 0 : signature[index].value);
  }
  output << " 0b";
  for ( auto byte = signature.rbegin(); byte != signature.rend(); ++byte ) output << (byte->wildcard ? '0' : '1');
  return output.str();
}

} // namespace

SignatureOutcome SearchService::MakeSignature(
    SignatureMode mode,
    std::uint64_t address,
    std::optional<std::uint64_t> end,
    SignatureFormat format,
    bool wildcard_operands,
    std::uint32_t max_length) const
{
  ea_t start = static_cast<ea_t>(address);
  if ( static_cast<std::uint64_t>(start) != address || start == BADADDR || !is_mapped(start)
    || max_length == 0 || max_length > search_detail::MaxSignatureBytes )
  {
    return {SearchStatus::InvalidAddress, std::nullopt};
  }

  std::optional<std::uint64_t> result_end;
  Signature signature;
  SearchStatus status = SearchStatus::Success;
  if ( mode == SignatureMode::Function )
  {
    start = get_func_start(start);
    if ( start == BADADDR ) return {SearchStatus::NotFound, std::nullopt};
    address = start;
    status = GenerateUniqueSignature(start, wildcard_operands, max_length, &signature);
  }
  else if ( mode == SignatureMode::Range )
  {
    if ( !end ) return {SearchStatus::InvalidAddress, std::nullopt};
    ea_t range_end = BADADDR;
    ea_t ignored = BADADDR;
    if ( !search_detail::Range(address, *end, &ignored, &range_end) )
      return {SearchStatus::InvalidAddress, std::nullopt};
    status = GenerateRangeSignature(start, range_end, wildcard_operands, max_length, &signature);
    result_end = *end;
  }
  else
  {
    if ( end ) return {SearchStatus::InvalidAddress, std::nullopt};
    status = GenerateUniqueSignature(start, wildcard_operands, max_length, &signature);
  }
  if ( status != SearchStatus::Success ) return {status, std::nullopt};

  const bool unique = mode == SignatureMode::Range ? IsUniqueAt(signature, start) : true;
  return {
      SearchStatus::Success,
      SignatureResult{
          ModeName(mode), address, result_end, FormatSignature(signature, format), FormatName(format),
          static_cast<std::uint32_t>(signature.size()), unique,
      },
  };
}

XrefSignatureOutcome SearchService::XrefSignatures(
    std::uint64_t address,
    SignatureFormat format,
    bool wildcard_operands,
    std::uint32_t max_length,
    std::uint32_t top) const
{
  const ea_t target = static_cast<ea_t>(address);
  if ( static_cast<std::uint64_t>(target) != address || target == BADADDR || !is_mapped(target) )
    return {SearchStatus::InvalidAddress, std::nullopt};
  if ( max_length == 0 || max_length > search_detail::MaxSignatureBytes || top == 0 )
    return {SearchStatus::OutputLimit, std::nullopt};

  std::vector<ea_t> xrefs;
  xrefblk_t xref;
  for ( bool found = xref.first_to(target, XREF_ALL); found; found = xref.next_to() )
  {
    if ( !xref.iscode || !is_code_ea(xref.from) ) continue;
    if ( xrefs.size() == MaxXrefCandidates ) return {SearchStatus::OutputLimit, std::nullopt};
    xrefs.push_back(xref.from);
  }
  std::sort(xrefs.begin(), xrefs.end());
  xrefs.erase(std::unique(xrefs.begin(), xrefs.end()), xrefs.end());

  struct Candidate
  {
    ea_t address;
    Signature signature;
  };
  std::vector<Candidate> candidates;
  for ( ea_t xref_address : xrefs )
  {
    Signature signature;
    if ( GenerateUniqueSignature(xref_address, wildcard_operands, max_length, &signature) == SearchStatus::Success )
      candidates.push_back({xref_address, std::move(signature)});
  }
  std::sort(candidates.begin(), candidates.end(), [](const Candidate &left, const Candidate &right)
  {
    if ( left.signature.size() != right.signature.size() ) return left.signature.size() < right.signature.size();
    const std::size_t left_wildcards = WildcardCount(left.signature);
    const std::size_t right_wildcards = WildcardCount(right.signature);
    return left_wildcards != right_wildcards ? left_wildcards < right_wildcards : left.address < right.address;
  });

  XrefSignatureResult result{address, {}, static_cast<std::uint32_t>(xrefs.size()), candidates.size() > top};
  const std::size_t returned = (std::min)(candidates.size(), static_cast<std::size_t>(top));
  result.items.reserve(returned);
  for ( std::size_t index = 0; index < returned; ++index )
  {
    result.items.push_back({
        candidates[index].address,
        FormatSignature(candidates[index].signature, format),
        static_cast<std::uint32_t>(candidates[index].signature.size()),
    });
  }
  return {SearchStatus::Success, std::move(result)};
}

} // namespace ida_agent::services
