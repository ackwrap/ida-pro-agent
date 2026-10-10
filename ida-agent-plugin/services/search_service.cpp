#include "search_service.hpp"

#include "list_cursor.hpp"
#include "search_internal.hpp"

#include <bytes.hpp>
#include <ida.hpp>
#include <lines.hpp>
#include <ua.hpp>

#include <limits>
#include <utility>

namespace ida_agent::services
{

AddressSearchOutcome SearchService::Bytes(
    std::string_view pattern,
    std::uint64_t start,
    std::uint64_t end,
    std::uint32_t limit) const
{
  ea_t current = BADADDR;
  ea_t last = BADADDR;
  if ( !search_detail::Range(start, end, &current, &last) )
    return {SearchStatus::InvalidAddress, std::nullopt};
  compiled_binpat_vec_t compiled;
  qstring error;
  if ( pattern.empty()
    || !parse_binpat_str(&compiled, current, std::string(pattern).c_str(), 16, PBSENC_DEF1BPU, &error)
    || compiled.empty() )
  {
    return {SearchStatus::InvalidPattern, std::nullopt};
  }

  AddressSearchResult result;
  std::size_t scanned = 0;
  while ( current < last && scanned++ < search_detail::MaxSearchScan )
  {
    const ea_t hit = bin_search(current, last, compiled, BIN_SEARCH_FORWARD | BIN_SEARCH_NOSHOW);
    if ( hit == BADADDR )
      break;
    if ( result.items.size() == limit )
    {
      result.has_more = true;
      result.next_address = hit;
      break;
    }
    result.items.push_back(hit);
    if ( hit == (std::numeric_limits<ea_t>::max)() )
      break;
    current = hit + 1;
  }
  if ( scanned == search_detail::MaxSearchScan && current < last )
  {
    result.has_more = true;
    result.next_address = current;
  }
  return {SearchStatus::Success, std::move(result)};
}

InstructionSearchOutcome SearchService::Instructions(
    std::uint64_t start,
    std::uint64_t end,
    std::string_view mnemonic,
    std::string_view operand,
    std::uint32_t limit,
    const std::optional<std::string> &cursor) const
{
  ea_t current = BADADDR;
  ea_t last = BADADDR;
  if ( !search_detail::Range(start, end, &current, &last) )
    return {SearchStatus::InvalidAddress, std::nullopt};
  const std::string mnemonic_filter = search_detail::Lower(mnemonic);
  const std::string operand_filter = search_detail::Lower(operand);
  const std::string identity = search_detail::SearchIdentity(
      start, end, {mnemonic_filter, operand_filter});
  if ( cursor )
  {
    try
    {
      const std::uint64_t decoded = rpc::DecodeListCursor("iq1", *cursor, identity);
      current = static_cast<ea_t>(decoded);
      if ( static_cast<std::uint64_t>(current) != decoded || current == BADADDR
        || current < static_cast<ea_t>(start) || current >= last
        || get_item_head(current) != current )
      {
        return {SearchStatus::InvalidCursor, std::nullopt};
      }
    }
    catch ( const std::invalid_argument & )
    {
      return {SearchStatus::InvalidCursor, std::nullopt};
    }
  }
  InstructionSearchResult result;
  std::size_t scanned = 0;
  if ( !cursor )
  {
    current = get_item_head(current);
    if ( current != BADADDR && current < static_cast<ea_t>(start) )
      current = next_head(current, last);
  }
  while ( current != BADADDR && current < last && scanned++ < search_detail::MaxSearchScan )
  {
    insn_t instruction;
    if ( decode_insn(&instruction, current) > 0 )
    {
      qstring ida_mnemonic;
      print_insn_mnem(&ida_mnemonic, current);
      const std::string stable_mnemonic = search_detail::Untag(ida_mnemonic);
      qstring generated;
      if ( !generate_disasm_line(&generated, current, GENDSM_REMOVE_TAGS) )
        return {SearchStatus::InvalidAddress, std::nullopt};
      const std::string text(generated.c_str(), generated.length());
      const std::string bytes = search_detail::HexBytes(current, instruction.size);
      if ( text.size() > search_detail::MaxTextBytes || !is_valid_utf8(text.c_str()) || bytes.empty() )
        return {SearchStatus::OutputLimit, std::nullopt};
      std::vector<std::string> operands;
      std::string joined;
      for ( int index = 0; index < UA_MAXOP; ++index )
      {
        if ( instruction.ops[index].type == o_void )
          break;
        qstring ida_operand;
        if ( print_operand(&ida_operand, current, index) )
        {
          operands.push_back(search_detail::Untag(ida_operand));
          joined += operands.back();
          joined.push_back(' ');
        }
      }
      if ( (mnemonic_filter.empty() || search_detail::Lower(stable_mnemonic).find(mnemonic_filter) != std::string::npos)
        && (operand_filter.empty() || search_detail::Lower(joined).find(operand_filter) != std::string::npos) )
      {
        if ( result.items.size() == limit )
        {
          result.has_more = true;
          result.next_cursor = rpc::EncodeListCursor("iq1", identity, current);
          break;
        }
        result.items.push_back({
            current,
            bytes,
            static_cast<std::uint32_t>(instruction.size),
            text,
            stable_mnemonic,
            std::move(operands),
        });
      }
    }
    current = next_head(current, last);
  }
  if ( scanned == search_detail::MaxSearchScan && current != BADADDR && current < last )
  {
    result.has_more = true;
    result.next_cursor = rpc::EncodeListCursor("iq1", identity, current);
  }
  return {SearchStatus::Success, std::move(result)};
}

} // namespace ida_agent::services
