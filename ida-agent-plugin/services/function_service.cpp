#include "function_service.hpp"

#include "address.hpp"
#include "function_search_cursor.hpp"
#include "inventory_text.hpp"

#include <bytes.hpp>
#include <funcs.hpp>
#include <gdl.hpp>
#include <lines.hpp>
#include <name.hpp>
#include <typeinf.hpp>
#include <xref.hpp>

#include <algorithm>
#include <cstddef>
#include <cctype>
#include <iterator>
#include <map>
#include <stdexcept>

namespace ida_agent::services
{
namespace
{

constexpr std::uint64_t MaxJsonInteger = 9007199254740991ULL;
constexpr std::uint64_t MaxFunctionAnalysisBytes = 1024 * 1024;
constexpr std::size_t MaxFunctionChunks = 1024;
constexpr std::size_t MaxFunctionsScannedPerPage = 4096;
constexpr std::size_t MaxDisassemblyLineBytes = 4096;
constexpr std::size_t MaxBlockEdges = 64;
constexpr std::size_t MaxCallees = 10000;
constexpr std::size_t MaxCalleeNameBytes = 1024;
constexpr std::size_t MaxFunctionNameCharacters = 1024;
constexpr std::size_t MaxFunctionSignatureCharacters = 2048;

void RequireJsonInteger(std::uint64_t value, const char *field)
{
  if ( value > MaxJsonInteger )
    throw std::range_error(std::string(field) + " exceeds the protocol integer limit");
}

std::string NormalizeSearchName(std::string_view name)
{
  std::string normalized(name);
  for ( char &character : normalized )
  {
    const unsigned char value = static_cast<unsigned char>(character);
    if ( value >= 'A' && value <= 'Z' )
      character = static_cast<char>(std::tolower(value));
  }
  return normalized;
}

FunctionSummary ReadFunctionSummary(ea_t entry_address)
{
  func_entry_info_t entry;
  if ( !get_func_entry_info(&entry, entry_address, GFI_NAME) )
    throw std::runtime_error("function search result is unavailable");
  return FunctionSummary{entry_address, entry.get_name()};
}

bool IsBoundedUtf8(std::string_view value, std::size_t maximum)
{
  std::size_t characters = 0;
  return !value.empty() && Utf8CodePointCount(value, &characters) && characters <= maximum;
}

FunctionAnalysisStatus ResolveFunction(std::uint64_t address, ea_t *entry_address)
{
  const ea_t requested = static_cast<ea_t>(address);
  if ( static_cast<std::uint64_t>(requested) != address
    || requested == BADADDR || !is_mapped(requested) )
  {
    return FunctionAnalysisStatus::InvalidAddress;
  }

  *entry_address = get_func_start(requested);
  if ( *entry_address == BADADDR )
    return FunctionAnalysisStatus::NotFound;
  const std::uint64_t size_bytes = calc_func_size_ea(*entry_address);
  if ( size_bytes == 0 )
    throw std::runtime_error("function size is unavailable");
  if ( size_bytes > MaxFunctionAnalysisBytes )
    return FunctionAnalysisStatus::OutputLimit;
  return FunctionAnalysisStatus::Success;
}

BasicBlockType StableBlockType(fc_block_type_t type)
{
  switch ( type )
  {
    case fcb_normal:
      return BasicBlockType::Normal;
    case fcb_indjump:
      return BasicBlockType::IndirectJump;
    case fcb_ret:
      return BasicBlockType::Return;
    case fcb_cndret:
      return BasicBlockType::ConditionalReturn;
    case fcb_noret:
      return BasicBlockType::NoReturn;
    case fcb_enoret:
      return BasicBlockType::ExternalNoReturn;
    case fcb_extern:
      return BasicBlockType::External;
    case fcb_error:
      return BasicBlockType::Error;
  }
  throw std::runtime_error("function basic block type is unavailable");
}

const char *StableBlockTypeName(BasicBlockType type)
{
  switch ( type )
  {
    case BasicBlockType::Normal:
      return "normal";
    case BasicBlockType::IndirectJump:
      return "indirect_jump";
    case BasicBlockType::Return:
      return "return";
    case BasicBlockType::ConditionalReturn:
      return "conditional_return";
    case BasicBlockType::NoReturn:
      return "no_return";
    case BasicBlockType::ExternalNoReturn:
      return "external_no_return";
    case BasicBlockType::External:
      return "external";
    case BasicBlockType::Error:
      return "error";
  }
  throw std::runtime_error("stable basic block type is unavailable");
}

template <typename Item>
void SetOffsetContinuation(
    std::uint32_t offset,
    const std::vector<Item> &items,
    bool has_more,
    std::optional<std::uint32_t> *next_offset)
{
  if ( has_more )
    *next_offset = offset + static_cast<std::uint32_t>(items.size());
}

} // namespace

FunctionLookup FunctionService::Get(std::uint64_t address) const
{
  const ea_t requested = static_cast<ea_t>(address);
  if ( static_cast<std::uint64_t>(requested) != address
    || requested == BADADDR || !is_mapped(requested) )
    return {FunctionLookupStatus::InvalidAddress, std::nullopt};

  const ea_t entry_address = get_func_start(requested);
  if ( entry_address == BADADDR )
    return {FunctionLookupStatus::NotFound, std::nullopt};

  func_entry_info_t entry;
  if ( !get_func_entry_info(&entry, entry_address, GFI_NAME) )
    throw std::runtime_error("function information is unavailable");
  const std::string function_name = entry.get_name();
  if ( !IsBoundedUtf8(function_name, MaxFunctionNameCharacters) )
    return {FunctionLookupStatus::OutputLimit, std::nullopt};

  const std::uint64_t size_bytes = calc_func_size_ea(entry_address);
  if ( size_bytes == 0 )
    throw std::runtime_error("function size is unavailable");
  if ( size_bytes > MaxFunctionAnalysisBytes )
    return {FunctionLookupStatus::OutputLimit, std::nullopt};

  rangeset_t ranges;
  if ( get_func_ranges_ea(&ranges, entry_address) == BADADDR || ranges.empty() )
    throw std::runtime_error("function ranges are unavailable");
  if ( ranges.nranges() > MaxFunctionChunks )
    return {FunctionLookupStatus::OutputLimit, std::nullopt};

  qstring declaration;
  std::optional<std::string> signature;
  if ( print_type(&declaration, entry_address, PRTYPE_1LINE | PRTYPE_MAXSTR) )
  {
    signature = declaration.c_str();
    if ( !IsBoundedUtf8(*signature, MaxFunctionSignatureCharacters) )
      return {FunctionLookupStatus::OutputLimit, std::nullopt};
  }

  std::uint64_t instruction_count = 0;
  function_item_iterator_t items;
  if ( items.set(entry_address) && items.first() )
  {
    if ( is_code_ea(items.current()) )
      ++instruction_count;
    while ( items.next_code() )
      ++instruction_count;
  }

  const qflow_chart_ea_t flow_chart(
      "",
      entry_address,
      BADADDR,
      BADADDR,
      FC_NOEXT);
  const std::uint64_t basic_block_count = static_cast<std::uint64_t>(flow_chart.size());
  const std::uint64_t chunk_count = static_cast<std::uint64_t>(ranges.nranges());
  RequireJsonInteger(size_bytes, "function size");
  RequireJsonInteger(instruction_count, "instruction count");
  RequireJsonInteger(basic_block_count, "basic block count");
  RequireJsonInteger(chunk_count, "chunk count");

  const std::uint64_t flags = entry.get_flags();
  return {
      FunctionLookupStatus::Found,
      FunctionInfo{
          entry_address,
          ranges.getrange(0).start_ea,
          ranges.lastrange().end_ea,
          function_name,
          std::move(signature),
          FunctionFlags{
              (flags & FUNC_NORET) != 0,
              (flags & FUNC_FAR) != 0,
              (flags & FUNC_LIB) != 0,
              (flags & FUNC_STATICDEF) != 0,
              (flags & FUNC_FRAME) != 0,
              (flags & FUNC_HIDDEN) != 0,
              (flags & FUNC_THUNK) != 0,
              (flags & FUNC_LUMINA) != 0,
              (flags & FUNC_OUTLINE) != 0,
          },
          FunctionStatistics{
              size_bytes,
              instruction_count,
              basic_block_count,
              chunk_count,
          },
      },
  };
}

FunctionSearchOutcome FunctionService::SearchByName(
    std::string_view name,
    std::uint32_t limit,
    const std::optional<std::string> &cursor) const
{
  const std::string normalized_name = NormalizeSearchName(name);
  ea_t current = BADADDR;
  if ( cursor )
  {
    try
    {
      const std::uint64_t decoded =
          rpc::DecodeFunctionSearchCursor(*cursor, normalized_name);
      current = static_cast<ea_t>(decoded);
      if ( static_cast<std::uint64_t>(current) != decoded )
        return {FunctionSearchStatus::InvalidCursor, std::nullopt};
    }
    catch ( const std::invalid_argument & )
    {
      return {FunctionSearchStatus::InvalidCursor, std::nullopt};
    }
    if ( current == BADADDR )
      return {FunctionSearchStatus::InvalidCursor, std::nullopt};
    if ( !is_function_entry(current) )
      current = get_next_func_ea(current);
  }
  else
  {
    current = get_func_ea_by_num(0);
  }

  FunctionSearchResult result;
  result.items.reserve(limit);
  std::size_t scanned = 0;
  while ( current != BADADDR && scanned < MaxFunctionsScannedPerPage )
  {
    const FunctionSummary item = ReadFunctionSummary(current);
    if ( IsBoundedUtf8(item.name, MaxFunctionNameCharacters)
      && NormalizeSearchName(item.name).find(normalized_name) != std::string::npos )
    {
      if ( result.items.size() == limit )
        break;
      result.items.push_back(item);
    }
    ++scanned;
    current = get_next_func_ea(current);
  }

  if ( current != BADADDR )
  {
    result.has_more = true;
    result.next_cursor = rpc::EncodeFunctionSearchCursor(normalized_name, current);
  }
  return {FunctionSearchStatus::Success, std::move(result)};
}

FunctionSearchOutcome FunctionService::SearchByAddress(std::uint64_t address) const
{
  const ea_t requested = static_cast<ea_t>(address);
  if ( static_cast<std::uint64_t>(requested) != address
    || requested == BADADDR || !is_mapped(requested) )
    return {FunctionSearchStatus::InvalidAddress, std::nullopt};

  FunctionSearchResult result;
  const ea_t entry_address = get_func_start(requested);
  if ( entry_address != BADADDR )
  {
    FunctionSummary summary = ReadFunctionSummary(entry_address);
    if ( !IsBoundedUtf8(summary.name, MaxFunctionNameCharacters) )
      return {FunctionSearchStatus::OutputLimit, std::nullopt};
    result.items.push_back(std::move(summary));
  }
  return {FunctionSearchStatus::Success, std::move(result)};
}

FunctionDisassemblyOutcome FunctionService::Disassemble(const FunctionPageQuery &query) const
{
  ea_t entry_address = BADADDR;
  const FunctionAnalysisStatus status = ResolveFunction(query.address, &entry_address);
  if ( status != FunctionAnalysisStatus::Success )
    return {status, std::nullopt};

  FunctionDisassemblyResult result{entry_address};
  result.items.reserve(query.limit);
  std::uint32_t index = 0;
  function_item_iterator_t iterator;
  if ( iterator.set(entry_address) && iterator.first() )
  {
    do
    {
      const ea_t item_address = iterator.current();
      if ( !is_code_ea(item_address) )
        continue;
      if ( index++ < query.offset )
        continue;
      if ( result.items.size() == query.limit )
      {
        result.has_more = true;
        break;
      }

      qstring generated;
      if ( !generate_disasm_line(&generated, item_address, GENDSM_REMOVE_TAGS) )
        throw std::runtime_error("function disassembly line is unavailable");
      const std::string text(generated.c_str(), generated.length());
      if ( text.size() > MaxDisassemblyLineBytes )
        return {FunctionAnalysisStatus::OutputLimit, std::nullopt};
      if ( !is_valid_utf8(text.c_str()) )
        throw std::runtime_error("function disassembly line is not valid UTF-8");
      result.items.push_back({item_address, text});
    } while ( iterator.next_code() );
  }
  SetOffsetContinuation(
      query.offset,
      result.items,
      result.has_more,
      &result.next_offset);
  return {FunctionAnalysisStatus::Success, std::move(result)};
}

FunctionBasicBlocksOutcome FunctionService::BasicBlocks(const FunctionPageQuery &query) const
{
  ea_t entry_address = BADADDR;
  const FunctionAnalysisStatus status = ResolveFunction(query.address, &entry_address);
  if ( status != FunctionAnalysisStatus::Success )
    return {status, std::nullopt};

  const qflow_chart_ea_t flow_chart(
      "",
      entry_address,
      BADADDR,
      BADADDR,
      FC_NOEXT);
  const std::size_t block_count = flow_chart.blocks.size();
  for ( const qbasic_block_t &block : flow_chart.blocks )
  {
    if ( block.succ.size() > MaxBlockEdges || block.pred.size() > MaxBlockEdges )
      return {FunctionAnalysisStatus::OutputLimit, std::nullopt};
  }

  FunctionBasicBlocksResult result{entry_address};
  const std::size_t begin = (std::min)(static_cast<std::size_t>(query.offset), block_count);
  const std::size_t end = (std::min)(begin + query.limit, block_count);
  result.items.reserve(end - begin);
  for ( std::size_t block_index = begin; block_index < end; ++block_index )
  {
    const qbasic_block_t &source = flow_chart.blocks[block_index];
    BasicBlock block{
        source.start_ea,
        source.end_ea,
        StableBlockType(flow_chart.calc_block_type(block_index)),
    };
    block.successors.reserve(source.succ.size());
    for ( int successor : source.succ )
    {
      if ( successor < 0 || static_cast<std::size_t>(successor) >= block_count )
        throw std::runtime_error("function basic block successor is invalid");
      block.successors.push_back(flow_chart.blocks[successor].start_ea);
    }
    block.predecessors.reserve(source.pred.size());
    for ( int predecessor : source.pred )
    {
      if ( predecessor < 0 || static_cast<std::size_t>(predecessor) >= block_count )
        throw std::runtime_error("function basic block predecessor is invalid");
      block.predecessors.push_back(flow_chart.blocks[predecessor].start_ea);
    }
    result.items.push_back(std::move(block));
  }
  result.has_more = end < block_count;
  SetOffsetContinuation(
      query.offset,
      result.items,
      result.has_more,
      &result.next_offset);
  return {FunctionAnalysisStatus::Success, std::move(result)};
}

FunctionCalleesOutcome FunctionService::Callees(const FunctionPageQuery &query) const
{
  ea_t entry_address = BADADDR;
  const FunctionAnalysisStatus status = ResolveFunction(query.address, &entry_address);
  if ( status != FunctionAnalysisStatus::Success )
    return {status, std::nullopt};

  std::map<std::uint64_t, FunctionCallee> collected;
  function_item_iterator_t iterator;
  if ( iterator.set(entry_address) && iterator.first() )
  {
    do
    {
      const ea_t item_address = iterator.current();
      if ( !is_code_ea(item_address) )
        continue;
      xrefblk_t xref;
      for ( bool found = xref.first_from(item_address, XREF_NOFLOW);
            found;
            found = xref.next_from() )
      {
        if ( !xref.iscode || (xref.type != fl_CF && xref.type != fl_CN) )
          continue;
        const ea_t target_entry = get_func_start(xref.to);
        const bool internal = target_entry != BADADDR;
        const ea_t target = internal ? target_entry : xref.to;
        const std::uint64_t stable_target = static_cast<std::uint64_t>(target);
        if ( collected.find(stable_target) != collected.end() )
          continue;
        if ( collected.size() == MaxCallees )
          return {FunctionAnalysisStatus::OutputLimit, std::nullopt};

        qstring ida_name;
        const ssize_t name_size = internal
            ? get_func_name(&ida_name, target)
            : get_name(&ida_name, target);
        std::string name;
        if ( name_size > 0 && !ida_name.empty() )
          name.assign(ida_name.c_str(), ida_name.length());
        else
          name = rpc::FormatAddress(stable_target);
        if ( name.size() > MaxCalleeNameBytes )
          return {FunctionAnalysisStatus::OutputLimit, std::nullopt};
        if ( !is_valid_utf8(name.c_str()) )
          throw std::runtime_error("function callee name is not valid UTF-8");
        collected.emplace(
            stable_target,
            FunctionCallee{stable_target, std::move(name), internal});
      }
    } while ( iterator.next_code() );
  }

  FunctionCalleesResult result{entry_address};
  auto current = collected.begin();
  const std::size_t begin = (std::min)(static_cast<std::size_t>(query.offset), collected.size());
  std::advance(current, begin);
  for ( std::uint32_t count = 0; count < query.limit && current != collected.end(); ++count, ++current )
    result.items.push_back(current->second);
  result.has_more = current != collected.end();
  SetOffsetContinuation(
      query.offset,
      result.items,
      result.has_more,
      &result.next_offset);
  return {FunctionAnalysisStatus::Success, std::move(result)};
}

nlohmann::json ToJson(const FunctionInfo &info)
{
  nlohmann::json signature = nullptr;
  if ( info.signature )
    signature = *info.signature;

  return {
      {"entryAddress", rpc::FormatAddress(info.entry_address)},
      {"addressRange",
       {
           {"start", rpc::FormatAddress(info.range_start)},
           {"end", rpc::FormatAddress(info.range_end)},
       }},
      {"name", info.name},
      {"signature", std::move(signature)},
      {"flags",
       {
           {"noReturn", info.flags.no_return},
           {"far", info.flags.far},
           {"library", info.flags.library},
           {"static", info.flags.static_definition},
           {"frame", info.flags.frame},
           {"hidden", info.flags.hidden},
           {"thunk", info.flags.thunk},
           {"lumina", info.flags.lumina},
           {"outlined", info.flags.outlined},
       }},
      {"statistics",
       {
           {"sizeBytes", info.statistics.size_bytes},
           {"instructionCount", info.statistics.instruction_count},
           {"basicBlockCount", info.statistics.basic_block_count},
           {"chunkCount", info.statistics.chunk_count},
       }},
  };
}

nlohmann::json ToJson(const FunctionSearchResult &result)
{
  nlohmann::json items = nlohmann::json::array();
  for ( const FunctionSummary &item : result.items )
  {
    items.push_back({
        {"entryAddress", rpc::FormatAddress(item.entry_address)},
        {"name", item.name},
    });
  }

  nlohmann::json next_cursor = nullptr;
  if ( result.next_cursor )
    next_cursor = *result.next_cursor;
  return {
      {"items", std::move(items)},
      {"nextCursor", std::move(next_cursor)},
      {"hasMore", result.has_more},
  };
}

nlohmann::json ToJson(const FunctionDisassemblyResult &result)
{
  nlohmann::json items = nlohmann::json::array();
  for ( const DisassemblyItem &item : result.items )
  {
    items.push_back({
        {"address", rpc::FormatAddress(item.address)},
        {"text", item.text},
    });
  }
  return {
      {"entryAddress", rpc::FormatAddress(result.entry_address)},
      {"items", std::move(items)},
      {"nextOffset", result.next_offset ? nlohmann::json(*result.next_offset) : nlohmann::json(nullptr)},
      {"hasMore", result.has_more},
  };
}

nlohmann::json ToJson(const FunctionBasicBlocksResult &result)
{
  nlohmann::json items = nlohmann::json::array();
  for ( const BasicBlock &block : result.items )
  {
    nlohmann::json successors = nlohmann::json::array();
    for ( std::uint64_t successor : block.successors )
      successors.push_back(rpc::FormatAddress(successor));
    nlohmann::json predecessors = nlohmann::json::array();
    for ( std::uint64_t predecessor : block.predecessors )
      predecessors.push_back(rpc::FormatAddress(predecessor));
    items.push_back({
        {"start", rpc::FormatAddress(block.start)},
        {"end", rpc::FormatAddress(block.end)},
        {"type", StableBlockTypeName(block.type)},
        {"successors", std::move(successors)},
        {"predecessors", std::move(predecessors)},
    });
  }
  return {
      {"entryAddress", rpc::FormatAddress(result.entry_address)},
      {"items", std::move(items)},
      {"nextOffset", result.next_offset ? nlohmann::json(*result.next_offset) : nlohmann::json(nullptr)},
      {"hasMore", result.has_more},
  };
}

nlohmann::json ToJson(const FunctionCalleesResult &result)
{
  nlohmann::json items = nlohmann::json::array();
  for ( const FunctionCallee &callee : result.items )
  {
    items.push_back({
        {"address", rpc::FormatAddress(callee.address)},
        {"name", callee.name},
        {"internal", callee.internal},
    });
  }
  return {
      {"entryAddress", rpc::FormatAddress(result.entry_address)},
      {"items", std::move(items)},
      {"nextOffset", result.next_offset ? nlohmann::json(*result.next_offset) : nlohmann::json(nullptr)},
      {"hasMore", result.has_more},
  };
}

} // namespace ida_agent::services
