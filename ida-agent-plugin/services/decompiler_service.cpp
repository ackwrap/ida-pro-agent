#include "decompiler_service.hpp"

#include "address.hpp"

#include <bytes.hpp>
#include <funcs.hpp>
#include <hexrays.hpp>
#include <lines.hpp>

#include <algorithm>
#include <cstddef>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace ida_agent::services
{
namespace
{

constexpr std::uint32_t MinDecompilerPageBytes = 4;
constexpr std::uint32_t MaxDecompilerPageBytes = 64 * 1024;
constexpr std::uint32_t MaxDecompilerTextBytes = 16 * 1024 * 1024;

DecompileStatus ClassifyFailure(merror_t code)
{
  if ( code == MERR_BUSY )
    return DecompileStatus::Busy;
  if ( code == MERR_LICENSE || code == MERR_BADARCH
    || code == MERR_BITNESS || code == MERR_ONLY32 || code == MERR_ONLY64 )
  {
    return DecompileStatus::CapabilityUnavailable;
  }
  return DecompileStatus::Failed;
}

bool IsUtf8Boundary(std::string_view value, std::size_t offset)
{
  return offset == 0 || offset == value.size()
      || (static_cast<unsigned char>(value[offset]) & 0xC0) != 0x80;
}

} // namespace

DecompileOutcome DecompilerService::Decompile(const DecompileQuery &query) const
{
  if ( !available_ )
    return {DecompileStatus::CapabilityUnavailable, std::nullopt};
  if ( query.max_bytes < MinDecompilerPageBytes
    || query.max_bytes > MaxDecompilerPageBytes
    || query.offset > MaxDecompilerTextBytes )
  {
    return {DecompileStatus::InvalidArgument, std::nullopt};
  }

  const ea_t address = static_cast<ea_t>(query.address);
  if ( static_cast<std::uint64_t>(address) != query.address
    || address == BADADDR || !is_mapped(address) )
    return {DecompileStatus::InvalidAddress, std::nullopt};
  const ea_t entry_address = get_func_start(address);
  if ( entry_address == BADADDR )
    return {DecompileStatus::NotFound, std::nullopt};

  try
  {
    hexrays_failure_t failure;
    cfuncptr_t function = decompile_function(
        entry_address,
        &failure,
        DECOMP_NO_WAIT | DECOMP_GXREFS_NOUPD);
    if ( function == nullptr )
      return {ClassifyFailure(failure.code), std::nullopt};

    std::string text;
    const strvec_t &lines = function->get_pseudocode();
    for ( std::size_t index = 0; index < lines.size(); ++index )
    {
      qstring line;
      if ( tag_remove(&line, lines[index].line) < 0 )
        throw std::runtime_error("failed to remove pseudocode formatting");
      const std::size_t separator = index == 0 ? 0 : 1;
      if ( separator + line.length() > MaxDecompilerTextBytes - text.size() )
        return {DecompileStatus::OutputLimit, std::nullopt};
      if ( separator != 0 )
        text.push_back('\n');
      text.append(line.c_str(), line.length());
    }
    if ( !is_valid_utf8(text.c_str()) )
      throw std::runtime_error("pseudocode is not valid UTF-8");

    if ( query.offset > text.size() || !IsUtf8Boundary(text, query.offset) )
      return {DecompileStatus::InvalidArgument, std::nullopt};
    std::size_t end = std::min<std::size_t>(
        text.size(),
        static_cast<std::size_t>(query.offset) + query.max_bytes);
    while ( end > query.offset && !IsUtf8Boundary(text, end) )
      --end;
    if ( end == query.offset && end < text.size() )
      return {DecompileStatus::InvalidArgument, std::nullopt};

    const bool truncated = end < text.size();
    std::optional<std::uint32_t> next_offset;
    if ( truncated )
      next_offset = static_cast<std::uint32_t>(end);
    DecompileResult result{
        entry_address,
        text.substr(query.offset, end - query.offset),
        query.offset,
        static_cast<std::uint32_t>(end - query.offset),
        static_cast<std::uint32_t>(text.size()),
        truncated,
        next_offset,
    };
    return {DecompileStatus::Success, std::move(result)};
  }
  catch ( const vd_failure_t &failure )
  {
    return {ClassifyFailure(failure.hf.code), std::nullopt};
  }
}

bool DecompilerService::Invalidate(std::uint64_t address) const
{
  const ea_t ea = static_cast<ea_t>(address);
  return available_ && static_cast<std::uint64_t>(ea) == address && ea != BADADDR
      && mark_cfunc_dirty(ea, false);
}

nlohmann::json ToJson(const DecompileResult &result)
{
  nlohmann::json next_offset = nullptr;
  if ( result.next_offset )
    next_offset = *result.next_offset;
  return {
      {"entryAddress", rpc::FormatAddress(result.entry_address)},
      {"pseudocode", result.pseudocode},
      {"offset", result.offset},
      {"returnedSize", result.returned_size},
      {"originalSize", result.original_size},
      {"truncated", result.truncated},
      {"nextOffset", std::move(next_offset)},
  };
}

} // namespace ida_agent::services
