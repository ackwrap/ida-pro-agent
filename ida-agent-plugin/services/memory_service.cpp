#include "memory_service.hpp"

#include "address.hpp"

#include <bytes.hpp>
#include <ida.hpp>
#include <segment.hpp>

#include <cstddef>
#include <string_view>
#include <utility>
#include <vector>

namespace ida_agent::services
{
namespace
{

constexpr std::uint32_t MaxMemoryReadBytes = 4096;

const char *FormatName(MemoryFormat format)
{
  switch ( format )
  {
    case MemoryFormat::Bytes:
      return "bytes";
    case MemoryFormat::String:
      return "string";
    case MemoryFormat::Integer:
      return "integer";
    case MemoryFormat::Pointer:
      return "pointer";
  }
  return "bytes";
}

bool IsValidUtf8(std::string_view value)
{
  std::size_t index = 0;
  while ( index < value.size() )
  {
    const unsigned char lead = static_cast<unsigned char>(value[index]);
    std::size_t continuation = 0;
    std::uint32_t codepoint = 0;
    if ( lead <= 0x7F )
    {
      ++index;
      continue;
    }
    if ( lead >= 0xC2 && lead <= 0xDF )
    {
      continuation = 1;
      codepoint = lead & 0x1F;
    }
    else if ( lead >= 0xE0 && lead <= 0xEF )
    {
      continuation = 2;
      codepoint = lead & 0x0F;
    }
    else if ( lead >= 0xF0 && lead <= 0xF4 )
    {
      continuation = 3;
      codepoint = lead & 0x07;
    }
    else
    {
      return false;
    }
    if ( continuation > value.size() - index - 1 )
      return false;
    for ( std::size_t offset = 1; offset <= continuation; ++offset )
    {
      const unsigned char byte = static_cast<unsigned char>(value[index + offset]);
      if ( (byte & 0xC0) != 0x80 )
        return false;
      codepoint = (codepoint << 6) | (byte & 0x3F);
    }
    if ( (continuation == 2 && codepoint < 0x800)
      || (continuation == 3 && codepoint < 0x10000)
      || (codepoint >= 0xD800 && codepoint <= 0xDFFF)
      || codepoint > 0x10FFFF )
    {
      return false;
    }
    index += continuation + 1;
  }
  return true;
}

std::string HexEncode(const std::vector<std::uint8_t> &bytes)
{
  static constexpr char Hex[] = "0123456789abcdef";
  std::string encoded(bytes.size() * 2, '0');
  for ( std::size_t index = 0; index < bytes.size(); ++index )
  {
    encoded[index * 2] = Hex[bytes[index] >> 4];
    encoded[index * 2 + 1] = Hex[bytes[index] & 0x0F];
  }
  return encoded;
}

std::uint64_t DecodeInteger(const std::vector<std::uint8_t> &bytes, bool big_endian)
{
  std::uint64_t value = 0;
  if ( big_endian )
  {
    for ( std::uint8_t byte : bytes )
      value = (value << 8) | byte;
  }
  else
  {
    for ( std::size_t index = 0; index < bytes.size(); ++index )
      value |= static_cast<std::uint64_t>(bytes[index]) << (index * 8);
  }
  return value;
}

} // namespace

MemoryReadOutcome MemoryService::Read(const MemoryReadQuery &query) const
{
  const ea_t address = static_cast<ea_t>(query.address);
  if ( static_cast<std::uint64_t>(address) != query.address
    || address == BADADDR || !is_mapped(address) )
    return {MemoryReadStatus::InvalidAddress, std::nullopt};

  segment_info_t segment;
  if ( !get_segment_info(&segment, address)
    || segment.is_debugger_segm() || segment.is_ephemeral_segm() )
  {
    return {MemoryReadStatus::InvalidAddress, std::nullopt};
  }
  if ( nbits(address) != 8 )
    return {MemoryReadStatus::UnsupportedProcessor, std::nullopt};

  std::uint32_t byte_count = 0;
  std::optional<std::uint32_t> width_bits;
  switch ( query.format )
  {
    case MemoryFormat::Bytes:
    case MemoryFormat::String:
      byte_count = query.length;
      break;
    case MemoryFormat::Integer:
      width_bits = query.width_bits;
      byte_count = query.width_bits / 8;
      break;
    case MemoryFormat::Pointer:
      width_bits = inf_get_app_bitness();
      byte_count = *width_bits / 8;
      break;
  }
  if ( byte_count == 0 || byte_count > MaxMemoryReadBytes
    || (width_bits && *width_bits != 8 && *width_bits != 16
      && *width_bits != 32 && *width_bits != 64) )
  {
    return {MemoryReadStatus::InvalidAddress, std::nullopt};
  }
  const std::uint64_t remaining = static_cast<std::uint64_t>(segment.end_ea - address);
  if ( byte_count > remaining )
    return {MemoryReadStatus::InvalidAddress, std::nullopt};

  std::vector<std::uint8_t> bytes;
  bytes.reserve(byte_count);
  bool terminated = false;
  for ( std::uint32_t index = 0; index < byte_count; ++index )
  {
    const ea_t current = address + index;
    if ( !is_mapped(current) || nbits(current) != 8
      || !has_value(get_flags_ex(current, GFE_IDB_VALUE)) )
    {
      return {MemoryReadStatus::Unreadable, std::nullopt};
    }
    const std::uint8_t byte = get_db_byte(current);
    if ( query.format == MemoryFormat::String && byte == 0 )
    {
      terminated = true;
      break;
    }
    bytes.push_back(byte);
  }

  MemoryReadResult result{
      query.address,
      query.format,
      static_cast<std::uint32_t>(bytes.size() + (terminated ? 1 : 0)),
      {},
      width_bits,
      std::nullopt,
      std::nullopt,
  };
  if ( query.format == MemoryFormat::Bytes )
  {
    result.value = HexEncode(bytes);
  }
  else if ( query.format == MemoryFormat::String )
  {
    result.value.assign(bytes.begin(), bytes.end());
    if ( !IsValidUtf8(result.value) )
      return {MemoryReadStatus::InvalidEncoding, std::nullopt};
    result.terminated = terminated;
  }
  else
  {
    const bool big_endian = inf_is_be();
    result.value = rpc::FormatAddress(DecodeInteger(bytes, big_endian));
    result.byte_order = big_endian ? "big" : "little";
  }
  return {MemoryReadStatus::Success, std::move(result)};
}

nlohmann::json ToJson(const MemoryReadResult &result)
{
  nlohmann::json encoded{
      {"address", rpc::FormatAddress(result.address)},
      {"format", FormatName(result.format)},
      {"bytesRead", result.bytes_read},
      {"value", result.value},
  };
  if ( result.width_bits )
    encoded["widthBits"] = *result.width_bits;
  if ( result.byte_order )
    encoded["byteOrder"] = *result.byte_order;
  if ( result.terminated )
    encoded["terminated"] = *result.terminated;
  return encoded;
}

} // namespace ida_agent::services
