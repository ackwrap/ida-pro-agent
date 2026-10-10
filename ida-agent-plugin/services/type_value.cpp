#include "type_service_internal.hpp"

#include "address.hpp"
#include "inventory_text.hpp"

#include <bytes.hpp>
#include <ida.hpp>
#include <name.hpp>
#include <nalt.hpp>
#include <typeinf.hpp>

#include <algorithm>
#include <iomanip>
#include <limits>
#include <sstream>
#include <utility>

namespace ida_agent::services
{
using type_service_detail::CheckedAddress;
using type_service_detail::Declaration;
using type_service_detail::Details;
using type_service_detail::MaxDetailDeclarationBytes;
using type_service_detail::MaxDetailMembers;
using type_service_detail::MaxDetailRelatedTypes;
using type_service_detail::MaxJsonInteger;
using type_service_detail::MaxMemberDeclarationBytes;
using type_service_detail::MaxRawFieldBytes;
using type_service_detail::MaxRawGlobalBytes;
using type_service_detail::MaxTypeMembersInspected;
using type_service_detail::MaxValueFields;
using type_service_detail::PrintedText;

namespace
{

std::string Hex(
    const std::vector<unsigned char> &bytes,
    std::size_t offset = 0,
    std::size_t count = std::string::npos)
{
  if ( offset >= bytes.size() ) return {};
  const std::size_t end = offset + (std::min)(count, bytes.size() - offset);
  std::ostringstream output;
  output << std::hex << std::setfill('0');
  for ( std::size_t index = offset; index < end; ++index )
    output << std::setw(2) << static_cast<unsigned>(bytes[index]);
  return output.str();
}

std::uint64_t DecodeInteger(
    const std::vector<unsigned char> &bytes,
    std::size_t offset,
    std::size_t size)
{
  std::uint64_t value = 0;
  if ( inf_is_be() )
  {
    for ( std::size_t index = 0; index < size; ++index )
      value = (value << 8) | bytes[offset + index];
  }
  else
  {
    for ( std::size_t index = 0; index < size; ++index )
      value |= static_cast<std::uint64_t>(bytes[offset + index]) << (index * 8);
  }
  return value;
}

std::string IntegerText(std::uint64_t value, std::size_t size)
{
  std::ostringstream output;
  output << "0x" << std::hex << std::setfill('0') << std::setw(static_cast<int>(size * 2)) << value
         << " (" << std::dec << value << ")";
  return output.str();
}

bool ReadMemory(ea_t address, std::size_t size, std::vector<unsigned char> *bytes)
{
  if ( size > static_cast<std::size_t>((std::numeric_limits<ssize_t>::max)()) ) return false;
  if ( size != 0 && address > BADADDR - static_cast<ea_t>(size - 1) ) return false;
  bytes->assign(size, 0);
  return size == 0
      || get_bytes(bytes->data(), static_cast<ssize_t>(size), address, GMB_READALL)
          == static_cast<ssize_t>(size);
}

TypedFieldValue FieldValue(
    std::string name,
    std::string declaration,
    std::uint64_t byte_offset,
    std::uint64_t size,
    bool parse_integer,
    bool pointer,
    const std::vector<unsigned char> &bytes)
{
  TypedFieldValue result{
      std::move(name), std::move(declaration), byte_offset, size, "hex", {}, false};
  if ( byte_offset >= bytes.size() )
  {
    result.truncated = size != 0;
    return result;
  }
  const std::size_t offset = static_cast<std::size_t>(byte_offset);
  const std::size_t stable_size = size > (std::numeric_limits<std::size_t>::max)()
      ? (std::numeric_limits<std::size_t>::max)() : static_cast<std::size_t>(size);
  const std::size_t available = (std::min)(stable_size, bytes.size() - offset);
  const bool integer_width = stable_size == 1 || stable_size == 2
      || stable_size == 4 || stable_size == 8;
  if ( parse_integer && integer_width && available == stable_size )
  {
    const std::uint64_t value = DecodeInteger(bytes, offset, stable_size);
    result.format = pointer ? "pointer" : "integer";
    result.value = pointer ? rpc::FormatAddress(value) : IntegerText(value, stable_size);
    return result;
  }
  const std::size_t displayed = (std::min)(available, MaxRawFieldBytes);
  result.value = Hex(bytes, offset, displayed);
  result.truncated = available < stable_size || displayed < stable_size;
  return result;
}

std::optional<TypedValueResult> BuildTypedValue(
    ea_t address,
    const tinfo_t &type,
    std::string name,
    std::uint32_t ordinal,
    std::uint32_t max_bytes)
{
  const std::size_t size = type.get_size();
  if ( size == BADSIZE || size > MaxJsonInteger ) return std::nullopt;
  const std::size_t read_size = (std::min)(size, static_cast<std::size_t>(max_bytes));
  std::vector<unsigned char> bytes;
  if ( !ReadMemory(address, read_size, &bytes) ) return std::nullopt;
  auto details = Details(
      type, std::move(name), ordinal, MaxDetailMembers, MaxDetailRelatedTypes,
      MaxDetailDeclarationBytes);
  if ( !details ) return std::nullopt;

  TypedValueResult result;
  result.address = address;
  result.type = std::move(*details);
  result.bytes = Hex(bytes);
  result.bytes_read = static_cast<std::uint64_t>(bytes.size());
  result.original_size = static_cast<std::uint64_t>(size);
  result.truncated = read_size < size;

  if ( type.is_udt() )
  {
    const int member_count = type.get_udt_nmembers();
    if ( member_count < 0 || static_cast<std::size_t>(member_count) > MaxTypeMembersInspected )
    {
      result.fields_truncated = member_count != 0;
      return result;
    }
    udt_type_data_t members;
    if ( !type.get_udt_details(&members) ) return std::nullopt;
    for ( const udm_t &member : members )
    {
      if ( result.fields.size() == MaxValueFields )
      {
        result.fields_truncated = true;
        break;
      }
      if ( member.offset / 8 > MaxJsonInteger || member.size > MaxJsonInteger * 8 )
      {
        result.fields_truncated = true;
        continue;
      }
      std::string member_name(member.name.c_str(), member.name.length());
      if ( member_name.find('\0') != std::string::npos || member_name.size() > 1024
        || !is_valid_utf8(member_name.c_str()) )
      {
        result.fields_truncated = true;
        continue;
      }
      const std::uint64_t byte_offset = member.offset / 8;
      const std::uint64_t byte_size = (member.size + 7) / 8;
      result.fields.push_back(FieldValue(
          member_name,
          Declaration(member.type, member_name.c_str(), MaxMemberDeclarationBytes).text,
          byte_offset,
          byte_size,
          member.offset % 8 == 0 && member.size % 8 == 0,
          member.offset % 8 == 0 && member.size % 8 == 0 && member.type.is_ptr(),
          bytes));
      if ( member.offset % 8 != 0 || member.size % 8 != 0 )
        result.fields.back().truncated = true;
    }
  }
  else
  {
    result.fields.push_back(FieldValue(
        result.type.summary.name,
        result.type.declaration,
        0,
        static_cast<std::uint64_t>(size),
        true,
        type.is_ptr(),
        bytes));
  }
  return result;
}

} // namespace

TypedValueOutcome TypeService::ReadValue(
    std::uint64_t address,
    std::string_view name,
    std::uint32_t max_bytes) const
{
  const auto ea = CheckedAddress(address);
  if ( !ea ) return {TypeStatus::InvalidAddress, std::nullopt};
  tinfo_t type;
  const std::string stable_name(name);
  if ( !type.get_named_type(stable_name.c_str()) ) return {TypeStatus::NotFound, std::nullopt};
  const int32 ordinal = get_type_ordinal(nullptr, stable_name.c_str());
  auto result = BuildTypedValue(
      *ea, type, stable_name, ordinal > 0 ? static_cast<std::uint32_t>(ordinal) : 0,
      max_bytes);
  return result ? TypedValueOutcome{TypeStatus::Success, std::move(result)}
                : TypedValueOutcome{TypeStatus::InvalidAddress, std::nullopt};
}

TypedValueOutcome TypeService::ReadStruct(
    std::uint64_t address,
    std::string_view name,
    std::uint32_t max_bytes) const
{
  const auto ea = CheckedAddress(address);
  if ( !ea ) return {TypeStatus::InvalidAddress, std::nullopt};
  tinfo_t type;
  std::string stable_name(name);
  std::uint32_t ordinal = 0;
  if ( stable_name.empty() )
  {
    if ( !get_tinfo(&type, *ea) || !type.is_udt() ) return {TypeStatus::NotFound, std::nullopt};
    qstring detected_name;
    if ( type.get_type_name(&detected_name) )
      stable_name.assign(detected_name.c_str(), detected_name.length());
    if ( stable_name.empty() ) stable_name = "<anonymous>";
    ordinal = type.get_ordinal();
  }
  else
  {
    if ( !type.get_named_type(stable_name.c_str()) || !type.is_udt() )
      return {TypeStatus::NotFound, std::nullopt};
    const int32 found_ordinal = get_type_ordinal(nullptr, stable_name.c_str());
    if ( found_ordinal > 0 ) ordinal = static_cast<std::uint32_t>(found_ordinal);
  }
  auto result = BuildTypedValue(*ea, type, stable_name, ordinal, max_bytes);
  return result ? TypedValueOutcome{TypeStatus::Success, std::move(result)}
                : TypedValueOutcome{TypeStatus::InvalidAddress, std::nullopt};
}

GlobalValueOutcome TypeService::GlobalValue(
    const std::optional<std::uint64_t> &address,
    const std::optional<std::string> &symbol,
    std::uint32_t max_bytes) const
{
  if ( address.has_value() == symbol.has_value() )
    return {TypeStatus::InvalidArgument, std::nullopt};
  ea_t ea = BADADDR;
  if ( address )
  {
    const auto checked = CheckedAddress(*address);
    if ( !checked ) return {TypeStatus::InvalidAddress, std::nullopt};
    ea = *checked;
  }
  else
  {
    ea = get_name_ea(BADADDR, symbol->c_str());
    if ( ea == BADADDR ) return {TypeStatus::NotFound, std::nullopt};
    if ( !is_mapped(ea) ) return {TypeStatus::InvalidAddress, std::nullopt};
  }

  tinfo_t type;
  const bool has_type = get_tinfo(&type, ea);
  std::size_t size = has_type ? type.get_size() : BADSIZE;
  if ( size == BADSIZE || size == 0 ) size = get_item_size(ea);
  if ( size == 0 || size == BADSIZE || size > MaxJsonInteger )
    return {TypeStatus::NotFound, std::nullopt};

  const bool scalar = size == 1 || size == 2 || size == 4 || size == 8;
  const bool pointer = has_type && type.is_ptr();
  std::size_t read_size = (std::min)(size, static_cast<std::size_t>(max_bytes));
  if ( !scalar && !pointer ) read_size = (std::min)(read_size, MaxRawGlobalBytes);
  std::vector<unsigned char> bytes;
  if ( !ReadMemory(ea, read_size, &bytes) ) return {TypeStatus::InvalidAddress, std::nullopt};

  GlobalValueResult result;
  result.address = ea;
  result.symbol = symbol;
  result.size = static_cast<std::uint64_t>(size);
  result.bytes_read = static_cast<std::uint64_t>(read_size);
  result.truncated = read_size < size;
  if ( has_type )
  {
    PrintedText declaration = Declaration(type);
    if ( !declaration.text.empty() ) result.declaration = std::move(declaration.text);
  }
  if ( scalar && read_size == size )
  {
    const std::uint64_t value = DecodeInteger(bytes, 0, size);
    result.format = pointer ? "pointer" : "integer";
    result.value = pointer ? rpc::FormatAddress(value) : IntegerText(value, size);
  }
  else
  {
    result.format = "hex";
    result.value = Hex(bytes);
  }
  return {TypeStatus::Success, std::move(result)};
}

} // namespace ida_agent::services
