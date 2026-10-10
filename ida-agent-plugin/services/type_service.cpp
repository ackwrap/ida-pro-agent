#include "type_service_internal.hpp"

#include "inventory_text.hpp"

#include <typeinf.hpp>

#include <set>
#include <utility>

namespace ida_agent::services::type_service_detail
{

const std::uint32_t MaxOrdinals = 1000000;
const std::size_t MaxTypeMembersInspected = 4096;
const std::size_t MaxQueryMembers = 16;
const std::size_t MaxDetailMembers = 256;
const std::size_t MaxQueryRelatedTypes = 16;
const std::size_t MaxDetailRelatedTypes = 256;
const std::size_t MaxValueFields = 256;
const std::size_t MaxRawFieldBytes = 16;
const std::size_t MaxRawGlobalBytes = 64;
const std::size_t MaxQueryDeclarationBytes = 4096;
const std::size_t MaxDetailDeclarationBytes = 16384;
const std::size_t MaxMemberDeclarationBytes = 4096;
const std::uint64_t MaxJsonInteger = 9007199254740991ULL;

std::string Kind(const tinfo_t &type)
{
  if ( type.is_enum() ) return "enum";
  if ( type.is_typedef() ) return "typedef";
  if ( type.is_func() ) return "function";
  if ( type.is_ptr() ) return "pointer";
  if ( type.is_array() ) return "array";
  if ( type.is_struct() ) return "struct";
  if ( type.is_union() ) return "union";
  return "other";
}

PrintedText Declaration(
    const tinfo_t &type,
    const char *name,
    std::size_t maximum_bytes)
{
  qstring printed;
  if ( !type.print(&printed, name, PRTYPE_1LINE | PRTYPE_SEMI) ) return {};
  std::string value(printed.c_str(), printed.length());
  if ( value.find('\0') != std::string::npos || !is_valid_utf8(value.c_str())
    || value.size() > MaxJsonInteger ) return {};
  return {
      TruncateUtf8Bytes(value, maximum_bytes),
      static_cast<std::uint64_t>(value.size()),
      value.size() > maximum_bytes,
  };
}

namespace
{

std::string RelatedName(const tinfo_t &type)
{
  qstring name;
  if ( type.get_type_name(&name) && !name.empty() )
  {
    std::string stable(name.c_str(), name.length());
    if ( stable.find('\0') == std::string::npos && stable.size() <= 1024
      && is_valid_utf8(stable.c_str()) ) return stable;
  }
  return Declaration(type, nullptr, 1024).text;
}

void AddRelated(std::set<std::string> *related, std::string value, std::string_view self)
{
  if ( value.empty() || value == self || value.find('\0') != std::string::npos
    || value.size() > 1024 || !is_valid_utf8(value.c_str()) ) return;
  related->insert(std::move(value));
}

} // namespace

std::optional<TypeDetails> Details(
    const tinfo_t &type,
    std::string name,
    std::uint32_t ordinal,
    std::size_t maximum_members,
    std::size_t maximum_related,
    std::size_t maximum_declaration_bytes)
{
  const std::size_t raw_size = type.get_size();
  const std::uint64_t size = raw_size == BADSIZE ? 0 : static_cast<std::uint64_t>(raw_size);
  if ( size > MaxJsonInteger ) return std::nullopt;

  TypeDetails result;
  result.summary = {ordinal, std::move(name), Kind(type), size};
  PrintedText declaration = Declaration(type, nullptr, maximum_declaration_bytes);
  result.declaration = std::move(declaration.text);
  result.declaration_original_size = declaration.original_size;
  result.declaration_truncated = declaration.truncated;

  std::set<std::string> related;
  bool relationship_scan_truncated = false;
  if ( type.is_udt() )
  {
    const int reported_count = type.get_udt_nmembers();
    if ( reported_count > 0 ) result.member_count = static_cast<std::uint64_t>(reported_count);
    if ( reported_count < 0 || static_cast<std::size_t>(reported_count) > MaxTypeMembersInspected )
    {
      result.members_truncated = reported_count != 0;
      relationship_scan_truncated = reported_count != 0;
    }
    else
    {
      udt_type_data_t members;
      if ( !type.get_udt_details(&members) ) return std::nullopt;
      result.member_count = static_cast<std::uint64_t>(members.size());
      for ( const udm_t &member : members )
      {
        AddRelated(&related, RelatedName(member.type), result.summary.name);
        if ( result.members.size() >= maximum_members )
        {
          result.members_truncated = true;
          continue;
        }
        if ( member.offset > MaxJsonInteger || member.size > MaxJsonInteger )
        {
          result.members_truncated = true;
          continue;
        }
        std::string member_name(member.name.c_str(), member.name.length());
        if ( member_name.find('\0') != std::string::npos || member_name.size() > 1024
          || !is_valid_utf8(member_name.c_str()) )
        {
          result.members_truncated = true;
          continue;
        }
        PrintedText member_declaration = Declaration(
            member.type, member_name.c_str(), MaxMemberDeclarationBytes);
        result.members.push_back({
            std::move(member_name),
            std::move(member_declaration.text),
            member.offset,
            member.size,
        });
        result.members_truncated = result.members_truncated || member_declaration.truncated;
      }
    }
  }
  if ( type.is_enum() )
  {
    const std::size_t reported_count = type.get_enum_nmembers();
    if ( reported_count == BADSIZE ) return std::nullopt;
    result.enum_member_count = static_cast<std::uint64_t>(reported_count);
    if ( reported_count > MaxTypeMembersInspected )
    {
      result.enum_members_truncated = true;
    }
    else
    {
      enum_type_data_t members;
      if ( !type.get_enum_details(&members) ) return std::nullopt;
      result.enum_member_count = static_cast<std::uint64_t>(members.size());
      for ( const edm_t &member : members )
      {
        if ( result.enum_members.size() >= maximum_members )
        {
          result.enum_members_truncated = true;
          continue;
        }
        std::string stable_name(member.name.c_str(), member.name.length());
        if ( stable_name.find('\0') != std::string::npos || stable_name.size() > 1024
          || !is_valid_utf8(stable_name.c_str()) )
        {
          result.enum_members_truncated = true;
          continue;
        }
        result.enum_members.push_back({std::move(stable_name), member.value});
      }
    }
  }

  if ( type.is_ptr() ) AddRelated(&related, RelatedName(type.get_pointed_object()), result.summary.name);
  if ( type.is_array() ) AddRelated(&related, RelatedName(type.get_array_element()), result.summary.name);
  if ( type.is_func() )
  {
    func_type_data_t function;
    if ( type.get_func_details(&function) )
    {
      AddRelated(&related, RelatedName(function.rettype), result.summary.name);
      for ( const funcarg_t &argument : function )
        AddRelated(&related, RelatedName(argument.type), result.summary.name);
    }
  }
  if ( type.is_typedef() )
  {
    qstring target;
    if ( type.get_next_type_name(&target) )
      AddRelated(&related, std::string(target.c_str(), target.length()), result.summary.name);
    else if ( type.get_final_type_name(&target) )
      AddRelated(&related, std::string(target.c_str(), target.length()), result.summary.name);
  }

  result.related_type_count = static_cast<std::uint64_t>(related.size());
  for ( const std::string &item : related )
  {
    if ( result.related_types.size() == maximum_related )
    {
      result.related_types_truncated = true;
      break;
    }
    result.related_types.push_back(item);
  }
  result.related_types_truncated = result.related_types_truncated || relationship_scan_truncated;
  return result;
}

std::optional<ea_t> CheckedAddress(std::uint64_t address)
{
  const ea_t result = static_cast<ea_t>(address);
  if ( static_cast<std::uint64_t>(result) != address || result == BADADDR || !is_mapped(result) )
    return std::nullopt;
  return result;
}

} // namespace ida_agent::services::type_service_detail
