#include "changeset_types.hpp"

#include <typeinf.hpp>

#include <cstdint>
#include <string>

namespace ida_agent::services::detail
{
namespace
{
struct ParsedEnum
{
  tinfo_t type;
  qstring name;
  std::string declaration;
};

std::optional<std::string> PrintDeclaration(const tinfo_t &type, const qstring &name, bool definition)
{
  qstring declaration;
  const int flags = PRTYPE_1LINE | PRTYPE_SEMI | (definition ? PRTYPE_DEF | PRTYPE_TYPE : 0);
  if ( !type.print(&declaration, name.c_str(), flags) ) return std::nullopt;
  return std::string(declaration.c_str(), declaration.length());
}

std::optional<ParsedEnum> ParseEnum(std::string_view declaration)
{
  ParsedEnum result;
  const std::string input(declaration);
  if ( !parse_decl(&result.type, &result.name, get_idati(), input.c_str(), PT_SIL | PT_TYP)
    || result.name.empty() || !result.type.is_enum() ) return std::nullopt;
  const auto canonical = PrintDeclaration(result.type, result.name, true);
  if ( !canonical ) return std::nullopt;
  result.declaration = *canonical;
  return result;
}

std::optional<std::string> CurrentEnum(const ParsedEnum &parsed)
{
  const int32 ordinal = get_type_ordinal(get_idati(), parsed.name.c_str());
  if ( ordinal <= 0 ) return std::string{};
  tinfo_t existing;
  if ( !existing.get_numbered_type(get_idati(), static_cast<std::uint32_t>(ordinal), BTF_ENUM, true)
    || !existing.is_enum() ) return std::nullopt;
  return PrintDeclaration(existing, parsed.name, true);
}
}

ChangeStatus ValidateTypeChange(ChangeKind kind, std::string_view declaration)
{
  if ( kind != ChangeKind::EnumUpsert ) return ChangeStatus::Success;
  const auto parsed = ParseEnum(declaration);
  if ( !parsed ) return ChangeStatus::InvalidArgument;
  const int32 ordinal = get_type_ordinal(get_idati(), parsed->name.c_str());
  if ( ordinal <= 0 )
  {
    const int found = get_named_type(get_idati(), parsed->name.c_str(), NTF_TYPE);
    return found == 0 ? ChangeStatus::Success : ChangeStatus::Conflict;
  }
  tinfo_t existing;
  if ( !existing.get_numbered_type(get_idati(), static_cast<std::uint32_t>(ordinal), BTF_ENUM, true)
    || !existing.is_enum() ) return ChangeStatus::Conflict;
  return PrintDeclaration(existing, parsed->name, true) ? ChangeStatus::Success : ChangeStatus::Failed;
}

std::optional<std::string> CurrentTypeDeclaration(ChangeKind kind, std::string_view declaration)
{
  if ( kind == ChangeKind::EnumUpsert )
  {
    const auto parsed = ParseEnum(declaration);
    return parsed ? CurrentEnum(*parsed) : std::nullopt;
  }
  if ( kind != ChangeKind::DeclareType ) return std::nullopt;
  tinfo_t parsed;
  qstring name;
  const std::string input(declaration);
  if ( !parse_decl(&parsed, &name, get_idati(), input.c_str(), PT_SIL | PT_TYP) ) return std::nullopt;
  if ( name.empty() ) return std::string{};
  tinfo_t existing;
  if ( !existing.get_named_type(name.c_str()) ) return std::string{};
  return PrintDeclaration(existing, name, false).value_or(std::string{});
}

std::optional<std::string> DesiredTypeDeclaration(ChangeKind kind, std::string_view declaration)
{
  if ( kind != ChangeKind::EnumUpsert ) return std::string(declaration);
  const auto parsed = ParseEnum(declaration);
  return parsed ? std::optional<std::string>(parsed->declaration) : std::nullopt;
}

bool ApplyTypeDeclaration(ChangeKind kind, std::string_view declaration)
{
  const std::string input(declaration);
  if ( kind == ChangeKind::DeclareType )
    return parse_decls(get_idati(), input.c_str(), nullptr, 0) == 0;
  if ( kind != ChangeKind::EnumUpsert || ValidateTypeChange(kind, declaration) != ChangeStatus::Success )
    return false;
  const auto desired = DesiredTypeDeclaration(kind, declaration);
  const auto current = CurrentTypeDeclaration(kind, declaration);
  if ( !desired || !current ) return false;
  if ( *current == *desired ) return true;
  if ( parse_decls(get_idati(), input.c_str(), nullptr, HTI_NWR) != 0 ) return false;
  const auto updated = CurrentTypeDeclaration(kind, declaration);
  return updated && *updated == *desired;
}
}
