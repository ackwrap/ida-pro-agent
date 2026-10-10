#pragma once

#include "type_service.hpp"

#include <ida.hpp>
#include <typeinf.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace ida_agent::services::type_service_detail
{

extern const std::uint32_t MaxOrdinals;
extern const std::size_t MaxTypeMembersInspected;
extern const std::size_t MaxQueryMembers;
extern const std::size_t MaxDetailMembers;
extern const std::size_t MaxQueryRelatedTypes;
extern const std::size_t MaxDetailRelatedTypes;
extern const std::size_t MaxValueFields;
extern const std::size_t MaxRawFieldBytes;
extern const std::size_t MaxRawGlobalBytes;
extern const std::size_t MaxQueryDeclarationBytes;
extern const std::size_t MaxDetailDeclarationBytes;
extern const std::size_t MaxMemberDeclarationBytes;
extern const std::uint64_t MaxJsonInteger;

struct PrintedText
{
  std::string text;
  std::uint64_t original_size = 0;
  bool truncated = false;
};

std::string Kind(const tinfo_t &type);
PrintedText Declaration(
    const tinfo_t &type,
    const char *name = nullptr,
    std::size_t maximum_bytes = MaxDetailDeclarationBytes);
std::optional<TypeDetails> Details(
    const tinfo_t &type,
    std::string name,
    std::uint32_t ordinal,
    std::size_t maximum_members,
    std::size_t maximum_related,
    std::size_t maximum_declaration_bytes);
std::optional<ea_t> CheckedAddress(std::uint64_t address);

} // namespace ida_agent::services::type_service_detail
