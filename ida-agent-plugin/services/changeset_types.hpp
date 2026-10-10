#pragma once

#include "changeset_service.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace ida_agent::services::detail
{
ChangeStatus ValidateTypeChange(ChangeKind kind, std::string_view declaration);
std::optional<std::string> CurrentTypeDeclaration(ChangeKind kind, std::string_view declaration);
std::optional<std::string> DesiredTypeDeclaration(ChangeKind kind, std::string_view declaration);
bool ApplyTypeDeclaration(ChangeKind kind, std::string_view declaration);
}
