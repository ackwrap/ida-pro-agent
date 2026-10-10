#pragma once

#include "changeset_service.hpp"

#include <optional>
#include <string>

namespace ida_agent::services::detail
{

std::optional<std::string> CurrentOperandState(const ChangeOperation &operation);
std::optional<std::string> DesiredOperandState(const ChangeOperation &operation);
bool ApplyOperand(const ChangeOperation &operation);

} // namespace ida_agent::services::detail
