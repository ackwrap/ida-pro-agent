#pragma once

#include "debugger_service.hpp"

namespace ida_agent::services::detail
{
std::string Lower(std::string value);
bool Available();
DebuggerActionOutcome Action(bool accepted);
} // namespace ida_agent::services::detail
