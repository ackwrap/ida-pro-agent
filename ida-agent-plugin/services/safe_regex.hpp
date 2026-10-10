#pragma once

#include <string_view>

namespace ida_agent::services
{

bool IsSafeRegex(std::string_view pattern);

} // namespace ida_agent::services
