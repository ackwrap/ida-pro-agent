#pragma once

#include <optional>
#include <string_view>
#include <vector>

namespace ida_agent::services::detail
{
std::optional<std::vector<unsigned char>> EncodeInteger(std::string_view value, std::string_view type);
}
