#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace ida_agent::rpc
{

std::uint64_t ParseAddress(std::string_view encoded);
std::string FormatAddress(std::uint64_t address);

} // namespace ida_agent::rpc
