#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace ida_agent::rpc
{

std::string EncodeFunctionSearchCursor(
    std::string_view normalized_query,
    std::uint64_t next_address);
std::uint64_t DecodeFunctionSearchCursor(
    std::string_view cursor,
    std::string_view normalized_query);

} // namespace ida_agent::rpc
