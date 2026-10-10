#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace ida_agent::rpc
{

std::string EncodeListCursor(
    std::string_view kind,
    std::string_view query_identity,
    std::uint64_t next_position);
std::uint64_t DecodeListCursor(
    std::string_view kind,
    std::string_view cursor,
    std::string_view query_identity);

} // namespace ida_agent::rpc
