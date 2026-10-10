#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace ida_agent::rpc
{

struct XrefQueryCursor
{
  bool data_phase;
  std::uint64_t next_index;
};

std::string EncodeXrefQueryCursor(
    std::string_view query_identity,
    bool data_phase,
    std::uint64_t next_index);
XrefQueryCursor DecodeXrefQueryCursor(
    std::string_view cursor,
    std::string_view query_identity);

} // namespace ida_agent::rpc
