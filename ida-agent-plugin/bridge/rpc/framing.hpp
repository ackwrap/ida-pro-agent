#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace ida_agent::rpc
{

inline constexpr std::uint8_t FramingVersion = 1;
inline constexpr std::size_t RequestHeaderBytes = 9;
inline constexpr std::size_t ResponseHeaderBytes = 9;

struct RequestFrameHeader
{
  std::uint32_t payload_size;
};

RequestFrameHeader ParseRequestFrameHeader(
    const std::array<std::uint8_t, RequestHeaderBytes> &encoded);
std::array<std::uint8_t, ResponseHeaderBytes> BuildResponseFrameHeader(
    std::uint32_t payload_size);

} // namespace ida_agent::rpc
