#include "framing.hpp"

#include "envelope.hpp"

#include <algorithm>
#include <stdexcept>

namespace ida_agent::rpc
{
namespace
{

constexpr std::array<std::uint8_t, 4> RequestMagic = {'I', 'M', 'C', 'P'};
constexpr std::array<std::uint8_t, 4> ResponseMagic = {'I', 'M', 'C', 'R'};

std::uint32_t ReadBigEndian(const std::uint8_t *encoded)
{
  return (static_cast<std::uint32_t>(encoded[0]) << 24)
      | (static_cast<std::uint32_t>(encoded[1]) << 16)
      | (static_cast<std::uint32_t>(encoded[2]) << 8)
      | static_cast<std::uint32_t>(encoded[3]);
}

void WriteBigEndian(std::uint8_t *encoded, std::uint32_t value)
{
  encoded[0] = static_cast<std::uint8_t>(value >> 24);
  encoded[1] = static_cast<std::uint8_t>(value >> 16);
  encoded[2] = static_cast<std::uint8_t>(value >> 8);
  encoded[3] = static_cast<std::uint8_t>(value);
}

} // namespace

RequestFrameHeader ParseRequestFrameHeader(
    const std::array<std::uint8_t, RequestHeaderBytes> &encoded)
{
  if ( !std::equal(RequestMagic.begin(), RequestMagic.end(), encoded.begin()) )
    throw std::invalid_argument("request frame magic is invalid");
  if ( encoded[4] != FramingVersion )
    throw std::invalid_argument("request framing version is unsupported");

  RequestFrameHeader header{};
  header.payload_size = ReadBigEndian(encoded.data() + 5);
  if ( header.payload_size == 0 || header.payload_size > MaxMessageBytes )
    throw std::invalid_argument("request payload size is invalid");
  return header;
}

std::array<std::uint8_t, ResponseHeaderBytes> BuildResponseFrameHeader(
    std::uint32_t payload_size)
{
  if ( payload_size == 0 || payload_size > MaxMessageBytes )
    throw std::invalid_argument("response payload size is invalid");

  std::array<std::uint8_t, ResponseHeaderBytes> encoded{};
  std::copy(ResponseMagic.begin(), ResponseMagic.end(), encoded.begin());
  encoded[4] = FramingVersion;
  WriteBigEndian(encoded.data() + 5, payload_size);
  return encoded;
}

} // namespace ida_agent::rpc
