#include "address.hpp"

#include <charconv>
#include <stdexcept>

namespace ida_agent::rpc
{

std::uint64_t ParseAddress(std::string_view encoded)
{
  if ( encoded.size() < 3 || encoded.substr(0, 2) != "0x" )
    throw std::invalid_argument("address must start with 0x");

  const std::string_view digits = encoded.substr(2);
  if ( digits.empty() || digits.size() > 16 )
    throw std::invalid_argument("address must contain 1 to 16 hexadecimal digits");

  std::uint64_t address = 0;
  const auto result = std::from_chars(digits.data(), digits.data() + digits.size(), address, 16);
  if ( result.ec != std::errc{} || result.ptr != digits.data() + digits.size() )
    throw std::invalid_argument("address contains invalid hexadecimal digits");
  return address;
}

std::string FormatAddress(std::uint64_t address)
{
  char buffer[18] = {'0', 'x'};
  const auto result = std::to_chars(buffer + 2, buffer + sizeof(buffer), address, 16);
  if ( result.ec != std::errc{} )
    throw std::runtime_error("failed to format address");
  return std::string(buffer, result.ptr);
}

} // namespace ida_agent::rpc
