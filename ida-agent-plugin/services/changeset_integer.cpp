#include "changeset_integer.hpp"

#include <charconv>
#include <cstdint>
#include <exception>
#include <limits>
#include <string>

namespace ida_agent::services::detail
{
std::optional<std::vector<unsigned char>> EncodeInteger(std::string_view value, std::string_view type)
{
  if ( value.empty() || type.empty() ) return std::nullopt;
  const bool signed_value = type.front() == 'i';
  const bool big_endian = type.size() > 2 && type.substr(type.size() - 2) == "be";
  std::size_t digits_end = 1;
  while ( digits_end < type.size() && type[digits_end] >= '0' && type[digits_end] <= '9' ) ++digits_end;
  int bits = 0;
  try { bits = std::stoi(std::string(type.substr(1, digits_end - 1))); }
  catch ( const std::exception & ) { return std::nullopt; }
  if ( (type.front() != 'u' && type.front() != 'i') || (bits != 8 && bits != 16 && bits != 32 && bits != 64)
    || (digits_end != type.size() && type.substr(digits_end) != "le" && type.substr(digits_end) != "be") ) return std::nullopt;
  while ( !value.empty() && (value.front() == ' ' || value.front() == '\t' || value.front() == '\r' || value.front() == '\n') ) value.remove_prefix(1);
  while ( !value.empty() && (value.back() == ' ' || value.back() == '\t' || value.back() == '\r' || value.back() == '\n') ) value.remove_suffix(1);
  if ( value.empty() ) return std::nullopt;
  bool negative = false;
  if ( value.front() == '+' || value.front() == '-' ) { negative = value.front() == '-'; value.remove_prefix(1); }
  if ( value.empty() || (negative && !signed_value) ) return std::nullopt;
  int base = 10;
  if ( value.size() > 2 && value[0] == '0' )
  {
    if ( value[1] == 'x' || value[1] == 'X' ) base = 16;
    else if ( value[1] == 'b' || value[1] == 'B' ) base = 2;
    else if ( value[1] == 'o' || value[1] == 'O' ) base = 8;
    if ( base != 10 ) value.remove_prefix(2);
  }
  if ( value.empty() ) return std::nullopt;
  std::uint64_t magnitude = 0;
  const auto parsed = std::from_chars(value.data(), value.data() + value.size(), magnitude, base);
  if ( parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() ) return std::nullopt;
  const std::uint64_t signed_limit = std::uint64_t(1) << (bits - 1);
  const std::uint64_t unsigned_limit = bits == 64 ? (std::numeric_limits<std::uint64_t>::max)() : (std::uint64_t(1) << bits) - 1;
  if ( signed_value ) { if ( negative ? magnitude > signed_limit : magnitude >= signed_limit ) return std::nullopt; }
  else if ( magnitude > unsigned_limit ) return std::nullopt;
  const std::uint64_t encoded = negative ? std::uint64_t(0) - magnitude : magnitude;
  const std::size_t size = static_cast<std::size_t>(bits / 8);
  std::vector<unsigned char> bytes(size);
  for ( std::size_t index = 0; index < size; ++index )
  {
    const std::size_t destination = big_endian ? size - index - 1 : index;
    bytes[destination] = static_cast<unsigned char>((encoded >> (index * 8)) & 0xFF);
  }
  return bytes;
}
}
