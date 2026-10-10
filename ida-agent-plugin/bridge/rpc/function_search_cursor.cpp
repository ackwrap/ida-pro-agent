#include "function_search_cursor.hpp"

#include <charconv>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace ida_agent::rpc
{
namespace
{

std::uint64_t Hash(std::string_view value)
{
  std::uint64_t result = 14695981039346656037ULL;
  for ( unsigned char character : value )
  {
    result ^= character;
    result *= 1099511628211ULL;
  }
  return result;
}

std::string Hex(std::uint64_t value)
{
  std::ostringstream output;
  output << std::hex << std::nouppercase << std::setfill('0') << std::setw(16) << value;
  return output.str();
}

std::uint64_t ParseHex(std::string_view value)
{
  for ( char character : value )
  {
    if ( (character < '0' || character > '9')
      && (character < 'a' || character > 'f') )
    {
      throw std::invalid_argument("function search cursor is invalid");
    }
  }
  std::uint64_t result = 0;
  const auto parsed = std::from_chars(
      value.data(),
      value.data() + value.size(),
      result,
      16);
  if ( parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() )
    throw std::invalid_argument("function search cursor is invalid");
  return result;
}

} // namespace

std::string EncodeFunctionSearchCursor(
    std::string_view normalized_query,
    std::uint64_t next_address)
{
  const std::string body =
      "fs1." + Hex(Hash(normalized_query)) + "." + Hex(next_address);
  return body + "." + Hex(Hash(body));
}

std::uint64_t DecodeFunctionSearchCursor(
    std::string_view cursor,
    std::string_view normalized_query)
{
  if ( cursor.size() != 54 || cursor.substr(0, 4) != "fs1."
    || cursor[20] != '.' || cursor[37] != '.' )
  {
    throw std::invalid_argument("function search cursor is invalid");
  }
  const std::string_view body = cursor.substr(0, 37);
  if ( ParseHex(cursor.substr(4, 16)) != Hash(normalized_query)
    || ParseHex(cursor.substr(38, 16)) != Hash(body) )
  {
    throw std::invalid_argument("function search cursor does not match the query");
  }
  return ParseHex(cursor.substr(21, 16));
}

} // namespace ida_agent::rpc
