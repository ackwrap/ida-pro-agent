#include "xref_query_cursor.hpp"

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

std::uint64_t PhaseHash(std::string_view query_identity, bool data_phase)
{
  std::string value(query_identity);
  value += data_phase ? "|data" : "|code";
  return Hash(value);
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
      throw std::invalid_argument("xref query cursor is invalid");
    }
  }
  std::uint64_t result = 0;
  const auto parsed = std::from_chars(
      value.data(),
      value.data() + value.size(),
      result,
      16);
  if ( parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() )
    throw std::invalid_argument("xref query cursor is invalid");
  return result;
}

} // namespace

std::string EncodeXrefQueryCursor(
    std::string_view query_identity,
    bool data_phase,
    std::uint64_t next_index)
{
  const std::string body =
      "xq2." + Hex(PhaseHash(query_identity, data_phase)) + "." + Hex(next_index);
  return body + "." + Hex(Hash(body));
}

XrefQueryCursor DecodeXrefQueryCursor(
    std::string_view cursor,
    std::string_view query_identity)
{
  if ( cursor.size() != 54 || cursor.substr(0, 4) != "xq2."
    || cursor[20] != '.' || cursor[37] != '.' )
  {
    throw std::invalid_argument("xref query cursor is invalid");
  }
  const std::string_view body = cursor.substr(0, 37);
  if ( ParseHex(cursor.substr(38, 16)) != Hash(body) )
    throw std::invalid_argument("xref query cursor checksum is invalid");

  const std::uint64_t phase_hash = ParseHex(cursor.substr(4, 16));
  bool data_phase = false;
  if ( phase_hash == PhaseHash(query_identity, true) )
    data_phase = true;
  else if ( phase_hash != PhaseHash(query_identity, false) )
    throw std::invalid_argument("xref query cursor does not match the query");
  return {data_phase, ParseHex(cursor.substr(21, 16))};
}

} // namespace ida_agent::rpc
