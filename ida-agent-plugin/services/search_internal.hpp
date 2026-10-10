#pragma once

#include <bytes.hpp>
#include <ida.hpp>
#include <lines.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <initializer_list>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace ida_agent::services::search_detail
{

inline constexpr std::size_t MaxSearchScan = 1000000;
inline constexpr std::size_t MaxTextBytes = 4096;
inline constexpr std::size_t MaxSignatureBytes = 1000;

inline bool Range(std::uint64_t start, std::uint64_t end, ea_t *first, ea_t *last)
{
  *first = static_cast<ea_t>(start);
  *last = static_cast<ea_t>(end);
  return static_cast<std::uint64_t>(*first) == start
      && static_cast<std::uint64_t>(*last) == end
      && *first != BADADDR && *last != BADADDR && *first < *last;
}

inline std::string Lower(std::string_view input)
{
  std::string value(input);
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character)
  {
    return static_cast<char>(std::tolower(character));
  });
  return value;
}

inline std::string SearchIdentity(
    std::uint64_t start,
    std::uint64_t end,
    std::initializer_list<std::string_view> fields)
{
  std::string result = std::to_string(start) + ":" + std::to_string(end);
  for ( std::string_view field : fields )
  {
    result.push_back('\0');
    result.append(field);
  }
  return result;
}

inline std::string HexBytes(ea_t address, std::size_t size)
{
  std::vector<unsigned char> bytes(size);
  if ( size == 0
    || get_bytes(bytes.data(), static_cast<ssize_t>(size), address)
        != static_cast<ssize_t>(size) )
  {
    return {};
  }
  std::ostringstream encoded;
  encoded << std::hex << std::setfill('0');
  for ( unsigned char byte : bytes )
    encoded << std::setw(2) << static_cast<unsigned>(byte);
  return encoded.str();
}

inline std::string Untag(const qstring &value)
{
  qstring clean;
  tag_remove(&clean, value);
  std::string result(clean.c_str(), clean.length());
  if ( result.size() > MaxTextBytes || !is_valid_utf8(result.c_str()) )
    return {};
  return result;
}

} // namespace ida_agent::services::search_detail
