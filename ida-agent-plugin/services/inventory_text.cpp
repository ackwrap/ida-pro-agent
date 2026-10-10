#include "inventory_text.hpp"

#include <algorithm>
#include <cstdint>

namespace ida_agent::services
{

bool Utf8CodePointCount(std::string_view value, std::size_t *count)
{
  std::size_t total = 0;
  for ( std::size_t index = 0; index < value.size(); )
  {
    const unsigned char first = static_cast<unsigned char>(value[index]);
    std::size_t width = 0;
    std::uint32_t codepoint = 0;
    if ( first <= 0x7F )
    {
      width = 1;
      codepoint = first;
    }
    else if ( first >= 0xC2 && first <= 0xDF )
    {
      width = 2;
      codepoint = first & 0x1F;
    }
    else if ( first >= 0xE0 && first <= 0xEF )
    {
      width = 3;
      codepoint = first & 0x0F;
    }
    else if ( first >= 0xF0 && first <= 0xF4 )
    {
      width = 4;
      codepoint = first & 0x07;
    }
    else
    {
      return false;
    }
    if ( index + width > value.size() )
      return false;
    for ( std::size_t continuation = 1; continuation < width; ++continuation )
    {
      const unsigned char byte = static_cast<unsigned char>(value[index + continuation]);
      if ( (byte & 0xC0) != 0x80 )
        return false;
      codepoint = (codepoint << 6) | (byte & 0x3F);
    }
    if ( (width == 2 && codepoint < 0x80)
      || (width == 3 && codepoint < 0x800)
      || (width == 4 && codepoint < 0x10000)
      || (codepoint >= 0xD800 && codepoint <= 0xDFFF)
      || codepoint > 0x10FFFF )
    {
      return false;
    }
    index += width;
    ++total;
  }
  if ( count != nullptr )
    *count = total;
  return true;
}

std::string NormalizeInventoryFilter(std::string_view value)
{
  std::string normalized(value);
  for ( char &character : normalized )
  {
    if ( character >= 'A' && character <= 'Z' )
      character = static_cast<char>(character + ('a' - 'A'));
  }
  return normalized;
}

bool InventoryFilterMatches(std::string_view value, std::string_view normalized_filter)
{
  return NormalizeInventoryFilter(value).find(normalized_filter) != std::string::npos;
}

std::string TruncateUtf8Bytes(std::string_view value, std::size_t maximum_bytes)
{
  if ( value.size() <= maximum_bytes )
    return std::string(value);
  std::size_t size = maximum_bytes;
  while ( size > 0 && (static_cast<unsigned char>(value[size]) & 0xC0) == 0x80 )
    --size;
  return std::string(value.substr(0, size));
}

} // namespace ida_agent::services
