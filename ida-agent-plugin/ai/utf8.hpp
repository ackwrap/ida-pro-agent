#pragma once
#include <cstdint>
#include <string_view>

namespace ida_agent::ai
{
inline bool ValidUtf8(std::string_view text)
{
  for (std::size_t i = 0; i < text.size();)
  {
    const auto first = static_cast<unsigned char>(text[i++]);
    if (first < 0x80) continue;
    unsigned remaining;
    std::uint32_t code, minimum;
    if (first >= 0xc2 && first <= 0xdf) { remaining = 1; code = first & 0x1f; minimum = 0x80; }
    else if (first >= 0xe0 && first <= 0xef) { remaining = 2; code = first & 0xf; minimum = 0x800; }
    else if (first >= 0xf0 && first <= 0xf4) { remaining = 3; code = first & 7; minimum = 0x10000; }
    else return false;
    if (remaining > text.size() - i) return false;
    while (remaining--)
    {
      const auto next = static_cast<unsigned char>(text[i++]);
      if (next < 0x80 || next > 0xbf) return false;
      code = (code << 6) | (next & 0x3f);
    }
    if (code < minimum || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return false;
  }
  return true;
}
}
