#include "safe_regex.hpp"

#include <cstddef>

namespace ida_agent::services
{

bool IsSafeRegex(std::string_view pattern)
{
  if ( pattern.empty() || pattern.size() > 256 ) return false;
  bool escaped = false;
  bool character_class = false;
  std::size_t unbounded_quantifiers = 0;
  for ( char character : pattern )
  {
    if ( escaped )
    {
      if ( character >= '0' && character <= '9' ) return false;
      escaped = false;
      continue;
    }
    if ( character == '\\' ) { escaped = true; continue; }
    if ( character == '[' ) { character_class = true; continue; }
    if ( character == ']' && character_class ) { character_class = false; continue; }
    if ( character_class ) continue;
    if ( character == '(' || character == ')' || character == '{' || character == '}'
      || character == '|' || character == '?' ) return false;
    if ( (character == '*' || character == '+') && ++unbounded_quantifiers > 1 ) return false;
  }
  return !escaped && !character_class;
}

} // namespace ida_agent::services
