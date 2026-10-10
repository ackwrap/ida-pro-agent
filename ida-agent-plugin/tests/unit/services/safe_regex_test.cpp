#include "safe_regex.hpp"

#include "test_support.hpp"

#include <string>
#include <string_view>

int main()
{
  using ida_agent::services::IsSafeRegex;

  for ( const std::string_view valid :
        {"literal", "^anchored$", "ab*c", "ab+c", "[a-z0-9?*+(){}|]", R"(a\?b)",
         R"(\(literal\))", R"(a\|b)", R"(a\{2\})", R"(a\*b\+c)"} )
  {
    Require(IsSafeRegex(valid), "safe regex rejected");
  }

  Require(IsSafeRegex(std::string(256, 'a')), "maximum-length regex rejected");

  for ( const std::string_view invalid :
        {"", "(group)", "group)", "a|b", "a{2}", "a}", R"(a\1)", R"(a\0)", "a?",
         "a*b+", "a++", "a**", R"(trailing\)", "[unterminated"} )
  {
    Require(!IsSafeRegex(invalid), "unsafe regex accepted");
  }

  Require(!IsSafeRegex(std::string(257, 'a')), "overlong regex accepted");
  Require(IsSafeRegex(R"([?*+(){}|]\?\*\+)"), "escaped and class metacharacters rejected");
  return 0;
}
