#include "ai/jump_target_text.hpp"

#include <cctype>
#include <cstdint>
#include <vector>

namespace ida_agent::ai
{
namespace
{

bool IsNameChar(char c) noexcept
{
  const unsigned char ch = static_cast<unsigned char>(c);
  return std::isalnum(ch) != 0 || c == '_' || c == '.' || c == '$'
      || c == '@' || c == '?';
}

bool IsNameStart(char c) noexcept
{
  const unsigned char ch = static_cast<unsigned char>(c);
  return std::isalpha(ch) != 0 || c == '_' || c == '.' || c == '$'
      || c == '?';
}

bool HasSymbolMarker(const std::string &token) noexcept
{
  return token.find_first_of("_.$@") != std::string::npos;
}

bool IsHexDigit(char c) noexcept
{
  return ( c >= '0' && c <= '9' )
      || ( c >= 'a' && c <= 'f' )
      || ( c >= 'A' && c <= 'F' );
}

bool ParseHexAddress(const std::string &token, std::uint64_t &out) noexcept
{
  if ( token.size() < 3
      || token.size() > 18
      || token[0] != '0'
      || ( token[1] != 'x' && token[1] != 'X' ) )
  {
    return false;
  }
  std::uint64_t value = 0;
  for ( std::size_t index = 2; index < token.size(); ++index )
  {
    if ( !IsHexDigit(token[index]) )
      return false;
    const char c = token[index];
    const unsigned int digit = c <= '9' ? static_cast<unsigned int>(c - '0')
        : ( c <= 'F' ? static_cast<unsigned int>(c - 'A' + 10)
                     : static_cast<unsigned int>(c - 'a' + 10));
    value = value * 16 + digit;
  }
  out = value;
  return true;
}

std::vector<std::string> SplitTokens(const std::string &text)
{
  std::vector<std::string> tokens;
  std::string token;
  const auto flush = [&token, &tokens]()
  {
    while ( token.size() > 1 && token.back() == '.' )
      token.pop_back();
    if ( !token.empty() )
      tokens.push_back(token);
    token.clear();
  };
  for ( const char c : text )
  {
    if ( IsNameChar(c) )
    {
      token.push_back(c);
    }
    else
    {
      flush();
    }
  }
  flush();
  return tokens;
}

} // namespace

std::optional<JumpTargetText> ExtractJumpTarget(const std::string &selected)
{
  if ( selected.empty() )
    return std::nullopt;

  const std::vector<std::string> tokens = SplitTokens(selected);
  if ( tokens.empty() )
    return std::nullopt;

  for ( const std::string &token : tokens )
  {
    std::uint64_t address = 0;
    if ( ParseHexAddress(token, address) )
      return JumpTargetText{true, address, {}};
  }

  if ( tokens.size() > 1 )
  {
    for ( const std::string &token : tokens )
    {
      if ( IsNameStart(token[0]) && HasSymbolMarker(token) )
        return JumpTargetText{false, 0, token};
    }
    return std::nullopt;
  }

  const std::string &only = tokens.front();
  if ( IsNameStart(only[0]) )
    return JumpTargetText{false, 0, only};
  return std::nullopt;
}

} // namespace ida_agent::ai
