#include "function_search_cursor.hpp"

#include "test_support.hpp"

#include <string>

int main()
{
  const std::string cursor = ida_agent::rpc::EncodeFunctionSearchCursor(
      "sub_",
      0x140001000ULL);
  Require(cursor.size() == 54, "cursor size mismatch");
  Require(
      ida_agent::rpc::DecodeFunctionSearchCursor(cursor, "sub_") == 0x140001000ULL,
      "cursor address mismatch");
  RequireFailure(
      [&cursor]()
      {
        static_cast<void>(ida_agent::rpc::DecodeFunctionSearchCursor(cursor, "other"));
      },
      "cursor query mismatch accepted");
  std::string modified = cursor;
  modified.back() = modified.back() == '0' ? '1' : '0';
  RequireFailure(
      [&modified]()
      {
        static_cast<void>(ida_agent::rpc::DecodeFunctionSearchCursor(modified, "sub_"));
      },
      "modified cursor accepted");
  std::string uppercase = cursor;
  bool uppercased = false;
  for ( std::size_t index = 4; index < uppercase.size(); ++index )
  {
    if ( uppercase[index] >= 'a' && uppercase[index] <= 'f' )
    {
      uppercase[index] = static_cast<char>(uppercase[index] - 'a' + 'A');
      uppercased = true;
      break;
    }
  }
  Require(uppercased, "cursor did not contain a hexadecimal letter");
  RequireFailure(
      [&uppercase]()
      {
        static_cast<void>(ida_agent::rpc::DecodeFunctionSearchCursor(uppercase, "sub_"));
      },
      "uppercase cursor accepted");
  RequireFailure(
      []()
      {
        static_cast<void>(ida_agent::rpc::DecodeFunctionSearchCursor("invalid", "sub_"));
      },
      "malformed cursor accepted");
  return 0;
}
