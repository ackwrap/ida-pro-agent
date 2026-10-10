#include "changeset_integer.hpp"

#include "test_support.hpp"

#include <initializer_list>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

namespace
{

void ExpectBytes(
    std::string_view value,
    std::string_view type,
    std::initializer_list<unsigned char> expected)
{
  const auto encoded = ida_agent::services::detail::EncodeInteger(value, type);
  Require(encoded.has_value(), "valid integer rejected");
  Require(*encoded == std::vector<unsigned char>(expected), "integer bytes mismatch");
}

void ExpectInvalid(std::string_view value, std::string_view type)
{
  Require(
      !ida_agent::services::detail::EncodeInteger(value, type).has_value(),
      "invalid integer accepted");
}

} // namespace

int main()
{
  for ( const std::string_view sign : {"u", "i"} )
  {
    for ( const std::string_view width : {"8", "16", "32", "64"} )
    {
      for ( const std::string_view endian : {"le", "be"} )
      {
        const std::string type = std::string(sign) + std::string(width) + std::string(endian);
        const auto zero = ida_agent::services::detail::EncodeInteger("0", type);
        Require(zero.has_value(), "supported integer type rejected");
        Require(zero->size() == static_cast<std::size_t>(std::stoi(std::string(width)) / 8),
            "integer width mismatch");
        for ( unsigned char byte : *zero ) Require(byte == 0, "zero encoded as nonzero");
      }
    }
  }

  ExpectBytes("255", "u8le", {0xFF});
  ExpectBytes("127", "i8be", {0x7F});
  ExpectBytes("-128", "i8le", {0x80});
  ExpectBytes("0x1234", "u16le", {0x34, 0x12});
  ExpectBytes("0x1234", "u16be", {0x12, 0x34});
  ExpectBytes("-2", "i16le", {0xFE, 0xFF});
  ExpectBytes("-2", "i16be", {0xFF, 0xFE});
  ExpectBytes("0x12345678", "u32le", {0x78, 0x56, 0x34, 0x12});
  ExpectBytes("0x12345678", "u32be", {0x12, 0x34, 0x56, 0x78});
  ExpectBytes("-2147483648", "i32le", {0x00, 0x00, 0x00, 0x80});
  ExpectBytes("0x0123456789ABCDEF", "u64le", {0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01});
  ExpectBytes("0x0123456789ABCDEF", "u64be", {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF});
  ExpectBytes("-9223372036854775808", "i64be", {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});

  ExpectBytes("42", "u16le", {0x2A, 0x00});
  ExpectBytes("0x2A", "u16le", {0x2A, 0x00});
  ExpectBytes("0b101010", "u16le", {0x2A, 0x00});
  ExpectBytes("0o52", "u16le", {0x2A, 0x00});
  ExpectBytes(" \t+42\r\n", "i16le", {0x2A, 0x00});

  for ( const auto &[type, maximum, overflow] :
        std::initializer_list<std::tuple<std::string_view, std::string_view, std::string_view>>{
            {"u8", "255", "256"},
            {"u16", "65535", "65536"},
            {"u32", "4294967295", "4294967296"},
            {"u64", "18446744073709551615", "18446744073709551616"}} )
  {
    Require(ida_agent::services::detail::EncodeInteger(maximum, type).has_value(),
        "unsigned maximum rejected");
    ExpectInvalid(overflow, type);
  }

  for ( const auto &[type, maximum, minimum, positive_overflow, negative_overflow] :
        std::initializer_list<std::tuple<std::string_view, std::string_view, std::string_view,
            std::string_view, std::string_view>>{
            {"i8", "127", "-128", "128", "-129"},
            {"i16", "32767", "-32768", "32768", "-32769"},
            {"i32", "2147483647", "-2147483648", "2147483648", "-2147483649"},
            {"i64", "9223372036854775807", "-9223372036854775808", "9223372036854775808", "-9223372036854775809"}} )
  {
    Require(ida_agent::services::detail::EncodeInteger(maximum, type).has_value(),
        "signed maximum rejected");
    Require(ida_agent::services::detail::EncodeInteger(minimum, type).has_value(),
        "signed minimum rejected");
    ExpectInvalid(positive_overflow, type);
    ExpectInvalid(negative_overflow, type);
  }

  for ( const std::string_view invalid :
        {"", " ", "+", "-", "0x", "0b", "0o", "12x", "1.0", "0xGG", "0b102", "0o8"} )
  {
    ExpectInvalid(invalid, "i32le");
  }
  ExpectInvalid("-1", "u8le");
  for ( const std::string_view invalid_type :
        {"", "x8", "u7", "i128", "u16middle", "u16leb", "uint16"} )
  {
    ExpectInvalid("1", invalid_type);
  }
  return 0;
}
