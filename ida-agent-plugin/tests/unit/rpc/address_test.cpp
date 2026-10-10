#include "address.hpp"

#include "test_support.hpp"

#include <cstdint>
#include <limits>
#include <string_view>

int main()
{
  using ida_agent::rpc::FormatAddress;
  using ida_agent::rpc::ParseAddress;

  Require(ParseAddress("0x0") == 0, "zero address failed");
  Require(ParseAddress("0x401000") == 0x401000, "normal address failed");
  Require(
      ParseAddress("0xFFFFFFFFFFFFFFFF") == std::numeric_limits<std::uint64_t>::max(),
      "maximum address failed");
  Require(FormatAddress(0x401000) == "0x401000", "address formatting failed");

  for ( const std::string_view invalid :
        {"", "0x", "0X10", "10", "-0x1", "0xgg", "0x10000000000000000"} )
  {
    RequireFailure([invalid]() { static_cast<void>(ParseAddress(invalid)); }, "invalid address accepted");
  }
  return 0;
}
