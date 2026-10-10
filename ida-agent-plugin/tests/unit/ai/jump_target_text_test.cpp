#include "ai/jump_target_text.hpp"

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>

namespace
{

using namespace ida_agent::ai;

void Require(bool condition, const char *message)
{
  if ( !condition )
    throw std::runtime_error(message);
}

void RequireAddress(const JumpTargetText &candidate, std::uint64_t expected)
{
  Require(candidate.is_address, "candidate is not an address");
  Require(candidate.address == expected, "address value changed");
  Require(candidate.name.empty(), "address candidate carried a name");
}

void RequireName(const JumpTargetText &candidate, const std::string &expected)
{
  Require(!candidate.is_address, "candidate is unexpectedly an address");
  Require(candidate.name == expected, "symbol name changed");
}

void TestBareHexAddress()
{
  const auto candidate = ExtractJumpTarget("0x401000");
  Require(candidate.has_value(), "bare hex address was not extracted");
  RequireAddress(*candidate, 0x401000);
}

void TestUppercaseHexPrefix()
{
  const auto candidate = ExtractJumpTarget("0X7FFA1234");
  Require(candidate.has_value(), "uppercase 0X prefix was not extracted");
  RequireAddress(*candidate, 0x7FFA1234);
}

void TestFullWidthAddress()
{
  const auto candidate = ExtractJumpTarget("0xffffffffffffffff");
  Require(candidate.has_value(), "full-width address was not extracted");
  RequireAddress(*candidate, 0xFFFFFFFFFFFFFFFFULL);
}

void TestAddressSurroundedByProse()
{
  const auto candidate = ExtractJumpTarget(
      "the call target is at 0x401234 (right after the loop)");
  Require(candidate.has_value(), "address inside prose was not extracted");
  RequireAddress(*candidate, 0x401234);
}

void TestAddressFollowedByPunctuation()
{
  const auto candidate = ExtractJumpTarget("0x401000:");
  Require(candidate.has_value(), "address with trailing colon was not extracted");
  RequireAddress(*candidate, 0x401000);

  const auto period_candidate = ExtractJumpTarget("0x401000.");
  Require(period_candidate.has_value(), "address with trailing period was not extracted");
  RequireAddress(*period_candidate, 0x401000);
}

void TestAddressPrefersOverSymbolName()
{
  const auto candidate = ExtractJumpTarget("sub_401200 at 0x401000");
  Require(candidate.has_value(), "no candidate found");
  RequireAddress(*candidate, 0x401000);
}

void TestBareSymbolName()
{
  const auto candidate = ExtractJumpTarget("sub_401000");
  Require(candidate.has_value(), "bare symbol name was not extracted");
  RequireName(*candidate, "sub_401000");
}

void TestDecoratedSymbolName()
{
  const auto candidate = ExtractJumpTarget("?func@@YAHH@Z");
  Require(candidate.has_value(), "decorated symbol name was not extracted");
  RequireName(*candidate, "?func@@YAHH@Z");
}

void TestSymbolFollowedByPeriod()
{
  const auto candidate = ExtractJumpTarget("call sub_401000.");
  Require(candidate.has_value(), "symbol with trailing period was not extracted");
  RequireName(*candidate, "sub_401000");
}

void TestSymbolInsideProse()
{
  const auto candidate = ExtractJumpTarget("the vulnerable function is qword_140001234");
  Require(candidate.has_value(), "symbol inside prose was not extracted");
  RequireName(*candidate, "qword_140001234");
}

void TestInvalidHexFallsBackToName()
{
  const auto candidate = ExtractJumpTarget("0xZZZZ and sub_401000");
  Require(candidate.has_value(), "invalid hex should fall back to a symbol");
  RequireName(*candidate, "sub_401000");
}

void TestPureNumberIgnored()
{
  const auto candidate = ExtractJumpTarget("42");
  Require(!candidate.has_value(), "plain decimal number was treated as a symbol");
}

void TestLeadingDigitsOnlyTokensSkippedForName()
{
  const auto candidate = ExtractJumpTarget("0xZZZZ");
  Require(!candidate.has_value(), "malformed hex token was treated as a symbol");
}

void TestProseWithoutSymbolIgnored()
{
  const auto candidate = ExtractJumpTarget("line 42 ends here");
  Require(!candidate.has_value(), "ordinary prose word was treated as a symbol");
}

void TestMultiTokenRequiresSymbolMarker()
{
  const auto candidate = ExtractJumpTarget("check the qword_140001234 value");
  Require(candidate.has_value(), "symbol with marker was not extracted");
  RequireName(*candidate, "qword_140001234");
}

void TestBareWordIsSymbolCandidate()
{
  const auto candidate = ExtractJumpTarget("main");
  Require(candidate.has_value(), "single word was not extracted");
  RequireName(*candidate, "main");
}

void TestEmptySelection()
{
  const auto candidate = ExtractJumpTarget("");
  Require(!candidate.has_value(), "empty selection produced a candidate");
}

void TestWhitespaceOnlySelection()
{
  const auto candidate = ExtractJumpTarget("   \t  ");
  Require(!candidate.has_value(), "whitespace selection produced a candidate");
}

} // namespace

int main()
{
  try
  {
    TestBareHexAddress();
    TestUppercaseHexPrefix();
    TestFullWidthAddress();
    TestAddressSurroundedByProse();
    TestAddressFollowedByPunctuation();
    TestAddressPrefersOverSymbolName();
    TestBareSymbolName();
    TestDecoratedSymbolName();
    TestSymbolFollowedByPeriod();
    TestSymbolInsideProse();
    TestInvalidHexFallsBackToName();
    TestPureNumberIgnored();
    TestLeadingDigitsOnlyTokensSkippedForName();
    TestProseWithoutSymbolIgnored();
    TestMultiTokenRequiresSymbolMarker();
    TestBareWordIsSymbolCandidate();
    TestEmptySelection();
    TestWhitespaceOnlySelection();
    return 0;
  }
  catch ( const std::exception &error )
  {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
