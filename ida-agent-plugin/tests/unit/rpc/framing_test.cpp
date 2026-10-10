#include "framing.hpp"

#include "envelope.hpp"
#include "test_support.hpp"

#include <array>
#include <cstdint>

int main()
{
  using namespace ida_agent::rpc;

  std::array<std::uint8_t, RequestHeaderBytes> request{};
  request[0] = 'I';
  request[1] = 'M';
  request[2] = 'C';
  request[3] = 'P';
  request[4] = FramingVersion;
  request[8] = 16;

  const RequestFrameHeader parsed = ParseRequestFrameHeader(request);
  Require(parsed.payload_size == 16, "request payload size mismatch");

  const auto response = BuildResponseFrameHeader(0x00020304);
  Require(response[0] == 'I' && response[3] == 'R', "response magic mismatch");
  Require(
      response[5] == 0 && response[6] == 2 && response[7] == 3 && response[8] == 4,
      "response payload encoding mismatch");

  request[0] = 'X';
  RequireFailure(
      [&request]() { static_cast<void>(ParseRequestFrameHeader(request)); },
      "invalid request magic accepted");
  RequireFailure(
      []() { static_cast<void>(BuildResponseFrameHeader(MaxMessageBytes + 1)); },
      "oversized response accepted");
  return 0;
}
