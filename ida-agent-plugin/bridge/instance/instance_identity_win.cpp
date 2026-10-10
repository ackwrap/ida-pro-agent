#include "instance/instance_identity.hpp"

#include "crypto/secure_random.hpp"

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>

namespace ida_agent::bridge
{

std::string GenerateInstanceId()
{
  std::array<std::uint8_t, 16> random{};
  FillSecureRandom(random.data(), random.size());
  random[6] = static_cast<std::uint8_t>((random[6] & 0x0F) | 0x40);
  random[8] = static_cast<std::uint8_t>((random[8] & 0x3F) | 0x80);
  const std::string hex = HexEncode(random.data(), random.size());
  return hex.substr(0, 8) + "-" + hex.substr(8, 4) + "-" + hex.substr(12, 4)
      + "-" + hex.substr(16, 4) + "-" + hex.substr(20, 12);
}

std::wstring BuildPipeName(std::uint32_t pid, const std::string &instance_id)
{
  if ( instance_id.size() < 8 )
    throw std::invalid_argument("instance ID is too short");
  return L"\\\\.\\pipe\\ida-agent-" + std::to_wstring(pid) + L"-"
      + std::wstring(instance_id.begin(), instance_id.begin() + 8);
}

} // namespace ida_agent::bridge
