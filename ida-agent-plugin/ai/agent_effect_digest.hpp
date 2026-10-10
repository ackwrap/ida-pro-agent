#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace ida_agent::ai
{

class AgentEffectSha256State final
{
public:
  AgentEffectSha256State();

  void Update(std::string_view input);
  std::string Final();

private:
  void Transform(const unsigned char *block);

  std::array<std::uint32_t, 8> hash_;
  std::array<unsigned char, 64> buffer_{};
  std::uint64_t total_bytes_ = 0;
  std::size_t buffered_ = 0;
  bool finalized_ = false;
};

std::string AgentEffectSha256(std::string_view input);

} // namespace ida_agent::ai
