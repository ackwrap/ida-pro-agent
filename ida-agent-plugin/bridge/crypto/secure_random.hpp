#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ida_agent::bridge
{

void FillSecureRandom(std::uint8_t *output, std::size_t size);
std::vector<std::uint8_t> SecureRandom(std::size_t size);
std::string HexEncode(const std::uint8_t *data, std::size_t size);
void SecureWipe(void *data, std::size_t size) noexcept;

} // namespace ida_agent::bridge
