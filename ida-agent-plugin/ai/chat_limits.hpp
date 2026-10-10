#pragma once

#include <cstddef>
#include <cstdint>

namespace ida_agent::ai
{

inline constexpr std::size_t MaxChatResponseBytes = 1024 * 1024;
inline constexpr std::uint32_t MaxProviderChatOutputTokens = 256'000U;

} // namespace ida_agent::ai
