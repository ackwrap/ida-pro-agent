#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace ida_agent::services::detail
{

std::optional<std::string> CurrentPseudocodeComment(std::uint64_t address);
bool ApplyPseudocodeComment(std::uint64_t address, const std::string &comment);
std::optional<std::string> CurrentBookmark(std::uint64_t address);
bool ApplyBookmark(std::uint64_t address, const std::string &description);

} // namespace ida_agent::services::detail
