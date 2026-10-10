#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace ida_agent::services
{

bool Utf8CodePointCount(std::string_view value, std::size_t *count);
std::string NormalizeInventoryFilter(std::string_view value);
bool InventoryFilterMatches(std::string_view value, std::string_view normalized_filter);
std::string TruncateUtf8Bytes(std::string_view value, std::size_t maximum_bytes);

} // namespace ida_agent::services
