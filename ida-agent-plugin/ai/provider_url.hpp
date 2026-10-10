#pragma once
#include <string_view>

namespace ida_agent::ai::provider_detail
{
bool IsValidBaseUrl(std::string_view value);
}
