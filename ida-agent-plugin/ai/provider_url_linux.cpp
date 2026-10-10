#include "ai/provider_url.hpp"
#include "ai/url_linux.hpp"

namespace ida_agent::ai::provider_detail
{
bool IsValidBaseUrl(std::string_view value)
{
  return value.size() <= 2048 && value.find('?') == std::string_view::npos && ValidLinuxHttpUrl(value);
}
}
