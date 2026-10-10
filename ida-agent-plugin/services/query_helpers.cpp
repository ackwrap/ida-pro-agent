#include "query_helpers.hpp"
namespace ida_agent::services::query
{
constexpr std::size_t MaxFilenameBytes = 4096;
bool StableAddress(std::uint64_t value, ea_t *address)
{
  *address = static_cast<ea_t>(value);
  return static_cast<std::uint64_t>(*address) == value && *address != BADADDR;
}

std::optional<std::string> BoundedBasename(const char *path)
{
  if ( path == nullptr )
    return std::nullopt;
  const char *base = qbasename(path);
  if ( base == nullptr )
    return std::nullopt;
  std::string result(base);
  if ( result.empty() || result.size() > MaxFilenameBytes || !is_valid_utf8(result.c_str()) )
    return std::nullopt;
  return result;
}

bool BoundedUtf8(const std::string &value, std::size_t maximum)
{
  return value.size() <= maximum && value.find('\0') == std::string::npos
      && is_valid_utf8(value.c_str());
}
}
