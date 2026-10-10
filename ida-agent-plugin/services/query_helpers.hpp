#pragma once
#include <pro.h>
#include <cstdint>
#include <optional>
#include <string>
namespace ida_agent::services::query
{
bool StableAddress(std::uint64_t value, ea_t *address);
std::optional<std::string> BoundedBasename(const char *path);
bool BoundedUtf8(const std::string &value, std::size_t maximum);
}
