#pragma once
#include <filesystem>
#include <string>
#include <cstddef>

namespace ida_agent::bridge
{
enum class PrivateReadStatus { Loaded, Missing, Invalid, Unavailable };
struct PrivateReadResult
{
  PrivateReadStatus status = PrivateReadStatus::Unavailable;
  std::string contents;
};
PrivateReadResult ReadPrivateFile(const std::filesystem::path &path, std::size_t limit);
// Creates an empty 0600 file if missing, validates existing files without truncating.
void PreparePrivateFile(const std::filesystem::path &path);
}
