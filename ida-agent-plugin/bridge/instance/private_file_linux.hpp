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
// Same checks for SQLite database, WAL and shared-memory files, without opening
// them: closing any descriptor for a file drops every POSIX lock this process
// holds on it, including locks held by open SQLite connections.
void PreparePrivateDatabaseFile(const std::filesystem::path &path, bool create);
}
