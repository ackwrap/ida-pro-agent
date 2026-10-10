#include "ai/chat_history_store.hpp"

namespace ida_agent::ai
{
std::optional<std::string> NormalizeDatabaseKey(const std::filesystem::path &idb_path)
{
  if (idb_path.empty() || !idb_path.is_absolute() || idb_path.filename().empty()) return std::nullopt;
  std::error_code error;
  const auto status = std::filesystem::symlink_status(idb_path, error);
  std::filesystem::path path;
  if (status.type() == std::filesystem::file_type::not_found)
  {
    // IDA may keep only unpacked .id0/.id1 files while the database is open.
    // Its final .i64 name is still a stable history identity before packing.
    error.clear();
    const auto parent = std::filesystem::canonical(idb_path.parent_path(), error);
    if (error || !std::filesystem::is_directory(parent, error) || error) return std::nullopt;
    path = parent / idb_path.filename();
  }
  else
  {
    if (error || !std::filesystem::is_regular_file(idb_path, error) || error) return std::nullopt;
    path = std::filesystem::canonical(idb_path, error);
    if (error) return std::nullopt;
  }
  // Linux paths are case-sensitive. Resolve symlinks but preserve spelling.
  return path.u8string();
}
}
