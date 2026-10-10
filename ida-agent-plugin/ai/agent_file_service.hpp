#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace ida_agent::ai
{

inline constexpr std::size_t MaxAgentFilePathBytes = 1024;
inline constexpr std::size_t MaxAgentFileContentBytes = 128 * 1024;
inline constexpr std::size_t MaxAgentScriptBytes = 32 * 1024;

struct AgentFileState
{
  bool exists = false;
  std::string type;
  std::uint64_t size = 0;
  std::string sha256;
  std::uint64_t volume = 0;
  std::uint64_t file_index = 0;
};

struct AgentFileMutationPlan
{
  std::string path;
  std::string mode;
  std::string content;
  AgentFileState expected;
  std::uint64_t parent_volume = 0;
  std::uint64_t parent_file_index = 0;
};

struct AgentFileScriptSnapshot
{
  std::string path;
  std::string language;
  std::string source;
  std::string sha256;
};

enum class AgentFileMutationStatus
{
  Success,
  Rejected,
  StateUncertain,
};

struct AgentFileMutationOutcome
{
  AgentFileMutationStatus status = AgentFileMutationStatus::Rejected;
  nlohmann::json result = nlohmann::json::object();
};

class AgentFileService final
{
public:
  using IdbPathProvider = std::function<std::string()>;

  explicit AgentFileService(IdbPathProvider idb_path_provider);

  static AgentFileService ForTesting(std::string idb_path)
  {
    return AgentFileService(
        [path = std::move(idb_path)]() { return path; });
  }

  nlohmann::json List(std::string_view path, std::uint32_t limit) const;
  nlohmann::json Stat(std::string_view path) const;
  nlohmann::json Read(
      std::string_view path,
      std::uint64_t offset,
      std::uint32_t max_bytes) const;

  std::optional<AgentFileMutationPlan> PrepareMutation(
      std::string_view path,
      std::string_view mode,
      std::string_view content) const;
  AgentFileMutationOutcome ExecuteMutation(
      const AgentFileMutationPlan &plan) const noexcept;
  std::optional<AgentFileScriptSnapshot> PrepareScript(
      std::string_view path,
      std::string_view language) const;

private:
  IdbPathProvider idb_path_provider_;
};

} // namespace ida_agent::ai
