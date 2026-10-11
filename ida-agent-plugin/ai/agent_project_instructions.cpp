#include "ai/agent_project_instructions.hpp"
#include "ai/agent_file_service.hpp"
#include <filesystem>

namespace ida_agent::ai
{
AgentProjectInstructions LoadAgentProjectInstructions(const AgentFileService &files) noexcept
{
  for (const auto *path : {"AGENTS.md", "Agents.md", "agents.md"})
  {
    AgentProjectInstructions result;
    try
    {
      const auto metadata = files.Stat(path);
      result.path = path;
      result.status = AgentProjectInstructionStatus::Unavailable;
      if (metadata.at("type") != "file") return result;
      result.size = metadata.at("size").get<std::uint64_t>();
      if (result.size > MaxAgentProjectInstructionBytes)
      {
        result.status = AgentProjectInstructionStatus::NeedsRead;
        return result;
      }
      const auto read = files.Read(path, 0, MaxAgentProjectInstructionBytes);
      if (read.at("hasMore").get<bool>())
      {
        result.status = AgentProjectInstructionStatus::NeedsRead;
        return result;
      }
      result.content = read.at("content").get<std::string>();
      result.size = result.content.size();
      result.status = AgentProjectInstructionStatus::Loaded;
      return result;
    }
    catch (...)
    {
      if (!result.path.empty()) return result;
      // Failed safe metadata lookup may mean absent or inaccessible. Never claim absence.
    }
  }
  return {};
}
const AgentProjectInstructions &AgentProjectInstructionCache::Get(std::string_view idb_path)
{
  // A lexical project key requires no filesystem lookup on cached requests.
  auto project = std::filesystem::u8path(idb_path).parent_path().lexically_normal().u8string();
#ifdef _WIN32
  for (char &ch : project) if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
#endif
  if (!initialized_ || project != project_)
  {
    AgentFileService files([path = std::string(idb_path)]() { return path; });
    instructions_ = LoadAgentProjectInstructions(files);
    project_ = std::move(project);
    initialized_ = true; // Also cache missing/unreadable files until an explicit reload.
  }
  return instructions_;
}

void AgentProjectInstructionCache::Reset() noexcept
{
  project_.clear(); instructions_ = {}; initialized_ = false;
}
} // namespace ida_agent::ai
