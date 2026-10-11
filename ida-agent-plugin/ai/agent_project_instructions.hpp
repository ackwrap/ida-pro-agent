#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace ida_agent::ai
{
class AgentFileService;
inline constexpr std::uint32_t MaxAgentProjectInstructionBytes = 32 * 1024;
enum class AgentProjectInstructionStatus { NotLoaded, Loaded, NeedsRead, Unavailable };
struct AgentProjectInstructions
{
  AgentProjectInstructionStatus status = AgentProjectInstructionStatus::NotLoaded;
  std::string path;
  std::string content;
  std::uint64_t size = 0;
};
AgentProjectInstructions LoadAgentProjectInstructions(const AgentFileService &files) noexcept;
std::string BuildProjectInstructionsPrompt(const AgentProjectInstructions &instructions, std::size_t budget);
std::string WithProjectInstructions(const AgentProjectInstructions &instructions, std::string_view user_text);
class AgentProjectInstructionCache final
{
public:
  const AgentProjectInstructions &Get(std::string_view idb_path);
  const AgentProjectInstructions &Snapshot() const noexcept { return instructions_; }
  void Reset() noexcept;
private:
  std::string project_;
  AgentProjectInstructions instructions_;
  bool initialized_ = false;
};
} // namespace ida_agent::ai
