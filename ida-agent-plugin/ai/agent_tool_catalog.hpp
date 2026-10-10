#pragma once

#include "ai/agent_tool_registry.hpp"

#include <optional>
#include <string_view>
#include <vector>

namespace ida_agent::ai
{

inline constexpr std::string_view AgentToolSearchName = "ida_tool_search";

const AgentToolDefinition &AgentToolSearchDefinition();
std::vector<AgentToolDefinition> InitialAgentToolDefinitions(
    const std::vector<AgentToolDefinition> &catalog);

class AgentToolCatalogSession final
{
public:
  void Begin(std::vector<AgentToolDefinition> catalog);
  void Reset() noexcept;

  bool IsActive(std::string_view name) const noexcept;
  const std::vector<AgentToolDefinition> &ActiveDefinitions() const noexcept;
  std::optional<AgentToolResult> Invoke(const AgentToolCall &call);

private:
  std::vector<AgentToolDefinition> catalog_;
  std::vector<AgentToolDefinition> active_;
};

} // namespace ida_agent::ai
