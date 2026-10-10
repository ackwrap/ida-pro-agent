#pragma once

#include "ai/agent_tool_registry.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace ida_agent::ai
{

inline constexpr std::size_t MaxProviderAgentResultBytes = 512 * 1024;
inline constexpr std::size_t MaxProviderSystemPromptBytes = 8 * 1024;
inline constexpr std::size_t MaxProviderToolSchemaBytes = 512 * 1024;

struct ProviderAgentExchange
{
  std::string assistant_text;
  std::vector<AgentToolCall> calls;
  std::vector<AgentToolResult> results;
};

struct ProviderChatAgentOptions
{
  std::string system_prompt;
  std::vector<AgentToolDefinition> tools;
  std::vector<ProviderAgentExchange> exchanges;
};

struct ProviderToolCallUpdate
{
  std::size_t index = 0;
  bool initialize = false;
  std::optional<std::string> id_delta;
  std::optional<std::string> id_snapshot;
  std::optional<std::string> name_delta;
  std::optional<std::string> name_snapshot;
  std::optional<std::string> arguments_delta;
  std::optional<std::string> arguments_snapshot;
  bool empty_object_start = false;
  bool done = false;
};

} // namespace ida_agent::ai
