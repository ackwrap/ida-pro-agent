#pragma once

#include "ai/agent_effect_policy.hpp"
#include "ai/agent_tool_registry.hpp"

#include <optional>
#include <string>
#include <vector>

namespace ida_agent::ai
{

struct ChatScriptSource
{
  std::string language;
  std::string path;
};

enum class ChatScriptApprovalDecision
{
  AllowSessionAndExecute,
  DenySession,
};

enum class ChatScriptApprovalRoute
{
  ContinueStandardFlow,
  ShowDialog,
  DenySession,
};

std::optional<std::vector<ChatScriptSource>> ParsePreparedScriptSources(
    const std::vector<AgentToolCall> &prepared_calls) noexcept;

ChatScriptApprovalRoute RoutePreparedScriptApproval(
    AgentEffectApprovalPolicy policy,
    const std::optional<std::vector<ChatScriptSource>> &sources) noexcept;

ChatScriptApprovalDecision ChatScriptDecisionFromAccepted(
    bool accepted) noexcept;

std::string FormatChatScriptApprovalPreview(
    const std::vector<ChatScriptSource> &sources);

} // namespace ida_agent::ai
