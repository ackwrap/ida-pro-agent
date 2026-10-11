#pragma once

#include "ai/agent_tool_catalog.hpp"
#include "ai/provider_chat.hpp"

#include <chrono>
#include <optional>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace ida_agent::ai
{

inline constexpr std::string_view AgentLoopLimitMessage =
    "IDA analysis tool loop exceeded a time or resource boundary.";
inline constexpr std::string_view AgentLoopBuildMessage =
    "Unable to continue the IDA analysis tool loop.";

inline constexpr std::size_t MaxAgentToolRecoveryRounds = 3;
inline constexpr std::string_view AgentLoopRecoveryLimitMessage =
    "Unavailable tool calls exceeded the recovery limit; no calls in this round ran.";

enum class AgentLoopState
{
  Idle,
  Streaming,
  ExecutingTools,
};

struct AgentLoopStep
{
  ProviderChatBuildResult build;
  bool error = false;
  std::string safe_message;
};

class AgentLoop final
{
public:
  AgentLoopStep Begin(
      ProviderProfileDraft profile,
      std::vector<ProviderChatMessage> messages,
      std::string system_prompt,
      std::vector<AgentToolDefinition> tools);
  AgentLoopStep BeginToolRound(
      std::vector<AgentToolCall> calls,
      std::string assistant_text);
  std::optional<AgentToolResult> InvokeCatalogTool(
      const AgentToolCall &call);
  AgentLoopStep CompleteToolRound(std::vector<AgentToolResult> results);
  void Complete() noexcept;
  void Reset() noexcept;
  void PauseDeadline() noexcept;
  void ResumeDeadline() noexcept;
  AgentLoopState State() const noexcept;
  bool Active() const noexcept;
  bool DeadlineExpired() const noexcept;

private:
  AgentLoopStep BuildNext();

  ProviderProfileDraft profile_;
  std::vector<ProviderChatMessage> messages_;
  ProviderChatAgentOptions options_;
  std::chrono::steady_clock::time_point deadline_{};
  std::size_t result_bytes_ = 0;
  ProviderAgentExchange pending_exchange_;
  AgentToolCatalogSession tool_catalog_;
  std::map<std::string, AgentToolResult> unavailable_results_;
  std::size_t recovery_rounds_ = 0;
  std::chrono::steady_clock::time_point deadline_paused_at_{};
  AgentLoopState state_ = AgentLoopState::Idle;
};

} // namespace ida_agent::ai
