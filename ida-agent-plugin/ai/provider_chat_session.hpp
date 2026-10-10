#pragma once

#include "ai/provider_chat.hpp"

#include <cstddef>
#include <memory>
#include <string>

namespace ida_agent::ai
{

inline constexpr const char *ProviderChatEarlyCloseMessage =
    "Provider chat stream closed before completion.";
inline constexpr const char *ProviderChatTransportErrorMessage =
    "Provider chat transport error.";
inline constexpr const char *ProviderChatTextLimitMessage =
    "Provider chat response exceeded the text limit.";

enum class ProviderChatSessionEventKind
{
  None,
  Delta,
  ToolCalls,
  Completed,
  Error,
  Cancelled,
};

struct ProviderChatSessionEvent
{
  ProviderChatSessionEventKind kind = ProviderChatSessionEventKind::None;
  std::string text_delta;
  std::string reasoning_delta;
  std::string assistant_text;
  std::string safe_message;
  std::vector<AgentToolCall> calls;
};

class ProviderChatSession final
{
public:
  explicit ProviderChatSession(
      std::size_t max_text_bytes = MaxProviderChatTextBytes);
  ~ProviderChatSession();

  ProviderChatSession(const ProviderChatSession &) = delete;
  ProviderChatSession &operator=(const ProviderChatSession &) = delete;

  bool Start(StreamClient &client, ProviderChatBuildResult request);
  ProviderChatSessionEvent Poll();
  void Cancel() noexcept;
  bool IsActive() const noexcept;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

#ifdef IDA_AGENT_PROVIDER_CHAT_SESSION_TESTING
ProviderChatSessionEventKind SelectProviderChatTerminalKindForTesting(
    bool has_pending_error,
    bool codec_completed,
    bool user_cancel_requested,
    bool has_completed_calls) noexcept;
#endif

} // namespace ida_agent::ai
