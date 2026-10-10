#pragma once

#include "ai/chat_transcript.hpp"
#include "ai/provider_chat.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ida_agent::ai
{

struct ChatContextUsage
{
  bool valid = false;
  bool agent_tools = false;
  bool cropped = false;
  std::uint64_t estimated_input_tokens = 0;
  std::uint64_t input_token_budget = 0;
  std::uint32_t context_length = 0;
  std::uint32_t max_output_tokens = 0;
  std::size_t request_bytes = 0;
  std::size_t total_messages = 0;
  std::size_t included_messages = 0;
  std::size_t history_entries = 0;
  std::size_t history_bytes = 0;
  std::size_t user_messages = 0;
  std::size_t assistant_messages = 0;
  std::size_t compacted_summaries = 0;
};

struct ChatCompactionPlan
{
  std::string prompt;
  std::vector<ChatEntry> retained_entries;
  std::size_t summarized_entries = 0;
  std::size_t summarized_bytes = 0;
};

bool ChatModelHasCapability(
    std::string_view capabilities,
    std::string_view expected);
const ProviderModelDraft *SelectedChatModel(
    const ProviderProfileDraft &profile) noexcept;
std::vector<ProviderChatMessage> BuildConversationMessages(
    const std::vector<ChatEntry> &entries);
ChatContextUsage MakeChatContextUsage(
    const ProviderChatBuildResult &build,
    const std::vector<ChatEntry> &entries,
    std::size_t total_messages,
    bool agent_tools);
std::string FormatChatContextUsage(
    const ChatContextUsage &usage,
    bool detailed);
bool ShouldAutoCompactContext(
    const ChatContextUsage &usage,
    std::uint64_t threshold_percent = 85) noexcept;
std::optional<ChatCompactionPlan> PlanChatCompaction(
    const std::vector<ChatEntry> &entries);

} // namespace ida_agent::ai
