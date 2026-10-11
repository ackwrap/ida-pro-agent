#pragma once
#include "ai/provider_settings_model.hpp"
#include <array>

namespace ida_agent::ai
{
inline constexpr std::array<ProviderReasoningEffort, 7> ChatReasoningLevels{
    ProviderReasoningEffort::Default, ProviderReasoningEffort::None,
    ProviderReasoningEffort::Low, ProviderReasoningEffort::Medium,
    ProviderReasoningEffort::High, ProviderReasoningEffort::XHigh,
    ProviderReasoningEffort::Max};

struct ChatReasoningSelection
{
  std::string provider_id;
  std::string model_id;
  std::uint64_t revision = 0;
  ProviderReasoningEffort effort = ProviderReasoningEffort::Default;
};
struct ChatReasoningState
{
  ChatReasoningSelection selection;
  std::string tooltip;
  bool enabled = false;
};
enum class ChatReasoningChange { Changed, Unchanged, Busy, Stale, Unavailable, Invalid };
ChatReasoningState MakeChatReasoningState(const ProviderManagerDraft &manager,
    std::uint64_t revision, bool busy);
ChatReasoningChange ApplyChatReasoningSelection(ProviderManagerDraft &manager,
    std::uint64_t revision, const ChatReasoningSelection &selection, bool busy);
} // namespace ida_agent::ai
