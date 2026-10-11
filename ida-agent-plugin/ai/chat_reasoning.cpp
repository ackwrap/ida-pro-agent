#include "ai/chat_reasoning.hpp"
#include <algorithm>

namespace ida_agent::ai
{
namespace
{
const ProviderModelDraft *Selected(const ProviderProfileDraft &profile)
{
  const auto model = std::find_if(profile.models.begin(), profile.models.end(),
      [&](const ProviderModelDraft &item) { return item.enabled && item.id == profile.settings.model; });
  return model == profile.models.end() ? nullptr : &*model;
}
}
ChatReasoningState MakeChatReasoningState(const ProviderManagerDraft &manager,
    std::uint64_t revision, bool busy)
{
  ChatReasoningState state;
  state.selection.revision = revision;
  const auto *profile = ActiveProvider(manager);
  const auto *model = profile ? Selected(*profile) : nullptr;
  if (!model)
  {
    state.tooltip = "Configure a provider and an enabled model in Provider Manager to select reasoning effort.";
    return state;
  }
  state.selection = {profile->id, model->id, revision, model->reasoning_effort};
  if (profile->settings.protocol != ProviderProtocol::OpenAI)
  {
    state.tooltip = "Reasoning effort is unavailable for this protocol: the current Claude transport does not send an effort parameter.";
    return state;
  }
  state.enabled = !busy;
  state.tooltip = profile->settings.display_name + " / " + model->id + "\n"
      "Reasoning effort is saved for this model. Default omits the effort parameter. "
      "Supported explicit levels depend on your provider and model.";
  if (busy) state.tooltip += "\nWait for the current request to finish before changing effort.";
  return state;
}
ChatReasoningChange ApplyChatReasoningSelection(ProviderManagerDraft &manager,
    std::uint64_t revision, const ChatReasoningSelection &selection, bool busy)
{
  if (busy) return ChatReasoningChange::Busy;
  if (std::find(ChatReasoningLevels.begin(), ChatReasoningLevels.end(), selection.effort)
      == ChatReasoningLevels.end()) return ChatReasoningChange::Invalid;
  if (revision != selection.revision) return ChatReasoningChange::Stale;
  auto *profile = ActiveProvider(manager);
  if (!profile || profile->id != selection.provider_id || profile->settings.model != selection.model_id)
    return ChatReasoningChange::Stale;
  if (profile->settings.protocol != ProviderProtocol::OpenAI) return ChatReasoningChange::Unavailable;
  const auto model = std::find_if(profile->models.begin(), profile->models.end(),
      [&](const ProviderModelDraft &item) { return item.enabled && item.id == selection.model_id; });
  if (model == profile->models.end()) return ChatReasoningChange::Unavailable;
  if (model->reasoning_effort == selection.effort) return ChatReasoningChange::Unchanged;
  model->reasoning_effort = selection.effort;
  return ChatReasoningChange::Changed;
}
} // namespace ida_agent::ai
