#include "ai/chat_reasoning.hpp"
#include "ai/provider_settings_store.hpp"
#include <chrono>
#include <filesystem>
#include <iostream>
#include <stdexcept>

using namespace ida_agent::ai;
namespace
{
void Require(bool value, const char *message) { if (!value) throw std::runtime_error(message); }
ProviderManagerDraft Manager()
{
  auto manager = CreateProviderManagerDraft();
  auto *profile = ActiveProvider(manager);
  Require(profile != nullptr, "missing preset provider");
  profile->settings.model = "reasoning-test";
  profile->models = {ProviderModelDraft{"reasoning-test"}, ProviderModelDraft{"other-model"}};
  NormalizeProviderManagerDraft(manager);
  return manager;
}
void SelectionGuards()
{
  auto manager = Manager();
  const auto state = MakeChatReasoningState(manager, 7, false);
  Require(state.enabled && state.selection.model_id == "reasoning-test", "active model binding missing");
  auto choice = state.selection;
  choice.effort = ProviderReasoningEffort::High;
  Require(ApplyChatReasoningSelection(manager, 7, choice, true) == ChatReasoningChange::Busy, "running request allowed effort change");
  Require(ApplyChatReasoningSelection(manager, 8, choice, false) == ChatReasoningChange::Stale, "stale settings revision accepted");
  auto wrong = choice; wrong.model_id = "other-model";
  Require(ApplyChatReasoningSelection(manager, 7, wrong, false) == ChatReasoningChange::Stale, "another model was changed");
  wrong = choice; wrong.provider_id = "another-provider";
  Require(ApplyChatReasoningSelection(manager, 7, wrong, false) == ChatReasoningChange::Stale, "another provider was changed");
  wrong = choice; wrong.effort = static_cast<ProviderReasoningEffort>(999);
  Require(ApplyChatReasoningSelection(manager, 7, wrong, false) == ChatReasoningChange::Invalid, "unknown effort accepted");
  Require(ActiveProvider(manager)->models.front().reasoning_effort == ProviderReasoningEffort::Default, "rejected selection mutated settings");
  Require(ApplyChatReasoningSelection(manager, 7, choice, false) == ChatReasoningChange::Changed, "valid effort was not applied");
  Require(ActiveProvider(manager)->models.front().reasoning_effort == ProviderReasoningEffort::High, "selected model did not change");
  Require(ActiveProvider(manager)->models.back().reasoning_effort == ProviderReasoningEffort::Default, "unselected model changed");
  Require(ApplyChatReasoningSelection(manager, 7, choice, false) == ChatReasoningChange::Unchanged, "unchanged effort requested a write");
  Require(!MakeChatReasoningState(manager, 7, true).enabled, "busy selector remained enabled");
  ActiveProvider(manager)->settings.protocol = ProviderProtocol::Claude;
  Require(!MakeChatReasoningState(manager, 7, false).enabled, "unsupported protocol pretended to control effort");
  Require(ApplyChatReasoningSelection(manager, 7, choice, false) == ChatReasoningChange::Unavailable, "Claude ignored a choice silently");
  ActiveProvider(manager)->settings.protocol = ProviderProtocol::OpenAI;
  ActiveProvider(manager)->models.front().enabled = false;
  Require(!MakeChatReasoningState(manager, 7, false).enabled, "disabled model selector remained enabled");
  Require(ApplyChatReasoningSelection(manager, 7, choice, false) == ChatReasoningChange::Unavailable, "disabled model was changed");
  Require(!MakeChatReasoningState({}, 0, false).enabled, "empty settings enabled effort");
}
void Persistence(const std::filesystem::path &path)
{
  auto manager = Manager();
  for (const auto effort : ChatReasoningLevels)
  {
    auto choice = MakeChatReasoningState(manager, 1, false).selection;
    choice.effort = effort;
    const auto result = ApplyChatReasoningSelection(manager, 1, choice, false);
    Require(result == ChatReasoningChange::Changed || result == ChatReasoningChange::Unchanged, "level could not be selected");
    Require(ProviderSettingsStore(path).Save(manager), "model effort could not be saved");
    const auto loaded = ProviderSettingsStore(path).Load();
    Require(loaded.status == ProviderSettingsLoadStatus::Loaded, "model settings failed to load");
    const auto state = MakeChatReasoningState(loaded.manager, 2, false);
    Require(state.enabled && state.selection.effort == effort, "saved model effort did not restore");
    Require(ActiveProvider(loaded.manager)->models.back().reasoning_effort == ProviderReasoningEffort::Default, "saving changed another model");
  }
}
}
int main()
{
  const auto parent = std::filesystem::current_path();
  const auto directory = parent / ("chat-reasoning-test-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
  int status = 0;
  try
  {
    std::filesystem::create_directory(directory);
#ifndef _WIN32
    std::filesystem::permissions(directory, std::filesystem::perms::owner_all);
#endif
    SelectionGuards(); Persistence(directory / "providers.json");
    std::cout << "Reasoning selector identity, revisions, busy state and persistence passed.\n";
  }
  catch (const std::exception &error) { std::cerr << error.what() << '\n'; status = 1; }
  std::error_code error;
  if (directory.parent_path() == parent && directory.filename().string().rfind("chat-reasoning-test-", 0) == 0)
    std::filesystem::remove_all(directory, error);
  return status;
}
