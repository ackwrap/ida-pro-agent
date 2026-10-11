#include "ai/ai_menu.hpp"
#include "ai/ai_menu_registry.hpp"
#include "ai/provider_settings_dialog.hpp"
#include <chrono>

namespace ida_agent::ai
{
void AiMenuController::RefreshReasoningControl(bool force)
{
  const bool busy = HasActiveRequest();
  const auto now = std::chrono::steady_clock::now();
  if (!force && busy == reasoning_control_busy_ && now < reasoning_control_refresh_) return;
  const auto settings = AiMenuRegistry::Instance().ProviderSettings();
  chat_panel_.SetReasoningState(MakeChatReasoningState(settings.Manager(), settings.Revision(), busy));
  reasoning_control_busy_ = busy;
  reasoning_control_refresh_ = now + std::chrono::milliseconds(500);
}
void AiMenuController::SelectReasoningEffort(const ChatReasoningSelection &selection)
{
  auto settings = AiMenuRegistry::Instance().ProviderSettings();
  const auto change = ApplyChatReasoningSelection(settings.Manager(), settings.Revision(), selection, HasActiveRequest());
  if (change == ChatReasoningChange::Changed)
  {
    const auto saved = AiMenuRegistry::Instance().ApplyProviderSettings(settings.Manager(), selection.revision);
    if (saved.status == ProviderSettingsCommitStatus::Saved)
      chat_panel_.AppendSystem("Reasoning effort for " + selection.model_id + ": "
          + std::string(ProviderReasoningEffortName(selection.effort)) + ".");
    else if (saved.status == ProviderSettingsCommitStatus::Conflict)
      chat_panel_.AppendSystem("Provider settings changed; the effort selector was refreshed. Select the level again.");
    else
      chat_panel_.AppendSystem("Reasoning effort could not be saved; the previous setting remains active.");
  }
  else if (change == ChatReasoningChange::Busy)
    chat_panel_.AppendSystem("Wait for the current request to finish before changing reasoning effort.");
  else if (change != ChatReasoningChange::Unchanged)
    chat_panel_.AppendSystem("The model or provider settings changed; the effort selector was refreshed.");
  RefreshReasoningControl(true);
  if (change != ChatReasoningChange::Unchanged) PersistTranscript();
}
} // namespace ida_agent::ai
