#include "ai/provider_settings_dialog.hpp"

#include "ai/provider_settings/dialog_controller.hpp"

namespace ida_agent::ai
{

bool ShowProviderSettingsDialog(
    ProviderManagerDraft &draft,
    std::uint64_t &revision,
    ProviderClient &client,
    const ProviderSettingsCommitCallback &commit)
{
  provider_settings::DialogController controller(
      draft,
      revision,
      client,
      commit);
  return controller.Exec();
}

} // namespace ida_agent::ai
