#pragma once

#include "ai/plugin_settings.hpp"

#include <functional>

namespace ida_agent::ai
{
class UpdateController;

bool ShowPluginSettingsDialog(
    PluginSettings &settings,
    const std::function<bool()> &clear_all_history,
    UpdateController &updates,
    bool &automatic_updates);

} // namespace ida_agent::ai
