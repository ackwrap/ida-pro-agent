#pragma once

#include "ai/plugin_settings.hpp"

#include <functional>

namespace ida_agent::ai
{

bool ShowPluginSettingsDialog(
    PluginSettings &settings,
    const std::function<bool()> &clear_all_history);

} // namespace ida_agent::ai
