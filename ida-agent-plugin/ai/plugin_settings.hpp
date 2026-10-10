#pragma once

#include <filesystem>

namespace ida_agent::ai
{

struct PluginSettings
{
  bool open_chat_on_database_open = false;
  bool focus_input_on_auto_open = true;
  bool load_chat_history = true;
  bool save_chat_history = true;
  bool debug_logging = false;
  bool network_logging = false;
};

enum class PluginSettingsLoadStatus
{
  Loaded,
  Missing,
  Invalid,
  Unavailable,
};

struct PluginSettingsLoadResult
{
  PluginSettingsLoadStatus status;
  PluginSettings settings;
};

class PluginSettingsStore final
{
public:
  explicit PluginSettingsStore(std::filesystem::path path = {});

  PluginSettingsLoadResult Load();
  bool Save(const PluginSettings &settings);

private:
  bool ResolvePath();

  std::filesystem::path path_;
};

} // namespace ida_agent::ai
