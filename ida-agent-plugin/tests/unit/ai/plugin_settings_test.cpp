#include "ai/plugin_settings.hpp"
#include "ai/application_paths.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#include <unistd.h>
#include <fstream>
inline unsigned long GetCurrentProcessId() { return static_cast<unsigned long>(getpid()); }
#endif

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

namespace
{

void Require(bool condition, const char *message)
{
  if ( !condition )
    throw std::runtime_error(message);
}

void WriteText(const std::filesystem::path &path, const char *text)
{
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  Require(static_cast<bool>(output), "test settings file was not opened");
  output << text;
  Require(static_cast<bool>(output), "test settings file was not written");
}

} // namespace

int main()
{
  using namespace ida_agent::ai;

  const std::filesystem::path root = std::filesystem::canonical(std::filesystem::temp_directory_path())
      / (L"ida-agent-plugin-settings-" + std::to_wstring(GetCurrentProcessId()));
  std::filesystem::remove_all(root);
  std::filesystem::create_directories(root);
#ifndef _WIN32
  std::filesystem::permissions(root, std::filesystem::perms::owner_all);
#endif
  const std::filesystem::path path = root / L"settings.json";

  for ( const auto *filename : {L"settings.json", L"providers.json", L"chat.db"} )
  {
    const auto preferred = root / L"ida-agent" / L"ai" / filename;
    const auto legacy = root / L"ida-mcp" / L"ai" / filename;
    Require(ResolveAiDataPath(root, filename) == preferred, "new installation path mismatch");
    std::filesystem::create_directories(legacy.parent_path());
    WriteText(legacy, "legacy data");
    Require(ResolveAiDataPath(root, filename) == preferred, "old product directory was reused");
    std::filesystem::create_directories(preferred.parent_path());
    WriteText(preferred, "new data");
    Require(ResolveAiDataPath(root, filename) == preferred, "new data did not take precedence");
    Require(std::filesystem::file_size(legacy) == 11, "legacy data was modified");
  }

  PluginSettingsStore store(path);
  const PluginSettingsLoadResult missing = store.Load();
  Require(missing.status == PluginSettingsLoadStatus::Missing, "missing settings mismatch");
  Require(!missing.settings.open_chat_on_database_open, "auto-open default mismatch");
  Require(missing.settings.focus_input_on_auto_open, "focus default mismatch");
  Require(missing.settings.load_chat_history, "history load default mismatch");
  Require(missing.settings.save_chat_history, "history save default mismatch");
  Require(!missing.settings.debug_logging, "debug logging default mismatch");
  Require(!missing.settings.network_logging, "network logging default mismatch");

  const PluginSettings expected{true, false, false, true, true, true};
  Require(store.Save(expected), "settings save failed");
  const PluginSettingsLoadResult loaded = store.Load();
  Require(loaded.status == PluginSettingsLoadStatus::Loaded, "settings load failed");
  Require(loaded.settings.open_chat_on_database_open, "auto-open was not loaded");
  Require(!loaded.settings.focus_input_on_auto_open, "focus was not loaded");
  Require(!loaded.settings.load_chat_history, "history load was not loaded");
  Require(loaded.settings.save_chat_history, "history save was not loaded");
  Require(loaded.settings.debug_logging, "debug logging was not loaded");
  Require(loaded.settings.network_logging, "network logging was not loaded");

  WriteText(
      path,
      "{\"version\":1,\"openChatOnDatabaseOpen\":false,"
      "\"focusInputOnAutoOpen\":true,\"loadChatHistory\":true,"
      "\"saveChatHistory\":true}");
  const PluginSettingsLoadResult migrated = store.Load();
  Require(migrated.status == PluginSettingsLoadStatus::Loaded,
          "legacy settings did not migrate");
  Require(!migrated.settings.debug_logging && !migrated.settings.network_logging,
          "legacy settings enabled logging");

  WriteText(
      path,
      "{\"version\":2,\"openChatOnDatabaseOpen\":false,"
      "\"focusInputOnAutoOpen\":true,\"loadChatHistory\":true,"
      "\"saveChatHistory\":true,\"debugLogging\":false,"
      "\"networkLogging\":false,\"unknown\":false}");
  Require(store.Load().status == PluginSettingsLoadStatus::Invalid, "unknown field accepted");
  WriteText(path, "{\"version\":2}");
  Require(store.Load().status == PluginSettingsLoadStatus::Invalid, "missing fields accepted");
  WriteText(path, "not-json");
  Require(store.Load().status == PluginSettingsLoadStatus::Invalid, "invalid JSON accepted");

  std::filesystem::remove_all(root);
  return 0;
}
