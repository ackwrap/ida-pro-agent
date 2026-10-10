#include "ai/plugin_settings.hpp"
#include "ai/application_paths.hpp"

#include "instance/secure_file.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <knownfolders.h>
#include <shlobj.h>

#else
#include "ai/application_paths_linux.hpp"
#include "instance/private_file_linux.hpp"
#endif

#include <nlohmann/json.hpp>

#include <array>
#include <cstdint>
#include <exception>
#include <fstream>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace ida_agent::ai
{
namespace
{

constexpr std::uint32_t SettingsVersion = 2;
constexpr std::uint32_t LegacySettingsVersion = 1;
constexpr std::uintmax_t MaxSettingsBytes = 64 * 1024;
constexpr std::array<std::string_view, 5> LegacySettingNames{{
    "version",
    "openChatOnDatabaseOpen",
    "focusInputOnAutoOpen",
    "loadChatHistory",
    "saveChatHistory",
}};
constexpr std::array<std::string_view, 7> SettingNames{{
    "version",
    "openChatOnDatabaseOpen",
    "focusInputOnAutoOpen",
    "loadChatHistory",
    "saveChatHistory",
    "debugLogging",
    "networkLogging",
}};

std::filesystem::path ResolveDefaultSettingsPath()
{
#ifdef _WIN32
  PWSTR raw_path = nullptr;
  if ( FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_CREATE, nullptr, &raw_path)) )
    return {};
  std::unique_ptr<wchar_t, decltype(&CoTaskMemFree)> local_app_data(raw_path, CoTaskMemFree);
  return ResolveAiDataPath(local_app_data.get(), L"settings.json");
#else
  return LinuxAiPath("XDG_CONFIG_HOME", ".config", "settings.json");
#endif
}

template <std::size_t Size>
bool HasExactFields(
    const nlohmann::json &document,
    const std::array<std::string_view, Size> &names)
{
  if ( document.size() != names.size() )
    return false;
  for ( auto field = document.begin(); field != document.end(); ++field )
  {
    bool known = false;
    for ( const std::string_view name : names )
      known = known || field.key() == name;
    if ( !known )
      return false;
  }
  return true;
}

bool IsBoolean(const nlohmann::json &document, const char *name)
{
  return document.contains(name) && document.at(name).is_boolean();
}

} // namespace

PluginSettingsStore::PluginSettingsStore(std::filesystem::path path)
    : path_(std::move(path))
{
}

bool PluginSettingsStore::ResolvePath()
{
  if ( path_.empty() )
    path_ = ResolveDefaultSettingsPath();
  return !path_.empty();
}

PluginSettingsLoadResult PluginSettingsStore::Load()
{
  const PluginSettings defaults;
  if ( !ResolvePath() )
    return {PluginSettingsLoadStatus::Unavailable, defaults};

#ifdef _WIN32
  std::error_code error;
  if ( !std::filesystem::exists(path_, error) )
    return error
        ? PluginSettingsLoadResult{PluginSettingsLoadStatus::Unavailable, defaults}
        : PluginSettingsLoadResult{PluginSettingsLoadStatus::Missing, defaults};
  if ( !std::filesystem::is_regular_file(path_, error) || error )
    return {PluginSettingsLoadStatus::Unavailable, defaults};
  const std::uintmax_t size = std::filesystem::file_size(path_, error);
  if ( error )
    return {PluginSettingsLoadStatus::Unavailable, defaults};
  if ( size == 0 || size > MaxSettingsBytes )
    return {PluginSettingsLoadStatus::Invalid, defaults};

  std::ifstream input(path_, std::ios::binary);
  if ( !input )
    return {PluginSettingsLoadStatus::Unavailable, defaults};
  std::string contents(static_cast<std::size_t>(size), '\0');
  if ( !input.read(contents.data(), static_cast<std::streamsize>(contents.size())) )
    return {PluginSettingsLoadStatus::Unavailable, defaults};
#else
  const auto read = ida_agent::bridge::ReadPrivateFile(path_, MaxSettingsBytes);
  using ReadStatus = ida_agent::bridge::PrivateReadStatus;
  if (read.status == ReadStatus::Missing) return {PluginSettingsLoadStatus::Missing, defaults};
  if (read.status == ReadStatus::Invalid) return {PluginSettingsLoadStatus::Invalid, defaults};
  if (read.status != ReadStatus::Loaded) return {PluginSettingsLoadStatus::Unavailable, defaults};
  const std::string &contents = read.contents;
#endif

  const nlohmann::json document = nlohmann::json::parse(contents, nullptr, false);
  if ( !document.is_object()
      || !document.contains("version")
      || !document.at("version").is_number_unsigned() )
  {
    return {PluginSettingsLoadStatus::Invalid, defaults};
  }
  const std::uint32_t version = document.at("version").get<std::uint32_t>();
  const bool legacy = version == LegacySettingsVersion;
  if ( (legacy && !HasExactFields(document, LegacySettingNames))
      || (!legacy && (version != SettingsVersion
          || !HasExactFields(document, SettingNames)))
      || !IsBoolean(document, "openChatOnDatabaseOpen")
      || !IsBoolean(document, "focusInputOnAutoOpen")
      || !IsBoolean(document, "loadChatHistory")
      || !IsBoolean(document, "saveChatHistory")
      || (!legacy && (!IsBoolean(document, "debugLogging")
          || !IsBoolean(document, "networkLogging"))) )
  {
    return {PluginSettingsLoadStatus::Invalid, defaults};
  }

  return {
      PluginSettingsLoadStatus::Loaded,
      PluginSettings{
          document.at("openChatOnDatabaseOpen").get<bool>(),
          document.at("focusInputOnAutoOpen").get<bool>(),
          document.at("loadChatHistory").get<bool>(),
          document.at("saveChatHistory").get<bool>(),
          legacy ? false : document.at("debugLogging").get<bool>(),
          legacy ? false : document.at("networkLogging").get<bool>(),
      },
  };
}

bool PluginSettingsStore::Save(const PluginSettings &settings)
{
  if ( !ResolvePath() )
    return false;
  const nlohmann::json document{
      {"version", SettingsVersion},
      {"openChatOnDatabaseOpen", settings.open_chat_on_database_open},
      {"focusInputOnAutoOpen", settings.focus_input_on_auto_open},
      {"loadChatHistory", settings.load_chat_history},
      {"saveChatHistory", settings.save_chat_history},
      {"debugLogging", settings.debug_logging},
      {"networkLogging", settings.network_logging},
  };
  try
  {
    ida_agent::bridge::AtomicWriteCurrentUserOnlyFile(path_, document.dump(2) + "\n");
    return true;
  }
  catch ( const std::exception & )
  {
    return false;
  }
}

} // namespace ida_agent::ai
