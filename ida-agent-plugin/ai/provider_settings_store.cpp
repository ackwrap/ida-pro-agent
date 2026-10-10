#include "ai/provider_settings_store.hpp"
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

#include <cstdint>
#include <exception>
#include <fstream>
#include <initializer_list>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace ida_agent::ai
{
namespace
{

constexpr std::uint32_t ProviderSettingsVersion = 1;
constexpr std::uintmax_t MaxProviderSettingsBytes = 1024 * 1024;
constexpr std::size_t MaxProfiles = 64;
constexpr std::size_t MaxModelsPerProfile = 256;
constexpr std::size_t MaxHeadersPerProfile = 64;

std::filesystem::path ResolveDefaultProviderSettingsPath()
{
#ifdef _WIN32
  PWSTR raw_path = nullptr;
  if ( FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_CREATE, nullptr, &raw_path)) )
    return {};
  std::unique_ptr<wchar_t, decltype(&CoTaskMemFree)> local_app_data(raw_path, CoTaskMemFree);
  return ResolveAiDataPath(local_app_data.get(), L"providers.json");
#else
  return LinuxAiPath("XDG_CONFIG_HOME", ".config", "providers.json");
#endif
}

bool HasExactFields(
    const nlohmann::json &object,
    std::initializer_list<std::string_view> fields)
{
  if ( !object.is_object() || object.size() != fields.size() )
    return false;
  for ( const std::string_view field : fields )
  {
    if ( !object.contains(field) )
      return false;
  }
  return true;
}

bool IsString(const nlohmann::json &object, std::string_view field)
{
  return object.at(field).is_string();
}

bool IsBoolean(const nlohmann::json &object, std::string_view field)
{
  return object.at(field).is_boolean();
}

bool IsUnsigned32(const nlohmann::json &object, std::string_view field)
{
  if ( !object.at(field).is_number_unsigned() )
    return false;
  return object.at(field).get<std::uint64_t>()
      <= (std::numeric_limits<std::uint32_t>::max)();
}

bool IsUnsigned16(const nlohmann::json &object, std::string_view field)
{
  if ( !object.at(field).is_number_unsigned() )
    return false;
  return object.at(field).get<std::uint64_t>()
      <= (std::numeric_limits<std::uint16_t>::max)();
}

bool ParseProtocol(std::string_view value, ProviderProtocol &protocol)
{
  if ( value == "openai" )
  {
    protocol = ProviderProtocol::OpenAI;
    return true;
  }
  if ( value == "claude" )
  {
    protocol = ProviderProtocol::Claude;
    return true;
  }
  return false;
}

bool ParseOpenAiApiMode(std::string_view value, OpenAIApiMode &mode)
{
  if ( value == "responses" )
  {
    mode = OpenAIApiMode::Responses;
    return true;
  }
  if ( value == "chatCompletions" )
  {
    mode = OpenAIApiMode::ChatCompletions;
    return true;
  }
  return false;
}

bool ParseProxyMode(std::string_view value, ProviderProxyMode &mode)
{
  if ( value == "system" )
  {
    mode = ProviderProxyMode::System;
    return true;
  }
  if ( value == "direct" )
  {
    mode = ProviderProxyMode::Direct;
    return true;
  }
  if ( value == "http" )
  {
    mode = ProviderProxyMode::Http;
    return true;
  }
  return false;
}

std::string_view ProtocolName(ProviderProtocol protocol)
{
  return protocol == ProviderProtocol::Claude ? "claude" : "openai";
}

std::string_view OpenAiApiModeName(OpenAIApiMode mode)
{
  return mode == OpenAIApiMode::ChatCompletions
      ? "chatCompletions"
      : "responses";
}

std::string_view ProxyModeName(ProviderProxyMode mode)
{
  switch ( mode )
  {
    case ProviderProxyMode::System:
      return "system";
    case ProviderProxyMode::Direct:
      return "direct";
    case ProviderProxyMode::Http:
      return "http";
  }
  return "system";
}

bool ParseSettings(const nlohmann::json &document, ProviderSettingsDraft &settings)
{
  if ( !HasExactFields(
           document,
           {"displayName", "protocol", "openAiApiMode", "baseUrl", "model", "apiKey"})
      || !IsString(document, "displayName")
      || !IsString(document, "protocol")
      || !IsString(document, "openAiApiMode")
      || !IsString(document, "baseUrl")
      || !IsString(document, "model")
      || !IsString(document, "apiKey") )
  {
    return false;
  }

  ProviderSettingsDraft parsed;
  parsed.display_name = document.at("displayName").get<std::string>();
  parsed.base_url = document.at("baseUrl").get<std::string>();
  parsed.model = document.at("model").get<std::string>();
  parsed.api_key = document.at("apiKey").get<std::string>();
  if ( !ParseProtocol(document.at("protocol").get<std::string>(), parsed.protocol)
      || !ParseOpenAiApiMode(
          document.at("openAiApiMode").get<std::string>(),
          parsed.openai_api_mode) )
  {
    return false;
  }
  settings = std::move(parsed);
  return true;
}

bool ParseModel(const nlohmann::json &document, ProviderModelDraft &model)
{
  const bool legacy = HasExactFields(
      document,
      {"id", "enabled", "capabilities", "contextLength", "maxOutputTokens"});
  const bool current = HasExactFields(
      document,
      {"id", "enabled", "capabilities", "contextLength", "maxOutputTokens",
       "reasoningEffort", "reasoningSummary"});
  if ( (!legacy && !current)
      || !IsString(document, "id")
      || !IsBoolean(document, "enabled")
      || !IsString(document, "capabilities")
      || !IsUnsigned32(document, "contextLength")
      || !IsUnsigned32(document, "maxOutputTokens")
      || (current
          && (!IsString(document, "reasoningEffort")
              || !IsString(document, "reasoningSummary"))) )
  {
    return false;
  }
  ProviderModelDraft parsed{
      document.at("id").get<std::string>(),
      document.at("enabled").get<bool>(),
      document.at("capabilities").get<std::string>(),
      document.at("contextLength").get<std::uint32_t>(),
      document.at("maxOutputTokens").get<std::uint32_t>(),
  };
  if ( current
      && (!ParseProviderReasoningEffort(
              document.at("reasoningEffort").get<std::string>(),
              parsed.reasoning_effort)
          || !ParseProviderReasoningSummary(
              document.at("reasoningSummary").get<std::string>(),
              parsed.reasoning_summary)) )
  {
    return false;
  }
  model = std::move(parsed);
  return true;
}

bool ParseHeader(const nlohmann::json &document, ProviderHeaderDraft &header)
{
  if ( !HasExactFields(document, {"name", "value", "enabled"})
      || !IsString(document, "name")
      || !IsString(document, "value")
      || !IsBoolean(document, "enabled") )
  {
    return false;
  }
  header = ProviderHeaderDraft{
      document.at("name").get<std::string>(),
      document.at("value").get<std::string>(),
      document.at("enabled").get<bool>(),
  };
  return true;
}

bool ParseProxy(const nlohmann::json &document, ProviderProxyDraft &proxy)
{
  if ( !HasExactFields(
           document,
           {"mode", "host", "port", "username", "password", "bypassLocal"})
      || !IsString(document, "mode")
      || !IsString(document, "host")
      || !IsUnsigned16(document, "port")
      || !IsString(document, "username")
      || !IsString(document, "password")
      || !IsBoolean(document, "bypassLocal") )
  {
    return false;
  }
  ProviderProxyDraft parsed;
  parsed.host = document.at("host").get<std::string>();
  parsed.port = document.at("port").get<std::uint16_t>();
  parsed.username = document.at("username").get<std::string>();
  parsed.password = document.at("password").get<std::string>();
  parsed.bypass_local = document.at("bypassLocal").get<bool>();
  if ( !ParseProxyMode(document.at("mode").get<std::string>(), parsed.mode) )
    return false;
  proxy = std::move(parsed);
  return true;
}

bool ParseProfile(const nlohmann::json &document, ProviderProfileDraft &profile)
{
  if ( !HasExactFields(
           document,
           {"id", "builtIn", "settings", "models", "headers", "proxy"})
      || !IsString(document, "id")
      || !IsBoolean(document, "builtIn")
      || !document.at("models").is_array()
      || !document.at("headers").is_array()
      || document.at("models").size() > MaxModelsPerProfile
      || document.at("headers").size() > MaxHeadersPerProfile )
  {
    return false;
  }

  ProviderProfileDraft parsed;
  parsed.id = document.at("id").get<std::string>();
  parsed.built_in = document.at("builtIn").get<bool>();
  if ( !ParseSettings(document.at("settings"), parsed.settings) )
    return false;
  if ( !ParseProxy(document.at("proxy"), parsed.proxy) )
    return false;

  parsed.models.reserve(document.at("models").size());
  for ( const nlohmann::json &model_document : document.at("models") )
  {
    ProviderModelDraft model;
    if ( !ParseModel(model_document, model) )
      return false;
    parsed.models.push_back(std::move(model));
  }

  parsed.custom_headers.reserve(document.at("headers").size());
  for ( const nlohmann::json &header_document : document.at("headers") )
  {
    ProviderHeaderDraft header;
    if ( !ParseHeader(header_document, header) )
      return false;
    parsed.custom_headers.push_back(std::move(header));
  }
  profile = std::move(parsed);
  return true;
}

bool ParseManager(const nlohmann::json &document, ProviderManagerDraft &manager)
{
  if ( !HasExactFields(
           document,
           {"version", "activeProfileId", "nextCustomId", "profiles"})
      || !document.at("version").is_number_unsigned()
      || document.at("version").get<std::uint64_t>() != ProviderSettingsVersion
      || !IsString(document, "activeProfileId")
      || !document.at("nextCustomId").is_number_unsigned()
      || !document.at("profiles").is_array()
      || document.at("profiles").size() > MaxProfiles )
  {
    return false;
  }

  ProviderManagerDraft parsed;
  parsed.active_profile_id = document.at("activeProfileId").get<std::string>();
  parsed.next_custom_id = document.at("nextCustomId").get<std::uint64_t>();
  parsed.profiles.reserve(document.at("profiles").size());
  for ( const nlohmann::json &profile_document : document.at("profiles") )
  {
    ProviderProfileDraft profile;
    if ( !ParseProfile(profile_document, profile) )
      return false;
    parsed.profiles.push_back(std::move(profile));
  }
  manager = std::move(parsed);
  return true;
}

nlohmann::json SerializeSettings(const ProviderSettingsDraft &settings)
{
  return {
      {"displayName", settings.display_name},
      {"protocol", ProtocolName(settings.protocol)},
      {"openAiApiMode", OpenAiApiModeName(settings.openai_api_mode)},
      {"baseUrl", settings.base_url},
      {"model", settings.model},
      {"apiKey", settings.api_key},
  };
}

nlohmann::json SerializeModel(const ProviderModelDraft &model)
{
  return {
      {"id", model.id},
      {"enabled", model.enabled},
      {"capabilities", model.capabilities},
      {"contextLength", model.context_length},
      {"maxOutputTokens", model.max_output_tokens},
      {"reasoningEffort", ProviderReasoningEffortName(model.reasoning_effort)},
      {"reasoningSummary", ProviderReasoningSummaryName(model.reasoning_summary)},
  };
}

nlohmann::json SerializeHeader(const ProviderHeaderDraft &header)
{
  return {
      {"name", header.name},
      {"value", header.value},
      {"enabled", header.enabled},
  };
}

nlohmann::json SerializeProxy(const ProviderProxyDraft &proxy)
{
  return {
      {"mode", ProxyModeName(proxy.mode)},
      {"host", proxy.host},
      {"port", proxy.port},
      {"username", proxy.username},
      {"password", proxy.password},
      {"bypassLocal", proxy.bypass_local},
  };
}

nlohmann::json SerializeManager(const ProviderManagerDraft &manager)
{
  nlohmann::json profiles = nlohmann::json::array();
  for ( const ProviderProfileDraft &profile : manager.profiles )
  {
    nlohmann::json models = nlohmann::json::array();
    for ( const ProviderModelDraft &model : profile.models )
      models.push_back(SerializeModel(model));
    nlohmann::json headers = nlohmann::json::array();
    for ( const ProviderHeaderDraft &header : profile.custom_headers )
      headers.push_back(SerializeHeader(header));
    profiles.push_back({
        {"id", profile.id},
        {"builtIn", profile.built_in},
        {"settings", SerializeSettings(profile.settings)},
        {"models", std::move(models)},
        {"headers", std::move(headers)},
        {"proxy", SerializeProxy(profile.proxy)},
    });
  }
  return {
      {"version", ProviderSettingsVersion},
      {"activeProfileId", manager.active_profile_id},
      {"nextCustomId", manager.next_custom_id},
      {"profiles", std::move(profiles)},
  };
}

} // namespace

ProviderSettingsStore::ProviderSettingsStore(std::filesystem::path path)
    : path_(std::move(path))
{
}

bool ProviderSettingsStore::ResolvePath()
{
  if ( path_.empty() )
    path_ = ResolveDefaultProviderSettingsPath();
  return !path_.empty();
}

ProviderSettingsLoadResult ProviderSettingsStore::Load()
{
  const ProviderManagerDraft defaults = CreateProviderManagerDraft();
  if ( !ResolvePath() )
    return {ProviderSettingsLoadStatus::Unavailable, defaults};

#ifdef _WIN32
  std::error_code error;
  if ( !std::filesystem::exists(path_, error) )
  {
    return error
        ? ProviderSettingsLoadResult{ProviderSettingsLoadStatus::Unavailable, defaults}
        : ProviderSettingsLoadResult{ProviderSettingsLoadStatus::Missing, defaults};
  }
  if ( !std::filesystem::is_regular_file(path_, error) || error )
    return {ProviderSettingsLoadStatus::Unavailable, defaults};
  const std::uintmax_t size = std::filesystem::file_size(path_, error);
  if ( error )
    return {ProviderSettingsLoadStatus::Unavailable, defaults};
  if ( size == 0 || size > MaxProviderSettingsBytes )
    return {ProviderSettingsLoadStatus::Invalid, defaults};

  std::ifstream input(path_, std::ios::binary);
  if ( !input )
    return {ProviderSettingsLoadStatus::Unavailable, defaults};
  std::string contents(static_cast<std::size_t>(size), '\0');
  if ( !input.read(contents.data(), static_cast<std::streamsize>(contents.size())) )
    return {ProviderSettingsLoadStatus::Unavailable, defaults};
#else
  const auto read = ida_agent::bridge::ReadPrivateFile(path_, MaxProviderSettingsBytes);
  using ReadStatus = ida_agent::bridge::PrivateReadStatus;
  if (read.status == ReadStatus::Missing) return {ProviderSettingsLoadStatus::Missing, defaults};
  if (read.status == ReadStatus::Invalid) return {ProviderSettingsLoadStatus::Invalid, defaults};
  if (read.status != ReadStatus::Loaded) return {ProviderSettingsLoadStatus::Unavailable, defaults};
  const std::string &contents = read.contents;
#endif

  try
  {
    const nlohmann::json document = nlohmann::json::parse(contents, nullptr, false);
    ProviderManagerDraft manager;
    if ( document.is_discarded() || !ParseManager(document, manager) )
      return {ProviderSettingsLoadStatus::Invalid, defaults};
    NormalizeProviderManagerDraft(manager);
    if ( !IsValidManagerDraft(manager) )
      return {ProviderSettingsLoadStatus::Invalid, defaults};
    return {ProviderSettingsLoadStatus::Loaded, std::move(manager)};
  }
  catch ( const std::exception & )
  {
    return {ProviderSettingsLoadStatus::Invalid, defaults};
  }
}

bool ProviderSettingsStore::Save(const ProviderManagerDraft &manager)
{
  if ( !ResolvePath() )
    return false;
  ProviderManagerDraft normalized = manager;
  NormalizeProviderManagerDraft(normalized);
  if ( !IsValidManagerDraft(normalized) )
    return false;

  try
  {
    const std::string contents = SerializeManager(normalized).dump(2) + "\n";
    if ( contents.size() > MaxProviderSettingsBytes )
      return false;
    ida_agent::bridge::AtomicWriteCurrentUserOnlyFile(path_, contents);
    return true;
  }
  catch ( const std::exception & )
  {
    return false;
  }
}

} // namespace ida_agent::ai
