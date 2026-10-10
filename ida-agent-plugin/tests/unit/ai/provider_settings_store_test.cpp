#include "ai/provider_settings_store.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#include <unistd.h>
#include <fstream>
inline unsigned long GetCurrentProcessId() { return static_cast<unsigned long>(getpid()); }
#endif

#include <nlohmann/json.hpp>

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

void WriteText(const std::filesystem::path &path, const std::string &text)
{
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  Require(static_cast<bool>(output), "test provider file was not opened");
  output << text;
  Require(static_cast<bool>(output), "test provider file was not written");
}

std::string ReadText(const std::filesystem::path &path)
{
  std::ifstream input(path, std::ios::binary);
  Require(static_cast<bool>(input), "test provider file was not opened for reading");
  return std::string(
      std::istreambuf_iterator<char>(input),
      std::istreambuf_iterator<char>());
}

} // namespace

int main()
{
  using namespace ida_agent::ai;

  const std::filesystem::path root = std::filesystem::canonical(std::filesystem::temp_directory_path())
      / (L"ida-agent-provider-settings-" + std::to_wstring(GetCurrentProcessId()));
  std::filesystem::remove_all(root);
  std::filesystem::create_directories(root);
#ifndef _WIN32
  std::filesystem::permissions(root, std::filesystem::perms::owner_all);
#endif
  const std::filesystem::path path = root / L"providers.json";

  ProviderSettingsStore store(path);
  const ProviderSettingsLoadResult missing = store.Load();
  Require(missing.status == ProviderSettingsLoadStatus::Missing, "missing status mismatch");
  Require(IsValidManagerDraft(missing.manager), "missing result did not contain defaults");
  Require(
      missing.manager.profiles.front().custom_headers.front().value == DefaultBrowserUserAgent(),
      "missing result did not contain the default User-Agent");

  ProviderManagerDraft expected = CreateProviderManagerDraft();
  ProviderProfileDraft &openai = expected.profiles.front();
  openai.settings.display_name = "  Saved OpenAI  ";
  openai.settings.base_url = "https://api.openai.com/v1///";
  openai.settings.api_key = "plain-text-secret-key";
  openai.settings.model = " model-a ";
  openai.models.push_back(ProviderModelDraft{" model-a ", true, " Tools ", 128000, 4096});
  openai.models.front().reasoning_effort = ProviderReasoningEffort::High;
  openai.models.front().reasoning_summary = ProviderReasoningSummary::Detailed;
  openai.custom_headers.push_back(
      ProviderHeaderDraft{" Authorization ", " Bearer custom-token ", false});
  openai.proxy.mode = ProviderProxyMode::Http;
  openai.proxy.host = "  [2001:db8::10]  ";
  openai.proxy.port = 3128;
  openai.proxy.username = "  proxy-user  ";
  openai.proxy.password = " plain-text-proxy-password ";
  openai.proxy.bypass_local = false;
  expected.next_custom_id = 42;

  Require(store.Save(expected), "provider settings save failed");
  Require(
      expected.profiles.front().settings.display_name == "  Saved OpenAI  ",
      "save mutated the caller's provider manager");
  const std::string saved_text = ReadText(path);
  Require(
      saved_text.find("plain-text-secret-key") != std::string::npos,
      "API key was not stored in providers.json");
  Require(
      saved_text.find(" plain-text-proxy-password ") != std::string::npos,
      "proxy password was not stored in providers.json");
  Require(
      saved_text.find("\"version\": 1") != std::string::npos,
      "provider settings version was not stored");

  const ProviderSettingsLoadResult loaded = store.Load();
  Require(loaded.status == ProviderSettingsLoadStatus::Loaded, "provider settings load failed");
  Require(loaded.manager.next_custom_id == 42, "next custom ID did not round-trip");
  Require(loaded.manager.active_profile_id == expected.active_profile_id, "active profile did not round-trip");
  const ProviderProfileDraft &loaded_openai = loaded.manager.profiles.front();
  Require(loaded_openai.built_in, "built-in marker did not round-trip");
  Require(loaded_openai.settings.display_name == "Saved OpenAI", "display name was not normalized");
  Require(
      loaded_openai.settings.base_url == "https://api.openai.com/v1",
      "Base URL was not normalized before save");
  Require(loaded_openai.settings.api_key == "plain-text-secret-key", "API key did not round-trip");
  Require(loaded_openai.settings.model == "model-a", "default model did not round-trip");
  Require(loaded_openai.models.size() == 1, "models did not round-trip");
  Require(loaded_openai.models.front().enabled, "model enabled state did not round-trip");
  Require(loaded_openai.models.front().capabilities == "Tools", "model capabilities did not normalize");
  Require(loaded_openai.models.front().context_length == 128000, "model context did not round-trip");
  Require(loaded_openai.models.front().max_output_tokens == 4096, "model output did not round-trip");
  Require(
      loaded_openai.models.front().reasoning_effort == ProviderReasoningEffort::High
          && loaded_openai.models.front().reasoning_summary
              == ProviderReasoningSummary::Detailed,
      "model reasoning configuration did not round-trip");
  Require(loaded_openai.custom_headers.size() == 2, "headers did not round-trip");
  Require(!loaded_openai.custom_headers.back().enabled, "header enabled state did not round-trip");
  Require(
      loaded_openai.custom_headers.back().name == "Authorization",
      "header name did not normalize");
  Require(loaded_openai.proxy.mode == ProviderProxyMode::Http, "proxy mode did not round-trip");
  Require(loaded_openai.proxy.host == "2001:db8::10", "proxy host did not normalize");
  Require(loaded_openai.proxy.port == 3128, "proxy port did not round-trip");
  Require(loaded_openai.proxy.username == "proxy-user", "proxy username did not normalize");
  Require(
      loaded_openai.proxy.password == " plain-text-proxy-password ",
      "proxy password did not round-trip exactly");
  Require(!loaded_openai.proxy.bypass_local, "proxy bypass-local did not round-trip");

  nlohmann::json v1_zero_metadata = nlohmann::json::parse(saved_text);
  v1_zero_metadata["profiles"][0]["models"][0]["contextLength"] = 0;
  v1_zero_metadata["profiles"][0]["models"][0]["maxOutputTokens"] = 0;
  WriteText(path, v1_zero_metadata.dump());
  const ProviderSettingsLoadResult migrated = store.Load();
  Require(migrated.status == ProviderSettingsLoadStatus::Loaded, "V1 zero metadata did not load");
  Require(
      migrated.manager.profiles.front().models.front().context_length
          == DefaultModelContextLength,
      "V1 zero context was not migrated in memory");
  Require(
      migrated.manager.profiles.front().models.front().max_output_tokens
          == DefaultModelMaxOutputTokens,
      "V1 zero output was not migrated in memory");
  Require(store.Save(migrated.manager), "migrated defaults did not save");
  const ProviderSettingsLoadResult migrated_roundtrip = store.Load();
  Require(
      migrated_roundtrip.status == ProviderSettingsLoadStatus::Loaded
          && migrated_roundtrip.manager.profiles.front().models.front().context_length
              == DefaultModelContextLength
          && migrated_roundtrip.manager.profiles.front().models.front().max_output_tokens
              == DefaultModelMaxOutputTokens,
      "migrated defaults did not round-trip");

  nlohmann::json legacy_model = nlohmann::json::parse(saved_text);
  legacy_model["profiles"][0]["models"][0].erase("reasoningEffort");
  legacy_model["profiles"][0]["models"][0].erase("reasoningSummary");
  WriteText(path, legacy_model.dump());
  const ProviderSettingsLoadResult legacy_loaded = store.Load();
  Require(
      legacy_loaded.status == ProviderSettingsLoadStatus::Loaded
           && legacy_loaded.manager.profiles.front().models.front().reasoning_effort
               == ProviderReasoningEffort::Default
           && legacy_loaded.manager.profiles.front().models.front().reasoning_summary
               == ProviderReasoningSummary::Visible,
       "legacy model reasoning defaults did not migrate");

  nlohmann::json minimal_model = nlohmann::json::parse(saved_text);
  minimal_model["profiles"][0]["models"][0]["reasoningEffort"] = "minimal";
  WriteText(path, minimal_model.dump());
  const ProviderSettingsLoadResult minimal_loaded = store.Load();
  Require(
      minimal_loaded.status == ProviderSettingsLoadStatus::Loaded
          && minimal_loaded.manager.profiles.front().models.front().reasoning_effort
              == ProviderReasoningEffort::Low,
      "minimal reasoning effort did not migrate to low");

  nlohmann::json unknown = nlohmann::json::parse(saved_text);
  unknown["unknown"] = true;
  WriteText(path, unknown.dump());
  Require(store.Load().status == ProviderSettingsLoadStatus::Invalid, "unknown root field was accepted");

  unknown = nlohmann::json::parse(saved_text);
  unknown["profiles"][0]["models"][0]["reasoningEffort"] = "unbounded";
  WriteText(path, unknown.dump());
  Require(store.Load().status == ProviderSettingsLoadStatus::Invalid,
          "unknown reasoning effort was accepted");

  unknown = nlohmann::json::parse(saved_text);
  unknown["profiles"][0]["settings"]["unknown"] = true;
  WriteText(path, unknown.dump());
  Require(store.Load().status == ProviderSettingsLoadStatus::Invalid, "unknown nested field was accepted");

  unknown = nlohmann::json::parse(saved_text);
  unknown["profiles"][0]["proxy"]["unknown"] = true;
  WriteText(path, unknown.dump());
  Require(store.Load().status == ProviderSettingsLoadStatus::Invalid, "unknown proxy field was accepted");

  unknown = nlohmann::json::parse(saved_text);
  unknown["profiles"][0]["proxy"]["port"] = 65536;
  WriteText(path, unknown.dump());
  Require(store.Load().status == ProviderSettingsLoadStatus::Invalid, "over-limit proxy port was accepted");

  unknown = nlohmann::json::parse(saved_text);
  unknown.erase("activeProfileId");
  WriteText(path, unknown.dump());
  Require(store.Load().status == ProviderSettingsLoadStatus::Invalid, "missing field was accepted");

  WriteText(path, "not-json");
  Require(store.Load().status == ProviderSettingsLoadStatus::Invalid, "invalid JSON was accepted");

  ProviderManagerDraft invalid = CreateProviderManagerDraft();
  invalid.profiles.front().custom_headers.push_back(
      ProviderHeaderDraft{"Content-Length", "5", true});
  Require(!store.Save(invalid), "invalid provider manager was saved");

  std::filesystem::remove_all(root);
  return 0;
}
