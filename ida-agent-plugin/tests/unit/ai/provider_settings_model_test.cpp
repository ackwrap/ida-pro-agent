#include "ai/provider_settings_model.hpp"

#include <stdexcept>
#include <string>

namespace
{

void Require(bool condition, const char *message)
{
  if ( !condition )
    throw std::runtime_error(message);
}

ida_agent::ai::ProviderProfileDraft &FirstProfile(
    ida_agent::ai::ProviderManagerDraft &manager)
{
  return manager.profiles.front();
}

void RequireDefaultUserAgent(const ida_agent::ai::ProviderProfileDraft &profile)
{
  Require(profile.custom_headers.size() == 1, "default header count mismatch");
  Require(profile.custom_headers.front().enabled, "default User-Agent is disabled");
  Require(profile.custom_headers.front().name == "User-Agent", "default header name mismatch");
  Require(
      profile.custom_headers.front().value == ida_agent::ai::DefaultBrowserUserAgent(),
      "default User-Agent value mismatch");
}

} // namespace

int main()
{
  using namespace ida_agent::ai;

  const ProviderSettingsDraft openai = DraftForPreset(ProviderPreset::OpenAI);
  Require(openai.display_name == "OpenAI", "OpenAI display name mismatch");
  Require(openai.protocol == ProviderProtocol::OpenAI, "OpenAI protocol mismatch");
  Require(openai.openai_api_mode == OpenAIApiMode::Responses, "OpenAI mode mismatch");
  Require(openai.base_url == "https://api.openai.com/v1", "OpenAI URL mismatch");
  Require(!DefaultBrowserUserAgent().empty(), "default User-Agent is empty");
  Require(PresetForDraft(openai) == ProviderPreset::OpenAI, "OpenAI preset not recognized");
  ProviderSettingsDraft authenticated_openai = openai;
  authenticated_openai.api_key = "plain-text-key";
  Require(
      PresetForDraft(authenticated_openai) == ProviderPreset::OpenAI,
      "API key changed preset recognition");

  const ProviderSettingsDraft claude = DraftForPreset(ProviderPreset::Claude);
  Require(claude.display_name == "Claude", "Claude display name mismatch");
  Require(claude.protocol == ProviderProtocol::Claude, "Claude protocol mismatch");
  Require(claude.base_url == "https://api.anthropic.com/v1", "Claude URL mismatch");
  Require(PresetForDraft(claude) == ProviderPreset::Claude, "Claude preset not recognized");

  ProviderSettingsDraft custom = DraftForPreset(ProviderPreset::Custom);
  Require(custom.protocol == ProviderProtocol::OpenAI, "custom protocol mismatch");
  Require(custom.openai_api_mode == OpenAIApiMode::ChatCompletions, "custom mode mismatch");
  Require(PresetForDraft(custom) == ProviderPreset::Custom, "custom preset not recognized");
  Require(!IsValidDraft(custom), "custom draft without URL accepted");

  custom.base_url = "http://127.0.0.1:11434/v1";
  Require(IsValidDraft(custom), "complete custom draft rejected");
  SetProtocol(custom, ProviderProtocol::Claude);
  Require(custom.protocol == ProviderProtocol::Claude, "protocol change failed");
  Require(
      custom.openai_api_mode == OpenAIApiMode::ChatCompletions,
      "Claude switch unexpectedly destroyed the OpenAI mode preference");
  Require(PresetForDraft(custom) == ProviderPreset::Custom, "modified draft matched built-in preset");

  ProviderManagerDraft manager = CreateProviderManagerDraft();
  Require(manager.profiles.size() == 2, "built-in provider count mismatch");
  Require(ActiveProvider(manager) != nullptr, "default provider is missing");
  Require(
      ActiveProvider(manager)->settings.display_name == "OpenAI",
      "default provider mismatch");
  Require(IsValidManagerDraft(manager), "default provider manager is invalid");
  RequireDefaultUserAgent(manager.profiles[0]);
  RequireDefaultUserAgent(manager.profiles[1]);
  Require(
      manager.profiles[0].proxy.mode == ProviderProxyMode::System,
      "default proxy mode mismatch");
  Require(IsValidProviderProxyDraft(manager.profiles[0].proxy), "default proxy is invalid");

  const std::string custom_id = AddCustomProvider(manager);
  ProviderProfileDraft *custom_profile = FindProvider(manager, custom_id);
  Require(custom_profile != nullptr, "custom provider was not added");
  Require(!custom_profile->built_in, "custom provider marked built-in");
  RequireDefaultUserAgent(*custom_profile);
  Require(!IsValidManagerDraft(manager), "incomplete custom provider accepted");
  custom_profile->settings.base_url = "http://127.0.0.1:11434/v1";
  custom_profile->models.push_back(ProviderModelDraft{"local-model", true, "Tools", 32768, 4096});
  custom_profile->settings.model = "local-model";
  manager.active_profile_id = custom_id;
  Require(IsValidManagerDraft(manager), "complete provider manager rejected");
  Require(ActiveProvider(manager) == custom_profile, "active custom provider mismatch");
  Require(!RemoveCustomProvider(manager, "builtin-openai"), "built-in provider was removed");
  Require(RemoveCustomProvider(manager, custom_id), "custom provider was not removed");
  Require(ActiveProvider(manager) != nullptr, "active provider was not repaired after removal");

  ProviderManagerDraft normalized = CreateProviderManagerDraft();
  ProviderProfileDraft &normalized_profile = FirstProfile(normalized);
  normalized_profile.settings.display_name = "  OpenAI Local  ";
  normalized_profile.settings.base_url = "  https://example.com/v1///  ";
  normalized_profile.models.push_back(
      ProviderModelDraft{"  model-1  ", true, "  Tools  ", 0, 0});
  normalized_profile.settings.model = "  model-1  ";
  normalized_profile.custom_headers.push_back(
      ProviderHeaderDraft{"  Authorization  ", "  Bearer test  ", true});
  NormalizeProviderManagerDraft(normalized);
  Require(normalized_profile.settings.display_name == "OpenAI Local", "name was not trimmed");
  Require(
      normalized_profile.settings.base_url == "https://example.com/v1",
      "Base URL was not normalized");
  Require(normalized_profile.settings.model == "model-1", "default model was not trimmed");
  Require(normalized_profile.models.front().id == "model-1", "model ID was not trimmed");
  Require(
      normalized_profile.models.front().context_length == DefaultModelContextLength
          && normalized_profile.models.front().max_output_tokens
              == DefaultModelMaxOutputTokens,
      "missing model metadata did not receive defaults");
  Require(
      normalized_profile.models.front().capabilities == "Tools"
          && normalized_profile.models.front().reasoning_summary
              == ProviderReasoningSummary::Visible,
      "model tools/visible defaults mismatch");
  ProviderModelDraft empty_metadata;
  ApplyDefaultModelMetadata(empty_metadata);
  Require(empty_metadata.capabilities == "tools"
              && empty_metadata.reasoning_summary == ProviderReasoningSummary::Visible,
          "empty model metadata did not enable tools and visible thinking");
  ProviderReasoningEffort migrated_effort = ProviderReasoningEffort::Default;
  Require(ParseProviderReasoningEffort("minimal", migrated_effort)
              && migrated_effort == ProviderReasoningEffort::Low,
          "legacy minimal reasoning effort did not migrate to low");
  ProviderModelDraft full_capabilities;
  full_capabilities.capabilities.assign(1024, 'x');
  ApplyDefaultModelMetadata(full_capabilities);
  Require(full_capabilities.capabilities == "tools",
          "full legacy capabilities did not make room for tools");
  Require(
      normalized_profile.custom_headers.back().name == "Authorization",
      "header name was not trimmed");
  Require(IsValidManagerDraft(normalized), "normalized manager was rejected");

  ProviderManagerDraft merged = CreateProviderManagerDraft();
  ProviderProfileDraft &merged_profile = FirstProfile(merged);
  merged_profile.models = {
      {"manual", false, "Manual metadata", 111, 22},
      {"default", true, "Manual metadata", 222, 33},
      {"missing", true, "", 0, 0},
      {"stale", true, "Stale metadata", 333, 44},
  };
  merged_profile.settings.model = "default";
  MergeDiscoveredModels(
      merged_profile,
      {
          {"manual", true, "", 0, 0},
          {"default", false, "Updated metadata", 444, 55},
          {"missing", false, "Discovered metadata", 0, 0},
          {"new", false, "New metadata", 0, 0},
      });
  Require(merged_profile.models.size() == 5, "discovery did not preserve stale models");
  Require(
      merged_profile.models[0].id == "manual"
          && !merged_profile.models[0].enabled
          && merged_profile.models[0].capabilities == "Manual metadata"
          && merged_profile.models[0].context_length == 111
          && merged_profile.models[0].max_output_tokens == 22,
      "discovery replaced manual model state or empty metadata");
  Require(
      merged_profile.models[1].enabled
          && merged_profile.models[1].capabilities == "Manual metadata"
          && merged_profile.models[1].context_length == 222
          && merged_profile.models[1].max_output_tokens == 33,
      "discovery overwrote manual metadata");
  Require(
      merged_profile.models[2].capabilities == "Discovered metadata, tools"
          && merged_profile.models[2].context_length == DefaultModelContextLength
          && merged_profile.models[2].max_output_tokens == DefaultModelMaxOutputTokens,
      "discovery did not fill missing metadata");
  Require(
      merged_profile.models[3].id == "stale"
          && merged_profile.models[3].enabled
          && merged_profile.models[3].capabilities == "Stale metadata"
          && merged_profile.models[3].context_length == 333
          && merged_profile.models[3].max_output_tokens == 44,
      "stale model state was not preserved");
  Require(
      merged_profile.models.back().id == "new"
          && merged_profile.models.back().enabled
          && merged_profile.models.back().capabilities == "New metadata, tools"
          && merged_profile.models.back().context_length == DefaultModelContextLength
          && merged_profile.models.back().max_output_tokens == DefaultModelMaxOutputTokens,
      "newly discovered model defaults mismatch");
  Require(merged_profile.settings.model == "default", "enabled default model was replaced");

  ProviderProfileDraft &fallback_profile = merged.profiles[1];
  fallback_profile.models = {{"disabled", false, "", 0, 0}};
  fallback_profile.settings.model = "disabled";
  MergeDiscoveredModels(
      fallback_profile,
      {{"replacement", false, "", 0, 0}});
  Require(
      fallback_profile.settings.model == "replacement",
      "invalid default did not fall back to the first enabled model");
  fallback_profile.models.back().enabled = false;
  MergeDiscoveredModels(fallback_profile, {});
  Require(fallback_profile.settings.model.empty(), "default was not cleared without enabled models");
  NormalizeProviderManagerDraft(merged);
  Require(IsValidManagerDraft(merged), "merged provider manager was rejected");

  ProviderSettingsDraft url_draft = DraftForPreset(ProviderPreset::Custom);
  for ( const char *allowed : {
             "http://localhost:11434/v1",
             "http://127.255.255.255/v1",
             "http://[::1]:8080/v1",
             "http://192.168.100.1:8317/v1",
             "http://provider.example/v1",
             "http://128.0.0.1/v1",
             "https://provider.example/v1"} )
  {
    url_draft.base_url = allowed;
    Require(IsValidDraft(url_draft), "allowed URL was rejected");
  }
  for ( const char *rejected : {
            "https://user:password@provider.example/v1",
            "https://provider.example/v1?debug=1",
            "https://provider.example/v1#fragment",
            "https://provider.example/v1\r\nInjected: true"} )
  {
    url_draft.base_url = rejected;
    Require(!IsValidDraft(url_draft), "unsafe URL was accepted");
  }

  ProviderManagerDraft headers = CreateProviderManagerDraft();
  ProviderProfileDraft &header_profile = FirstProfile(headers);
  header_profile.custom_headers.push_back(
      ProviderHeaderDraft{"Authorization", "Bearer plaintext", true});
  header_profile.custom_headers.push_back(
      ProviderHeaderDraft{"x-api-key", "plaintext", false});
  Require(IsValidManagerDraft(headers), "supported custom authentication headers were rejected");
  header_profile.custom_headers.push_back(
      ProviderHeaderDraft{"user-agent", "duplicate", true});
  Require(!IsValidManagerDraft(headers), "case-insensitive duplicate header was accepted");
  header_profile.custom_headers.pop_back();
  header_profile.custom_headers.push_back(ProviderHeaderDraft{"Host", "example.com", true});
  Require(!IsValidManagerDraft(headers), "dangerous Host header was accepted");
  header_profile.custom_headers.back() = ProviderHeaderDraft{"X-Test", "ok\r\nInjected: yes", true};
  Require(!IsValidManagerDraft(headers), "header injection was accepted");
  header_profile.custom_headers.back() = ProviderHeaderDraft{"Bad Header", "value", true};
  Require(!IsValidManagerDraft(headers), "invalid HTTP token header name was accepted");

  ProviderManagerDraft disabled_default = CreateProviderManagerDraft();
  ProviderProfileDraft &disabled_profile = FirstProfile(disabled_default);
  disabled_profile.models.push_back(ProviderModelDraft{"disabled", false, "", 0, 0});
  disabled_profile.settings.model = "disabled";
  Require(!IsValidManagerDraft(disabled_default), "disabled model was accepted as default");

  ProviderProxyDraft proxy;
  Require(IsValidProviderProxyDraft(proxy), "system proxy mode was rejected");
  proxy.mode = ProviderProxyMode::Direct;
  Require(IsValidProviderProxyDraft(proxy), "direct proxy mode was rejected");
  proxy.host = "proxy.example";
  Require(!IsValidProviderProxyDraft(proxy), "direct proxy accepted an endpoint");

  for ( const char *allowed : {
            "proxy.example",
            "192.0.2.10",
            "2001:db8::1",
            "::1"} )
  {
    proxy = {};
    proxy.mode = ProviderProxyMode::Http;
    proxy.host = allowed;
    proxy.port = 8080;
    Require(IsValidProviderProxyDraft(proxy), "valid HTTP proxy host was rejected");
  }

  proxy = {};
  proxy.mode = ProviderProxyMode::Http;
  proxy.host = "  [2001:db8::1]  ";
  proxy.port = 3128;
  proxy.username = "  proxy-user  ";
  proxy.password = "  password is not trimmed  ";
  NormalizeProviderProxyDraft(proxy);
  Require(proxy.host == "2001:db8::1", "IPv6 proxy brackets were not normalized");
  Require(proxy.username == "proxy-user", "proxy username was not trimmed");
  Require(
      proxy.password == "  password is not trimmed  ",
      "proxy password was unexpectedly trimmed");
  Require(IsValidProviderProxyDraft(proxy), "normalized HTTP proxy was rejected");

  for ( const char *rejected : {
            "",
            "http://proxy.example",
            "proxy.example/path",
            "user@proxy.example",
            "proxy.example?query",
            "proxy.example#fragment",
            "proxy example",
            "999.1.1.1",
            "2001:db8:::1"} )
  {
    proxy = {};
    proxy.mode = ProviderProxyMode::Http;
    proxy.host = rejected;
    proxy.port = 8080;
    Require(!IsValidProviderProxyDraft(proxy), "invalid HTTP proxy host was accepted");
  }
  proxy.host = "proxy.example";
  proxy.port = 0;
  Require(!IsValidProviderProxyDraft(proxy), "zero HTTP proxy port was accepted");
  proxy.port = 8080;
  proxy.username = "bad\nuser";
  Require(!IsValidProviderProxyDraft(proxy), "control character in proxy username was accepted");
  return 0;
}
