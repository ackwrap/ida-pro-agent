#pragma once

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

namespace ida_agent::ai
{

inline constexpr std::uint32_t DefaultModelContextLength = 1'000'000U;
inline constexpr std::uint32_t DefaultModelMaxOutputTokens = 128'000U;
inline constexpr std::size_t MaxCapabilitiesLength = 1024;

enum class ProviderPreset
{
  OpenAI,
  Claude,
  Custom,
};

enum class ProviderProtocol
{
  OpenAI,
  Claude,
};

enum class OpenAIApiMode
{
  Responses,
  ChatCompletions,
};

enum class ProviderReasoningEffort
{
  Default,
  None,
  Low,
  Medium,
  High,
  XHigh,
  Max,
};

enum class ProviderReasoningSummary
{
  Hidden,
  Visible,
  Auto,
  Concise,
  Detailed,
};

enum class ProviderProxyMode
{
  System,
  Direct,
  Http,
};

struct ProviderProxyDraft
{
  ProviderProxyMode mode = ProviderProxyMode::System;
  std::string host;
  std::uint16_t port = 0;
  std::string username;
  std::string password;
  bool bypass_local = true;
};

struct ProviderSettingsDraft
{
  std::string display_name;
  ProviderProtocol protocol = ProviderProtocol::OpenAI;
  OpenAIApiMode openai_api_mode = OpenAIApiMode::Responses;
  std::string base_url;
  std::string model;
  std::string api_key;
};

struct ProviderHeaderDraft
{
  std::string name;
  std::string value;
  bool enabled = true;
};

struct ProviderModelDraft
{
  std::string id;
  bool enabled = true;
  std::string capabilities;
  std::uint32_t context_length = 0;
  std::uint32_t max_output_tokens = 0;
  ProviderReasoningEffort reasoning_effort = ProviderReasoningEffort::Default;
  ProviderReasoningSummary reasoning_summary = ProviderReasoningSummary::Visible;
};

inline std::string_view ProviderReasoningEffortName(
    ProviderReasoningEffort value) noexcept
{
  switch ( value )
  {
    case ProviderReasoningEffort::Default: return "default";
    case ProviderReasoningEffort::None: return "none";
    case ProviderReasoningEffort::Low: return "low";
    case ProviderReasoningEffort::Medium: return "medium";
    case ProviderReasoningEffort::High: return "high";
    case ProviderReasoningEffort::XHigh: return "xhigh";
    case ProviderReasoningEffort::Max: return "max";
  }
  return "default";
}

inline std::string_view ProviderReasoningSummaryName(
    ProviderReasoningSummary value) noexcept
{
  switch ( value )
  {
    case ProviderReasoningSummary::Hidden: return "hidden";
    case ProviderReasoningSummary::Visible: return "visible";
    case ProviderReasoningSummary::Auto: return "auto";
    case ProviderReasoningSummary::Concise: return "concise";
    case ProviderReasoningSummary::Detailed: return "detailed";
  }
  return "visible";
}

inline bool ParseProviderReasoningEffort(
    std::string_view value,
    ProviderReasoningEffort &result) noexcept
{
  // Migrate the removed provider-specific level without invalidating saved profiles.
  if ( value == "minimal" )
  {
    result = ProviderReasoningEffort::Low;
    return true;
  }
  for ( ProviderReasoningEffort candidate : {
            ProviderReasoningEffort::Default,
            ProviderReasoningEffort::None,
            ProviderReasoningEffort::Low,
            ProviderReasoningEffort::Medium,
            ProviderReasoningEffort::High,
            ProviderReasoningEffort::XHigh,
            ProviderReasoningEffort::Max} )
  {
    if ( value == ProviderReasoningEffortName(candidate) )
    {
      result = candidate;
      return true;
    }
  }
  return false;
}

inline bool ParseProviderReasoningSummary(
    std::string_view value,
    ProviderReasoningSummary &result) noexcept
{
  for ( ProviderReasoningSummary candidate : {
            ProviderReasoningSummary::Hidden,
            ProviderReasoningSummary::Visible,
            ProviderReasoningSummary::Auto,
            ProviderReasoningSummary::Concise,
            ProviderReasoningSummary::Detailed} )
  {
    if ( value == ProviderReasoningSummaryName(candidate) )
    {
      result = candidate;
      return true;
    }
  }
  return false;
}

void ApplyDefaultModelMetadata(ProviderModelDraft &model) noexcept;

struct ProviderProfileDraft
{
  std::string id;
  bool built_in = false;
  ProviderSettingsDraft settings;
  std::vector<ProviderModelDraft> models;
  std::vector<ProviderHeaderDraft> custom_headers;
  ProviderProxyDraft proxy;
};

struct ProviderManagerDraft
{
  std::vector<ProviderProfileDraft> profiles;
  std::string active_profile_id;
  std::uint64_t next_custom_id = 1;
};

ProviderSettingsDraft DraftForPreset(ProviderPreset preset);
std::string_view DefaultBrowserUserAgent() noexcept;
ProviderPreset PresetForDraft(const ProviderSettingsDraft &draft);
void SetProtocol(ProviderSettingsDraft &draft, ProviderProtocol protocol);
void NormalizeProviderProxyDraft(ProviderProxyDraft &draft);
bool IsValidProviderProxyDraft(const ProviderProxyDraft &draft);
void NormalizeProviderManagerDraft(ProviderManagerDraft &draft);
void MergeDiscoveredModels(
    ProviderProfileDraft &profile,
    const std::vector<ProviderModelDraft> &incoming);
bool IsValidDraft(const ProviderSettingsDraft &draft);
ProviderManagerDraft CreateProviderManagerDraft();
ProviderProfileDraft *FindProvider(
    ProviderManagerDraft &draft,
    std::string_view profile_id) noexcept;
const ProviderProfileDraft *FindProvider(
    const ProviderManagerDraft &draft,
    std::string_view profile_id) noexcept;
ProviderProfileDraft *ActiveProvider(ProviderManagerDraft &draft) noexcept;
const ProviderProfileDraft *ActiveProvider(const ProviderManagerDraft &draft) noexcept;
std::string AddCustomProvider(ProviderManagerDraft &draft);
bool RemoveCustomProvider(ProviderManagerDraft &draft, std::string_view profile_id);
bool IsValidManagerDraft(const ProviderManagerDraft &draft);

} // namespace ida_agent::ai
