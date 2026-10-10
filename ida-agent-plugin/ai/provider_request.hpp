#pragma once

#include "ai/network_types.hpp"
#include "ai/provider_settings_model.hpp"

#include <optional>
#include <string>
#include <vector>

namespace ida_agent::ai
{

// Transport-neutral request fields shared by model discovery and chat.
struct ProviderRequestParts
{
  ProviderSettingsDraft settings;
  std::string user_agent;
  std::vector<ProviderHeaderDraft> headers;
  ProviderProxyDraft proxy;
};

std::optional<ProviderRequestParts> BuildProviderRequestParts(
    const ProviderProfileDraft &profile,
    bool require_json_content_type);

std::optional<HttpProxyConfig> BuildHttpProxyConfig(
    const ProviderProxyDraft &proxy);

} // namespace ida_agent::ai
