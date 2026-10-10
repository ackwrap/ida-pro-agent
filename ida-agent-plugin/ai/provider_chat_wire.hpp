#pragma once

#include "ai/provider_chat.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ida_agent::ai::provider_chat_wire
{

std::string BuildRequestBody(
    ProviderChatCodec codec,
    const ProviderSettingsDraft &settings,
    const ProviderModelDraft &model,
    std::uint32_t max_output_tokens,
    const std::vector<ProviderChatMessage> &messages,
    const ProviderChatAgentOptions &options);

std::size_t FixedMessageItemCount(
    ProviderChatCodec codec,
    const ProviderChatAgentOptions &options);

} // namespace ida_agent::ai::provider_chat_wire
