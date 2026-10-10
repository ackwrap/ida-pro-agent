#pragma once

#include "ai/chat_transcript.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ida_agent::ai
{

std::optional<std::string> EncodeChatHistory(const std::vector<ChatEntry> &entries);
std::optional<std::vector<ChatEntry>> DecodeChatHistory(std::string_view encoded);

} // namespace ida_agent::ai
