#pragma once

#include <string>
#include <string_view>

namespace ida_agent::ai
{
std::string_view AgentSystemPrompt() noexcept;
std::string BuildChatSystemPrompt(bool agent_tools);
std::string_view ChatCompactionSystemPrompt() noexcept;
} // namespace ida_agent::ai
