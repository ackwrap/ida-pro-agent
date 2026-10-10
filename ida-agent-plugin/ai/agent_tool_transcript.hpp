#pragma once

#include <string>

namespace ida_agent::ai
{

struct AgentToolCall;
struct AgentToolResult;

std::string FormatAgentToolCallTranscript(const AgentToolCall &call);
std::string FormatAgentToolResultTranscript(const AgentToolResult &result);

} // namespace ida_agent::ai
