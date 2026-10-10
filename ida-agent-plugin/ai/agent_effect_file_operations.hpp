#pragma once

#include "ai/agent_effect_service.hpp"

namespace ida_agent::ai::agent_effect_file_operations
{

AgentEffectPreparation Prepare(
    const AgentEffectServiceCallbacks &callbacks,
    AgentEffectName effect,
    const AgentToolCall &call,
    const nlohmann::json &arguments);

AgentToolResult Execute(
    const AgentEffectServiceCallbacks &callbacks,
    AgentEffectName effect,
    const AgentToolCall &call,
    const std::string &payload);

} // namespace ida_agent::ai::agent_effect_file_operations
