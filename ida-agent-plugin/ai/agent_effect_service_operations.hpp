#pragma once

#include "ai/agent_effect_service.hpp"

namespace ida_agent::ai::agent_effect_service_operations
{

const char *Name(AgentEffectName effect) noexcept;

AgentEffectPreparation Prepare(
    const AgentEffectServiceCallbacks &callbacks,
    AgentEffectName effect,
    const AgentToolCall &call);

AgentToolResult Execute(
    const AgentEffectServiceCallbacks &callbacks,
    AgentEffectName effect,
    const AgentToolCall &call,
    const std::string &payload);

} // namespace ida_agent::ai::agent_effect_service_operations
