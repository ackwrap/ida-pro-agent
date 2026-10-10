#pragma once

#include <nlohmann/json_fwd.hpp>

#include <memory>

namespace ida_agent::ai
{

enum class AgentToolName;
struct AgentToolInvokers;

enum class AdditionalAgentToolStatus
{
  NotHandled,
  Invalid,
  Success,
};

AdditionalAgentToolStatus InvokeAdditionalAgentTool(
    AgentToolName tool,
    const nlohmann::json &arguments,
    const std::shared_ptr<AgentToolInvokers> &invokers,
    nlohmann::json &response,
    bool &page);

} // namespace ida_agent::ai
