#pragma once

namespace ida_agent::bridge
{
class IdaExecutor;
}

namespace ida_agent::ai
{

struct AgentToolInvokers;

// Wires the Agent UI-context tools (cursor, selection, highlight, view and
// address boundaries) to invokers that read IDA state on the IDA main thread.
// All IDA/UI access is performed through the provided executor.
void PopulateAgentUiContextInvokers(
    AgentToolInvokers &invokers,
    bridge::IdaExecutor &executor);

} // namespace ida_agent::ai
