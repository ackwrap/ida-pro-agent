#pragma once

#include "ai/agent_tool_registry.hpp"

#include <nlohmann/json_fwd.hpp>

namespace ida_agent::services
{
class DatabaseService;
class DecompilerService;
class FunctionService;
class StringService;
class SymbolService;
class XrefService;
}

namespace ida_agent::ai::composite
{

nlohmann::json DatabaseSurvey(
    const services::DatabaseService &database,
    const services::FunctionService &functions,
    const services::StringService &strings,
    const services::SymbolService &symbols,
    const AgentDatabaseSurveyArguments &arguments);

nlohmann::json FunctionProfile(
    const services::FunctionService &functions,
    const AgentFunctionProfileArguments &arguments);

nlohmann::json FunctionExport(
    const services::FunctionService &functions,
    const AgentFunctionExportArguments &arguments);

nlohmann::json FunctionAnalyze(
    const services::FunctionService &functions,
    const services::DecompilerService &decompiler,
    const services::StringService &strings,
    const services::XrefService &xrefs,
    const AgentFunctionAnalyzeArguments &arguments);

nlohmann::json AnalysisComponent(
    const services::FunctionService &functions,
    const services::StringService &strings,
    const services::SymbolService &symbols,
    const services::XrefService &xrefs,
    const AgentAnalysisComponentArguments &arguments);

nlohmann::json TraceDataFlow(
    const services::FunctionService &functions,
    const services::StringService &strings,
    const services::SymbolService &symbols,
    const services::XrefService &xrefs,
    const AgentTraceDataFlowArguments &arguments);

} // namespace ida_agent::ai::composite
