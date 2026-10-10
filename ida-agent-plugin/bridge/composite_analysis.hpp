#pragma once

#include "rpc/dispatcher.hpp"

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace ida_agent::services
{
class DecompilerService;
class FunctionService;
class StringService;
class SymbolService;
class XrefService;
struct FunctionCallGraphResult;
}

namespace ida_agent::bridge::composite
{

nlohmann::json AnalyzeOne(
    const services::FunctionService &functions,
    const services::DecompilerService &decompiler,
    const services::StringService &strings,
    const services::XrefService &xrefs,
    std::uint64_t address,
    const std::set<std::string> &sections,
    std::uint32_t per_section,
    std::uint32_t decompile_bytes);

Dispatcher::MethodResult AnalyzeBatch(
    const services::FunctionService &functions,
    const services::DecompilerService &decompiler,
    const services::StringService &strings,
    const services::XrefService &xrefs,
    const std::vector<std::uint64_t> &addresses,
    const std::set<std::string> &sections,
    std::uint32_t per_section,
    std::uint32_t decompile_bytes,
    std::size_t maximum_bytes);

Dispatcher::MethodResult ExportFunctions(
    const services::FunctionService &functions,
    const std::vector<std::uint64_t> &addresses,
    std::string_view format,
    std::uint32_t maximum_bytes);

nlohmann::json BuildComponent(
    const services::FunctionService &functions,
    const services::StringService &strings,
    const services::SymbolService &symbols,
    const services::XrefService &xrefs,
    const services::FunctionCallGraphResult &graph,
    std::uint32_t per_function,
    std::uint32_t shared_limit);

nlohmann::json BuildTraceNodes(
    const services::FunctionService &functions,
    const services::StringService &strings,
    const services::SymbolService &symbols,
    const std::set<std::uint64_t> &addresses,
    std::uint32_t inventory_limit,
    bool *truncated);

} // namespace ida_agent::bridge::composite
