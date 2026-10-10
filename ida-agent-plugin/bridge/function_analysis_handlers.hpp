#pragma once

#include "rpc/dispatcher.hpp"

namespace ida_agent::bridge
{

class IdaExecutor;

} // namespace ida_agent::bridge

namespace ida_agent::services
{

class FunctionService;

} // namespace ida_agent::services

namespace ida_agent::bridge
{

Dispatcher::MethodHandlers BuildFunctionAnalysisHandlers(
    IdaExecutor &executor,
    const services::FunctionService &function_service);

} // namespace ida_agent::bridge
