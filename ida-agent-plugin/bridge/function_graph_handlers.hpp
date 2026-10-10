#pragma once

#include "rpc/dispatcher.hpp"

namespace ida_agent::bridge
{
class IdaExecutor;
}

namespace ida_agent::services
{
class FunctionService;
}

namespace ida_agent::bridge
{
Dispatcher::MethodHandlers BuildFunctionGraphHandlers(
    IdaExecutor &executor,
    const services::FunctionService &function_service);
}
