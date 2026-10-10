#pragma once

#include "rpc/dispatcher.hpp"

namespace ida_agent::services { class ReadonlyAnalysisService; }
namespace ida_agent::bridge
{
class IdaExecutor;
Dispatcher::MethodHandlers BuildReadonlyAnalysisHandlers(
    IdaExecutor &executor,
    const services::ReadonlyAnalysisService &service);
}
