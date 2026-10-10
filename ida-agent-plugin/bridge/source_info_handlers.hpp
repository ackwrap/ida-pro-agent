#pragma once
#include "rpc/dispatcher.hpp"
namespace ida_agent::bridge { class IdaExecutor; }
namespace ida_agent::services { class SourceInfoService; }
namespace ida_agent::bridge
{
Dispatcher::MethodHandlers BuildSourceInfoHandlers(IdaExecutor &, const services::SourceInfoService &);
}
