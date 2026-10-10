#pragma once

#include "rpc/dispatcher.hpp"

namespace ida_agent::bridge { class IdaExecutor; }
namespace ida_agent::services { class ScriptService; }

namespace ida_agent::bridge
{
Dispatcher::MethodHandlers BuildScriptHandlers(IdaExecutor &, const services::ScriptService &);
} // namespace ida_agent::bridge
