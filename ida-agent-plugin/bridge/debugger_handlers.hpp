#pragma once
#include "rpc/dispatcher.hpp"
namespace ida_agent::bridge { class IdaExecutor; }
namespace ida_agent::services { class DebuggerService; }
namespace ida_agent::bridge { Dispatcher::MethodHandlers BuildDebuggerHandlers(IdaExecutor &, const services::DebuggerService &); }
