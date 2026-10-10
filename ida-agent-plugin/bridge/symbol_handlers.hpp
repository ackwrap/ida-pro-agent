#pragma once
#include "rpc/dispatcher.hpp"
namespace ida_agent::bridge { class IdaExecutor; }
namespace ida_agent::services { class SymbolService; }
namespace ida_agent::bridge
{
Dispatcher::MethodHandlers BuildSymbolHandlers(IdaExecutor &, const services::SymbolService &);
}
