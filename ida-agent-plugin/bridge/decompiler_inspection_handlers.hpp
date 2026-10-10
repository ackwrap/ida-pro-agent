#pragma once
#include "rpc/dispatcher.hpp"
namespace ida_agent::bridge { class IdaExecutor; }
namespace ida_agent::services { class DecompilerInspectionService; }
namespace ida_agent::bridge
{
Dispatcher::MethodHandlers BuildDecompilerInspectionHandlers(IdaExecutor &, const services::DecompilerInspectionService &);
}
