#pragma once
#include "rpc/dispatcher.hpp"
namespace ida_agent::bridge { class IdaExecutor; }
namespace ida_agent::services { class AnnotationService; }
namespace ida_agent::bridge
{
Dispatcher::MethodHandlers BuildAnnotationHandlers(IdaExecutor &, const services::AnnotationService &);
}
