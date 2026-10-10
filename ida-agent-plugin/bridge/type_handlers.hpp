#pragma once
#include "rpc/dispatcher.hpp"
namespace ida_agent::bridge { class IdaExecutor; }
namespace ida_agent::services { class TypeService; }
namespace ida_agent::bridge { Dispatcher::MethodHandlers BuildTypeHandlers(IdaExecutor &, const services::TypeService &); }
