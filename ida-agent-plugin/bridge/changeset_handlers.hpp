#pragma once
#include "rpc/dispatcher.hpp"
namespace ida_agent::bridge { class IdaExecutor; }
namespace ida_agent::services { class ChangeSetService; }
namespace ida_agent::bridge { Dispatcher::MethodHandlers BuildChangeSetHandlers(IdaExecutor &, services::ChangeSetService &); }
