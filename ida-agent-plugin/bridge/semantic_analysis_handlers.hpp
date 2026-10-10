#pragma once
#include "rpc/dispatcher.hpp"
namespace ida_agent::services { class SemanticAnalysisService; }
namespace ida_agent::bridge
{
class IdaExecutor;
Dispatcher::MethodHandlers BuildSemanticAnalysisHandlers(IdaExecutor &, const services::SemanticAnalysisService &);
}
