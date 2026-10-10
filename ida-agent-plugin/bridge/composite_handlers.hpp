#pragma once
#include "rpc/dispatcher.hpp"
namespace ida_agent::bridge { class IdaExecutor; }
namespace ida_agent::services { class DatabaseService; class DecompilerService; class FunctionService; class StringService; class SymbolService; class XrefService; }
namespace ida_agent::bridge
{
Dispatcher::MethodHandlers BuildCompositeHandlers(
    IdaExecutor &,
    const services::DatabaseService &,
    const services::DecompilerService &,
    const services::FunctionService &,
    const services::StringService &,
    const services::SymbolService &,
    const services::XrefService &);
}
