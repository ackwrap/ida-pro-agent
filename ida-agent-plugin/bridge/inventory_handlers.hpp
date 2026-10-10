#pragma once

#include "rpc/dispatcher.hpp"

namespace ida_agent::bridge
{
class IdaExecutor;
}

namespace ida_agent::services
{
class DatabaseService;
class StringService;
class SymbolService;
}

namespace ida_agent::bridge
{

Dispatcher::MethodHandlers BuildInventoryHandlers(
    IdaExecutor &executor,
    const services::DatabaseService &database_service,
    const services::StringService &string_service,
    const services::SymbolService &symbol_service);

} // namespace ida_agent::bridge
