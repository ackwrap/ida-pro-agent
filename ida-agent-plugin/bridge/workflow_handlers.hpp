#pragma once

#include "rpc/dispatcher.hpp"

namespace ida_agent::bridge
{
class IdaExecutor;
}

namespace ida_agent::services
{
class ChangeSetService;
class DatabaseService;
class DecompilerService;
}

namespace ida_agent::bridge
{

Dispatcher::MethodHandlers BuildWorkflowHandlers(
    IdaExecutor &executor,
    services::DatabaseService &database_service,
    const services::DecompilerService &decompiler_service,
    services::ChangeSetService &changeset_service);

} // namespace ida_agent::bridge
