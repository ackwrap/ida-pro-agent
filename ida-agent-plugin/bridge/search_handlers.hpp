#pragma once

#include "rpc/dispatcher.hpp"

namespace ida_agent::bridge { class IdaExecutor; }
namespace ida_agent::services { class SearchService; }

namespace ida_agent::bridge
{
Dispatcher::MethodHandlers BuildSearchHandlers(
    IdaExecutor &executor,
    const services::SearchService &search_service);
}
