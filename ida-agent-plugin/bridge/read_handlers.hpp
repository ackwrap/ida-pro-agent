#pragma once

#include "rpc/dispatcher.hpp"

namespace ida_agent::bridge
{

class IdaExecutor;

} // namespace ida_agent::bridge

namespace ida_agent::services
{

class DatabaseService;
class DecompilerService;
class FunctionService;
class MemoryService;
class SearchService;
class StringService;
class SymbolService;
class TypeService;
class XrefService;

} // namespace ida_agent::services

namespace ida_agent::bridge
{

Dispatcher::MethodHandlers BuildReadHandlers(
    IdaExecutor &executor,
    const services::DatabaseService &database_service,
    const services::FunctionService &function_service,
    const services::XrefService &xref_service,
    const services::MemoryService &memory_service,
    const services::DecompilerService &decompiler_service,
    const services::SearchService &search_service,
    const services::StringService &string_service,
    const services::SymbolService &symbol_service,
    const services::TypeService &type_service);

} // namespace ida_agent::bridge
