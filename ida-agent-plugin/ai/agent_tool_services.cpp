#include "ai/agent_tool_registry.hpp"
#include "ai/agent_file_service.hpp"
#include "ai/agent_ui_context.hpp"

#include "ai/agent_tool_registry_internal.hpp"
#include "bridge/ida_executor.hpp"
#include "services/database_service.hpp"
#include "services/decompiler_service.hpp"
#include "services/function_service.hpp"
#include "services/inventory.hpp"
#include "services/memory_service.hpp"
#include "services/readonly_analysis_service.hpp"
#include "services/search_service.hpp"
#include "services/string_service.hpp"
#include "services/symbol_service.hpp"
#include "services/type_service.hpp"
#include "services/xref_service.hpp"

#include <chrono>
#include <optional>
#include <regex>
#include <stdexcept>
#include <utility>

namespace ida_agent::ai
{

using Json = nlohmann::json;

namespace
{
template <typename Outcome>
Json InventoryPage(Outcome outcome)
{
  if ( outcome.status == services::InventoryStatus::OutputLimit )
    throw AgentToolSafeError("Inventory result exceeded service limits.");
  if ( outcome.status != services::InventoryStatus::Success || !outcome.result )
    throw std::runtime_error("inventory query failed");
  Json encoded = services::ToJson(*outcome.result);
  return {{"items", std::move(encoded["items"])}, {"hasMore", outcome.result->has_more}};
}

Json FunctionSearch(services::FunctionSearchOutcome outcome)
{
  switch ( outcome.status )
  {
    case services::FunctionSearchStatus::InvalidAddress:
      throw AgentToolSafeError("Function address is invalid.");
    case services::FunctionSearchStatus::InvalidCursor:
      throw std::runtime_error("unexpected function cursor failure");
    case services::FunctionSearchStatus::OutputLimit:
      throw AgentToolSafeError("Function search exceeded service limits.");
    case services::FunctionSearchStatus::Success:
      break;
  }
  if ( !outcome.result ) throw std::runtime_error("function search failed");
  Json encoded = services::ToJson(*outcome.result);
  return {{"items", std::move(encoded["items"])}, {"hasMore", outcome.result->has_more}};
}

template <typename Outcome>
Json FunctionAnalysis(Outcome outcome)
{
  switch ( outcome.status )
  {
    case services::FunctionAnalysisStatus::InvalidAddress:
      throw AgentToolSafeError("Function address is invalid.");
    case services::FunctionAnalysisStatus::NotFound:
      throw AgentToolSafeError("Function was not found.");
    case services::FunctionAnalysisStatus::OutputLimit:
      throw AgentToolSafeError("Function analysis exceeded service limits.");
    case services::FunctionAnalysisStatus::Success:
      break;
  }
  if ( !outcome.result ) throw std::runtime_error("function analysis failed");
  return services::ToJson(*outcome.result);
}

Json Readonly(services::ReadonlyResult result)
{
  switch ( result.status )
  {
    case services::ReadonlyStatus::InvalidAddress:
      throw AgentToolSafeError("IDA address is invalid.");
    case services::ReadonlyStatus::NotFound:
      throw AgentToolSafeError("Requested IDA object was not found.");
    case services::ReadonlyStatus::OutputLimit:
      throw AgentToolSafeError("IDA output exceeded service limits.");
    case services::ReadonlyStatus::Success:
      return std::move(result.value);
  }
  throw std::runtime_error("readonly analysis failed");
}

template <typename Outcome>
Json Search(Outcome outcome)
{
  switch ( outcome.status )
  {
    case services::SearchStatus::InvalidAddress:
      throw AgentToolSafeError("Search address or range is invalid.");
    case services::SearchStatus::InvalidCursor:
      throw std::runtime_error("unexpected search cursor failure");
    case services::SearchStatus::InvalidPattern:
      throw AgentToolSafeError("Search pattern is invalid.");
    case services::SearchStatus::NotFound:
      throw AgentToolSafeError("Search target was not found.");
    case services::SearchStatus::OutputLimit:
      throw AgentToolSafeError("Search output exceeded service limits.");
    case services::SearchStatus::Success:
      break;
  }
  if ( !outcome.result ) throw std::runtime_error("search failed");
  return services::ToJson(*outcome.result);
}

template <typename Outcome>
Json TypeResult(Outcome outcome)
{
  switch ( outcome.status )
  {
    case services::TypeStatus::InvalidAddress:
      throw AgentToolSafeError("Type address is invalid.");
    case services::TypeStatus::InvalidArgument:
      throw AgentToolSafeError("Type request is invalid.");
    case services::TypeStatus::NotFound:
      throw AgentToolSafeError("Type information was not found.");
    case services::TypeStatus::OutputLimit:
      throw AgentToolSafeError("Type output exceeded service limits.");
    case services::TypeStatus::Success:
      break;
  }
  if ( !outcome.result ) throw std::runtime_error("type query failed");
  return services::ToJson(*outcome.result);
}

template <typename Operation>
Json ReadFor(bridge::IdaExecutor &executor, Operation operation)
{
  return executor.ReadFor(std::chrono::seconds(12), std::move(operation));
}
} // namespace

AgentToolRegistry::AgentToolRegistry(
    bridge::IdaExecutor &executor,
    services::SymbolService &symbol_service,
    services::StringService &string_service,
    services::FunctionService &function_service,
    services::DecompilerService &decompiler_service,
    services::XrefService &xref_service,
    services::MemoryService &memory_service,
    services::DatabaseService &database_service,
    services::ReadonlyAnalysisService &readonly_service,
    services::SearchService &search_service,
    services::TypeService &type_service,
    services::SourceInfoService &source_info_service,
    services::AnnotationService &annotation_service,
    services::DecompilerInspectionService &decompiler_inspection_service,
    services::SemanticAnalysisService &semantic_analysis_service,
    services::DebuggerService &debugger_service,
    services::ChangeSetService &changeset_service,
    AgentFileService &file_service)
    : AgentToolRegistry(
          [&executor, &symbol_service](std::string_view name, std::uint32_t limit)
          {
            return executor.ReadFor(
                std::chrono::seconds(12),
                [&symbol_service, name, limit]()
                {
                  const auto outcome = symbol_service.Exports(
                      name, limit, std::nullopt);
                  if ( outcome.status != services::InventoryStatus::Success
                      || !outcome.result )
                  {
                    throw std::runtime_error("symbol export query failed");
                  }
                  Json encoded = services::ToJson(*outcome.result);
                  return Json{
                      {"items", std::move(encoded["items"])},
                      {"hasMore", outcome.result->has_more},
                  };
                });
          },
          [&executor, &string_service](
              std::string_view query,
              std::uint32_t minimum_length,
              std::uint32_t limit,
              bool refresh)
          {
            return executor.ReadFor(
                std::chrono::seconds(12),
                [&string_service, query, minimum_length, limit, refresh]()
                {
                  const auto outcome = string_service.Search(
                      query, minimum_length, limit, std::nullopt, refresh);
                  if ( outcome.status != services::InventoryStatus::Success
                      || !outcome.result )
                  {
                    throw std::runtime_error("string query failed");
                  }
                  Json encoded = services::ToJson(*outcome.result);
                  return Json{
                      {"items", std::move(encoded["items"])},
                      {"hasMore", outcome.result->has_more},
                  };
                });
          },
          [&executor, &function_service](std::uint64_t address)
          {
            return executor.ReadFor(
                std::chrono::seconds(12),
                [&function_service, address]()
                {
                  const auto outcome = function_service.Get(address);
                  switch ( outcome.status )
                  {
                    case services::FunctionLookupStatus::Found:
                      if ( outcome.info )
                        return services::ToJson(*outcome.info);
                      break;
                    case services::FunctionLookupStatus::InvalidAddress:
                      throw AgentToolSafeError("Function address is invalid.");
                    case services::FunctionLookupStatus::NotFound:
                      throw AgentToolSafeError("Function was not found.");
                    case services::FunctionLookupStatus::OutputLimit:
                      throw AgentToolSafeError("Function result exceeded service limits.");
                  }
                  throw std::runtime_error("function lookup failed");
                });
          },
          [&executor, &decompiler_service](
              std::uint64_t address,
              std::uint32_t offset,
              std::uint32_t max_bytes)
          {
            return executor.ReadFor(
                std::chrono::seconds(12),
                [&decompiler_service, address, offset, max_bytes]()
                {
                  const auto outcome = decompiler_service.Decompile(
                      {address, offset, max_bytes});
                  if ( outcome.status == services::DecompileStatus::Success
                      && outcome.result )
                  {
                    return services::ToJson(*outcome.result);
                  }
                  switch ( outcome.status )
                  {
                    case services::DecompileStatus::InvalidAddress:
                      throw AgentToolSafeError("Decompiler address is invalid.");
                    case services::DecompileStatus::NotFound:
                      throw AgentToolSafeError("Function was not found.");
                    case services::DecompileStatus::CapabilityUnavailable:
                      throw AgentToolSafeError("Decompiler is unavailable.");
                    case services::DecompileStatus::InvalidArgument:
                      throw AgentToolSafeError("Decompiler arguments are invalid.");
                    case services::DecompileStatus::Busy:
                      throw AgentToolSafeError("Decompiler is busy.");
                    case services::DecompileStatus::OutputLimit:
                      throw AgentToolSafeError("Decompiler result exceeded service limits.");
                    case services::DecompileStatus::Failed:
                    case services::DecompileStatus::Success:
                      break;
                  }
                  throw AgentToolSafeError("Decompilation failed.");
                });
          },
          [&executor, &xref_service](
              std::uint64_t address,
              std::string_view direction,
              std::string_view category,
              bool include_flow,
              std::uint32_t limit)
          {
            return executor.ReadFor(
                std::chrono::seconds(12),
                [&xref_service, address, direction, category, include_flow, limit]()
                {
                  const services::XrefDirection parsed_direction =
                      direction == "incoming"
                      ? services::XrefDirection::Incoming
                      : services::XrefDirection::Outgoing;
                  services::XrefCategory parsed_category = services::XrefCategory::All;
                  if ( category == "code" )
                    parsed_category = services::XrefCategory::Code;
                  else if ( category == "data" )
                    parsed_category = services::XrefCategory::Data;
                  const auto outcome = xref_service.Query({
                      address,
                      parsed_direction,
                      parsed_category,
                      include_flow,
                      limit,
                      std::nullopt,
                  });
                  if ( outcome.status == services::XrefQueryStatus::Success
                      && outcome.result )
                  {
                    Json encoded = services::ToJson(*outcome.result);
                    return Json{
                        {"items", std::move(encoded["items"])},
                        {"hasMore", outcome.result->has_more},
                    };
                  }
                  if ( outcome.status == services::XrefQueryStatus::InvalidAddress )
                    throw AgentToolSafeError("Cross-reference address is invalid.");
                  if ( outcome.status == services::XrefQueryStatus::OutputLimit )
                    throw AgentToolSafeError("Cross-reference result exceeded service limits.");
                  throw std::runtime_error("cross-reference query failed");
                });
          },
          [&executor, &memory_service](
              std::uint64_t address,
              std::string_view format,
              std::uint32_t length,
              std::uint32_t width_bits)
          {
            return executor.ReadFor(
                std::chrono::seconds(12),
                [&memory_service, address, format, length, width_bits]()
                {
                  services::MemoryFormat parsed_format = services::MemoryFormat::Bytes;
                  if ( format == "string" )
                    parsed_format = services::MemoryFormat::String;
                  else if ( format == "integer" )
                    parsed_format = services::MemoryFormat::Integer;
                  else if ( format == "pointer" )
                    parsed_format = services::MemoryFormat::Pointer;
                  const auto outcome = memory_service.Read(
                      {address, parsed_format, length, width_bits});
                  if ( outcome.status == services::MemoryReadStatus::Success
                      && outcome.result )
                  {
                    return services::ToJson(*outcome.result);
                  }
                  switch ( outcome.status )
                  {
                    case services::MemoryReadStatus::InvalidAddress:
                      throw AgentToolSafeError("Memory address is invalid.");
                    case services::MemoryReadStatus::Unreadable:
                      throw AgentToolSafeError("Memory is unreadable.");
                    case services::MemoryReadStatus::UnsupportedProcessor:
                      throw AgentToolSafeError("Memory format is unsupported for this processor.");
                    case services::MemoryReadStatus::InvalidEncoding:
                      throw AgentToolSafeError("Memory does not contain a valid string encoding.");
                    case services::MemoryReadStatus::Success:
                      break;
                  }
                  throw std::runtime_error("memory read failed");
                });
          },
          0)
{
  auto fixed = std::make_shared<AgentToolInvokers>();
  fixed->database_info = [&executor, &database_service]()
  {
    return ReadFor(executor, [&database_service]() { return services::ToJson(database_service.Info()); });
  };
  fixed->database_segments = [&executor, &database_service](const AgentListArguments &args)
  {
    return ReadFor(executor, [&database_service, args]() { return InventoryPage(database_service.Segments(args.first, args.limit, std::nullopt)); });
  };
  fixed->database_entry_points = [&executor, &database_service](const AgentListArguments &args)
  {
    return ReadFor(executor, [&database_service, args]() { return InventoryPage(database_service.EntryPoints(args.first, args.second, args.limit, std::nullopt)); });
  };
  fixed->function_search = [&executor, &function_service](const AgentFunctionSearchArguments &args)
  {
    return ReadFor(executor, [&function_service, args]()
    {
      return FunctionSearch(args.mode == "name"
          ? function_service.SearchByName(args.name, args.limit, std::nullopt)
          : function_service.SearchByAddress(args.address));
    });
  };
  fixed->function_disassemble = [&executor, &function_service](const AgentPageArguments &args)
  {
    return ReadFor(executor, [&function_service, args]() { return FunctionAnalysis(function_service.Disassemble({args.address, args.offset, args.limit})); });
  };
  fixed->function_basic_blocks = [&executor, &function_service](const AgentPageArguments &args)
  {
    return ReadFor(executor, [&function_service, args]() { return FunctionAnalysis(function_service.BasicBlocks({args.address, args.offset, args.limit})); });
  };
  fixed->function_callers = [&executor, &function_service](const AgentPageArguments &args)
  {
    return ReadFor(executor, [&function_service, args]() { return FunctionAnalysis(function_service.Callers({args.address, args.offset, args.limit})); });
  };
  fixed->function_callees = [&executor, &function_service](const AgentPageArguments &args)
  {
    return ReadFor(executor, [&function_service, args]() { return FunctionAnalysis(function_service.Callees({args.address, args.offset, args.limit})); });
  };
  fixed->function_chunks = [&executor, &readonly_service](const AgentPageArguments &args)
  {
    return ReadFor(executor, [&readonly_service, args]() { return Readonly(readonly_service.FunctionChunks(args.address, args.offset, args.limit)); });
  };
  fixed->function_call_graph = [&executor, &function_service](const AgentCallGraphArguments &args)
  {
    return ReadFor(executor, [&function_service, args]()
    {
      services::CallGraphDirection direction = services::CallGraphDirection::Callees;
      if ( args.direction == "callers" ) direction = services::CallGraphDirection::Callers;
      else if ( args.direction == "both" ) direction = services::CallGraphDirection::Both;
      return FunctionAnalysis(function_service.CallGraph({args.roots, direction, args.max_depth,
          args.max_nodes, args.max_edges, args.per_function}));
    });
  };
  fixed->instruction_get = [&executor, &readonly_service](std::uint64_t address)
  {
    return ReadFor(executor, [&readonly_service, address]() { return Readonly(readonly_service.InstructionGet(address)); });
  };
  fixed->fixup_get = [&executor, &readonly_service](std::uint64_t address)
  {
    return ReadFor(executor, [&readonly_service, address]() { return Readonly(readonly_service.FixupGet(address)); });
  };
  fixed->switch_get = [&executor, &readonly_service](std::uint64_t address)
  {
    return ReadFor(executor, [&readonly_service, address]() { return Readonly(readonly_service.SwitchGet(address)); });
  };
  fixed->symbol_imports = [&executor, &symbol_service](const AgentListArguments &args)
  {
    return ReadFor(executor, [&symbol_service, args]() { return InventoryPage(symbol_service.Imports(args.first, args.second, args.limit, std::nullopt)); });
  };
  fixed->symbol_search = [&executor, &symbol_service](const AgentListArguments &args)
  {
    return ReadFor(executor, [&symbol_service, args]() { return InventoryPage(symbol_service.Search(args.first, args.second, args.limit, std::nullopt)); });
  };
  fixed->string_search_regex = [&executor, &string_service](const AgentRegexArguments &args)
  {
    try
    {
      return ReadFor(executor, [&string_service, args]() { return InventoryPage(string_service.SearchRegex(args.pattern, args.minimum_length, args.limit, std::nullopt, args.refresh)); });
    }
    catch ( const std::regex_error & )
    {
      throw AgentToolSafeError("Regular expression is invalid.");
    }
  };
  fixed->memory_search_bytes = [&executor, &search_service](const AgentByteSearchArguments &args)
  {
    return ReadFor(executor, [&search_service, args]() { return Search(search_service.Bytes(args.pattern, args.start, args.end, args.limit)); });
  };
  fixed->instruction_search = [&executor, &search_service](const AgentInstructionSearchArguments &args)
  {
    return ReadFor(executor, [&search_service, args]() { return Search(search_service.Instructions(args.start, args.end, args.mnemonic, args.operand, args.limit, std::nullopt)); });
  };
  fixed->signature_make = [&executor, &search_service](const AgentSignatureArguments &args)
  {
    return ReadFor(executor, [&search_service, args]()
    {
      services::SignatureMode mode = services::SignatureMode::Address;
      if ( args.mode == "function" ) mode = services::SignatureMode::Function;
      else if ( args.mode == "range" ) mode = services::SignatureMode::Range;
      services::SignatureFormat format = services::SignatureFormat::Ida;
      if ( args.format == "x64dbg" ) format = services::SignatureFormat::X64Dbg;
      else if ( args.format == "mask" ) format = services::SignatureFormat::Mask;
      else if ( args.format == "bitmask" ) format = services::SignatureFormat::Bitmask;
      return Search(search_service.MakeSignature(mode, mode == services::SignatureMode::Range ? args.start : args.address,
          mode == services::SignatureMode::Range ? std::optional<std::uint64_t>(args.end) : std::nullopt,
          format, args.wildcard_operands, args.max_length));
    });
  };
  fixed->patch_assemble = [&executor, &search_service](const AgentAssemblyArguments &args)
  {
    return ReadFor(executor, [&search_service, args]() { return Search(search_service.Assemble(args.address, args.instruction)); });
  };
  fixed->type_search = [&executor, &type_service](const AgentTypeSearchArguments &args)
  {
    return ReadFor(executor, [&type_service, args]() { return TypeResult(type_service.Search(args.name, args.kind, args.ordinal, args.limit)); });
  };
  fixed->type_get = [&executor, &type_service](std::string_view name)
  {
    const std::string owned(name);
    return ReadFor(executor, [&type_service, owned]() { return TypeResult(type_service.Get(owned)); });
  };
  fixed->type_infer = [&executor, &type_service](std::uint64_t address)
  {
    return ReadFor(executor, [&type_service, address]() { return TypeResult(type_service.Infer(address)); });
  };
  fixed->type_read_value = [&executor, &type_service](const AgentTypedReadArguments &args)
  {
    return ReadFor(executor, [&type_service, args]() { return TypeResult(type_service.ReadValue(args.address, args.name, args.max_bytes)); });
  };
  fixed->type_read_struct = [&executor, &type_service](const AgentTypedReadArguments &args)
  {
    return ReadFor(executor, [&type_service, args]() { return TypeResult(type_service.ReadStruct(args.address, args.name, args.max_bytes)); });
  };
  fixed->global_value = [&executor, &type_service](const AgentGlobalValueArguments &args)
  {
    return ReadFor(executor, [&type_service, args]()
    {
      const std::optional<std::uint64_t> address = args.selector == "address" ? std::optional<std::uint64_t>(args.address) : std::nullopt;
      const std::optional<std::string> name = args.selector == "name" ? std::optional<std::string>(args.name) : std::nullopt;
      return TypeResult(type_service.GlobalValue(address, name, args.max_bytes));
    });
  };
  fixed->xref_struct_field = [&executor, &type_service](const AgentListArguments &args)
  {
    return ReadFor(executor, [&type_service, args]() { return TypeResult(type_service.FieldXrefs(args.first, args.second, args.limit)); });
  };
  PopulateExtendedAgentToolInvokers(*fixed, executor, database_service,
      decompiler_service, function_service, readonly_service, search_service,
      string_service, symbol_service, type_service, xref_service,
      source_info_service, annotation_service, decompiler_inspection_service, semantic_analysis_service, debugger_service, changeset_service);
  fixed->file_list = [&file_service](const AgentFileListArguments &args)
  {
    return file_service.List(args.path, args.limit);
  };
  fixed->file_stat = [&file_service](std::string_view path)
  {
    return file_service.Stat(path);
  };
  fixed->file_read = [&file_service](const AgentFileReadArguments &args)
  {
    return file_service.Read(args.path, args.offset, args.max_bytes);
  };
  PopulateAgentUiContextInvokers(*fixed, executor);
  fixed_invokers_ = std::move(fixed);
}

} // namespace ida_agent::ai
