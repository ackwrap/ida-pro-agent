#include "ai/agent_tool_registry.hpp"

#include "ai/agent_tool_composites.hpp"
#include "ai/agent_tool_registry_internal.hpp"
#include "bridge/ida_executor.hpp"
#include "services/changeset_service.hpp"
#include "services/database_service.hpp"
#include "services/decompiler_service.hpp"
#include "services/debugger_service.hpp"
#include "services/function_service.hpp"
#include "services/source_info_service.hpp"
#include "services/annotation_service.hpp"
#include "services/decompiler_inspection_service.hpp"
#include "services/semantic_analysis/service.hpp"
#include "services/readonly_analysis_service.hpp"
#include "services/search_service.hpp"
#include "services/string_service.hpp"
#include "services/symbol_service.hpp"
#include "services/type_service.hpp"
#include "services/xref_service.hpp"

#include <chrono>
#include <optional>
#include <stdexcept>
#include <utility>

namespace ida_agent::ai
{
namespace
{
using Json = nlohmann::json;

Json Readonly(services::ReadonlyResult result)
{
  switch ( result.status )
  {
    case services::ReadonlyStatus::InvalidAddress: throw AgentToolSafeError("IDA address or range is invalid.");
    case services::ReadonlyStatus::NotFound: throw AgentToolSafeError("Requested IDA object was not found.");
    case services::ReadonlyStatus::OutputLimit: throw AgentToolSafeError("IDA output exceeded service limits.");
    case services::ReadonlyStatus::Success: return std::move(result.value);
  }
  throw std::runtime_error("readonly analysis failed");
}

template <typename Outcome>
Json Search(Outcome outcome)
{
  switch ( outcome.status )
  {
    case services::SearchStatus::InvalidAddress: throw AgentToolSafeError("Search address or range is invalid.");
    case services::SearchStatus::InvalidCursor: throw std::runtime_error("unexpected search cursor failure");
    case services::SearchStatus::InvalidPattern: throw AgentToolSafeError("Search pattern is invalid.");
    case services::SearchStatus::NotFound: throw AgentToolSafeError("Search target was not found.");
    case services::SearchStatus::OutputLimit: throw AgentToolSafeError("Search output exceeded service limits.");
    case services::SearchStatus::Success: break;
  }
  if ( !outcome.result ) throw std::runtime_error("search failed");
  return services::ToJson(*outcome.result);
}

template <typename Outcome>
Json Type(Outcome outcome)
{
  switch ( outcome.status )
  {
    case services::TypeStatus::InvalidAddress: throw AgentToolSafeError("Type address is invalid.");
    case services::TypeStatus::InvalidArgument: throw AgentToolSafeError("Type request is invalid.");
    case services::TypeStatus::NotFound: throw AgentToolSafeError("Type information was not found.");
    case services::TypeStatus::OutputLimit: throw AgentToolSafeError("Type output exceeded service limits.");
    case services::TypeStatus::Success: break;
  }
  if ( !outcome.result ) throw std::runtime_error("type query failed");
  return services::ToJson(*outcome.result);
}

Json Query(services::QueryResult result)
{
  switch ( result.status )
  {
    case services::QueryStatus::InvalidAddress: throw AgentToolSafeError("IDA address or range is invalid.");
    case services::QueryStatus::InvalidArgument: throw AgentToolSafeError("Read-only request is invalid.");
    case services::QueryStatus::NotFound: throw AgentToolSafeError("Requested IDA object was not found.");
    case services::QueryStatus::CapabilityUnavailable: throw AgentToolSafeError("Requested IDA capability is unavailable.");
    case services::QueryStatus::Conflict: throw AgentToolSafeError("Requested debugger state is unavailable.");
    case services::QueryStatus::Busy: throw AgentToolSafeError("Decompiler is busy.");
    case services::QueryStatus::DecompileFailed: throw AgentToolSafeError("Decompilation failed.");
    case services::QueryStatus::OutputLimit: throw AgentToolSafeError("IDA output exceeded service limits.");
    case services::QueryStatus::Success: return std::move(result.value);
  }
  throw std::runtime_error("inspection query failed");
}

template <typename Outcome>
Json Debugger(Outcome outcome)
{
  switch ( outcome.status )
  {
    case services::DebuggerStatus::Unavailable: throw AgentToolSafeError("Debugger is unavailable.");
    case services::DebuggerStatus::AlreadyRunning: throw AgentToolSafeError("Debugger is already running.");
    case services::DebuggerStatus::NotRunning: throw AgentToolSafeError("Debugger is not running.");
    case services::DebuggerStatus::NotSuspended: throw AgentToolSafeError("Debugger is not suspended.");
    case services::DebuggerStatus::InvalidAddress: throw AgentToolSafeError("Debugger address is invalid.");
    case services::DebuggerStatus::InvalidArgument: throw AgentToolSafeError("Debugger request is invalid.");
    case services::DebuggerStatus::NotFound: throw AgentToolSafeError("Debugger object was not found.");
    case services::DebuggerStatus::Failed: throw AgentToolSafeError("Debugger rejected the read request.");
    case services::DebuggerStatus::StateUncertain: throw AgentToolSafeError("Debugger state is uncertain.");
    case services::DebuggerStatus::OutputLimit: throw AgentToolSafeError("Debugger output exceeded service limits.");
    case services::DebuggerStatus::Success: break;
  }
  if ( !outcome.result ) throw std::runtime_error("debugger result is unavailable");
  return services::ToJson(*outcome.result);
}

Json ChangeSet(services::AuditOutcome outcome)
{
  switch ( outcome.status )
  {
    case services::ChangeStatus::InvalidAddress: throw AgentToolSafeError("ChangeSet address is invalid.");
    case services::ChangeStatus::InvalidArgument: throw AgentToolSafeError("ChangeSet audit request is invalid.");
    case services::ChangeStatus::Conflict: throw AgentToolSafeError("ChangeSet state conflicts with the request.");
    case services::ChangeStatus::NotFound: throw AgentToolSafeError("ChangeSet audit was not found.");
    case services::ChangeStatus::CapabilityUnavailable: throw AgentToolSafeError("ChangeSet capability is unavailable.");
    case services::ChangeStatus::Failed: throw AgentToolSafeError("ChangeSet audit read failed.");
    case services::ChangeStatus::OutputLimit: throw AgentToolSafeError("ChangeSet output exceeded service limits.");
    case services::ChangeStatus::Success: break;
  }
  if ( !outcome.result ) throw std::runtime_error("changeset audit result is unavailable");
  return services::ToJson(*outcome.result);
}

Json ChangeSetPreview(services::PreviewOutcome outcome)
{
  switch ( outcome.status )
  {
    case services::ChangeStatus::InvalidAddress: throw AgentToolSafeError("ChangeSet address is invalid.");
    case services::ChangeStatus::InvalidArgument: throw AgentToolSafeError("ChangeSet preview request is invalid.");
    case services::ChangeStatus::Conflict: throw AgentToolSafeError("ChangeSet preview conflicts with database state.");
    case services::ChangeStatus::NotFound: throw AgentToolSafeError("ChangeSet preview target was not found.");
    case services::ChangeStatus::CapabilityUnavailable: throw AgentToolSafeError("ChangeSet preview capability is unavailable.");
    case services::ChangeStatus::Failed: throw AgentToolSafeError("ChangeSet preview failed.");
    case services::ChangeStatus::OutputLimit: throw AgentToolSafeError("ChangeSet preview exceeded the Agent output limit.");
    case services::ChangeStatus::Success: break;
  }
  if ( !outcome.result ) throw std::runtime_error("changeset preview result is unavailable");
  Json result = services::ToJson(*outcome.result);
  if ( result.dump().size() > MaxAgentToolResultBytes )
    throw AgentToolSafeError("ChangeSet preview exceeded the Agent output limit.");
  return result;
}

services::SignatureFormat SignatureFormat(std::string_view value)
{
  if ( value == "x64dbg" ) return services::SignatureFormat::X64Dbg;
  if ( value == "mask" ) return services::SignatureFormat::Mask;
  if ( value == "bitmask" ) return services::SignatureFormat::Bitmask;
  return services::SignatureFormat::Ida;
}

template <typename Operation>
Json ReadFor(bridge::IdaExecutor &executor, Operation operation)
{
  return executor.ReadFor(std::chrono::seconds(12), std::move(operation));
}
} // namespace

void PopulateExtendedAgentToolInvokers(
    AgentToolInvokers &invokers,
    bridge::IdaExecutor &executor,
    services::DatabaseService &database_service,
    services::DecompilerService &decompiler_service,
    services::FunctionService &function_service,
    services::ReadonlyAnalysisService &readonly_service,
    services::SearchService &search_service,
    services::StringService &string_service,
    services::SymbolService &symbol_service,
    services::TypeService &type_service,
    services::XrefService &xref_service,
    services::SourceInfoService &source_info_service,
    services::AnnotationService &annotation_service,
    services::DecompilerInspectionService &decompiler_inspection_service,
    services::SemanticAnalysisService &semantic_analysis_service,
    services::DebuggerService &debugger_service,
    services::ChangeSetService &changeset_service)
{
  invokers.fixup_list = [&executor, &readonly_service](const AgentOptionalRangeArguments &args)
  {
    return ReadFor(executor, [&readonly_service, args]()
    {
      const auto start = args.has_range ? std::optional<std::uint64_t>(args.start) : std::nullopt;
      const auto end = args.has_range ? std::optional<std::uint64_t>(args.end) : std::nullopt;
      return Readonly(readonly_service.FixupList(start, end, args.limit, std::nullopt));
    });
  };
  invokers.exception_try_blocks = [&executor, &readonly_service](const AgentAddressLimitArguments &args)
  {
    return ReadFor(executor, [&readonly_service, args]() { return Readonly(readonly_service.ExceptionTryBlocks(args.address, args.limit)); });
  };
  invokers.analysis_status = [&executor, &readonly_service]()
  {
    return ReadFor(executor, [&readonly_service]() { return Readonly(readonly_service.AnalysisStatus()); });
  };
  invokers.analysis_problems = [&executor, &readonly_service](const AgentAnalysisProblemsArguments &args)
  {
    return ReadFor(executor, [&readonly_service, args]()
    {
      const auto start = args.has_start ? std::optional<std::uint64_t>(args.start) : std::nullopt;
      return Readonly(readonly_service.AnalysisProblems(args.type, start, args.limit, std::nullopt));
    });
  };
  invokers.listing_search = [&executor, &search_service](const AgentListingArguments &args)
  {
    return ReadFor(executor, [&search_service, args]() { return Search(search_service.Listing(
        args.start, args.end, args.pattern, false, true, false, args.limit, std::nullopt)); });
  };
  invokers.listing_search_text = [&executor, &search_service](const AgentListingArguments &args)
  {
    return ReadFor(executor, [&search_service, args]() { return Search(search_service.Listing(
        args.start, args.end, args.pattern, args.mode == "regex", args.include_disassembly,
        args.include_comments, args.limit, std::nullopt)); });
  };
  invokers.signature_xrefs = [&executor, &search_service](const AgentSignatureXrefsArguments &args)
  {
    return ReadFor(executor, [&search_service, args]() { return Search(search_service.XrefSignatures(
        args.address, SignatureFormat(args.format), args.wildcard_operands, args.max_length, args.top)); });
  };
  invokers.function_stack_frame = [&executor, &type_service](std::uint64_t address)
  {
    return ReadFor(executor, [&type_service, address]() { return Type(type_service.StackFrame(address)); });
  };
  invokers.source_files = [&executor, &source_info_service](std::uint32_t limit)
  {
    return ReadFor(executor, [&source_info_service, limit]() { return Query(source_info_service.SourceFiles(limit, 0)); });
  };
  invokers.source_lines = [&executor, &source_info_service](const AgentRangeArguments &args)
  {
    return ReadFor(executor, [&source_info_service, args]() { return Query(
        source_info_service.SourceLines(args.start, args.end, args.limit, std::nullopt)); });
  };
  invokers.name_demangle = [&executor, &symbol_service](const AgentDemangleArguments &args)
  {
    return ReadFor(executor, [&symbol_service, args]()
    {
      const auto address = args.selector == "address" ? std::optional<std::uint64_t>(args.address) : std::nullopt;
      const auto name = args.selector == "name" ? std::optional<std::string>(args.name) : std::nullopt;
      return Query(symbol_service.Demangle(address, name));
    });
  };
  invokers.comment_get = [&executor, &annotation_service](const AgentCommentArguments &args)
  {
    return ReadFor(executor, [&annotation_service, args]() { return Query(
        annotation_service.CommentGet(args.address, args.scope, args.repeatable)); });
  };
  invokers.bookmark_list = [&executor, &annotation_service](std::uint32_t limit)
  {
    return ReadFor(executor, [&annotation_service, limit]() { return Query(annotation_service.BookmarkList(limit, 0)); });
  };
  invokers.type_xrefs = [&executor, &type_service](const AgentListArguments &args)
  {
    return ReadFor(executor, [&type_service, args]() { return Query(
        type_service.TypeXrefs(args.first, args.limit, 0)); });
  };
  invokers.decompiler_locals = [&executor, &decompiler_inspection_service](const AgentAddressLimitArguments &args)
  {
    return ReadFor(executor, [&decompiler_inspection_service, args]() { return Query(
        decompiler_inspection_service.DecompilerLocals(args.address, args.limit)); });
  };
  invokers.decompiler_ctree = [&executor, &decompiler_inspection_service](const AgentCtreeArguments &args)
  {
    return ReadFor(executor, [&decompiler_inspection_service, args]() { return Query(
        decompiler_inspection_service.DecompilerCtree(args.address, args.max_depth, args.max_nodes)); });
  };
  invokers.decompiler_local_xrefs = [&executor, &decompiler_inspection_service](const AgentLocalXrefsArguments &args)
  {
    return ReadFor(executor, [&decompiler_inspection_service, args]() { return Query(decompiler_inspection_service.DecompilerLocalXrefs(
        args.address, args.local_index, args.max_depth, args.max_nodes, args.max_items)); });
  };
  invokers.debugger_backends = [&executor, &debugger_service]()
  {
    return executor.DebuggerFor(std::chrono::seconds(12), [&]() { return Debugger(debugger_service.Backends()); });
  };
  invokers.debugger_configuration = [&executor, &debugger_service]()
  {
    return executor.DebuggerFor(std::chrono::seconds(12), [&]() { return Debugger(debugger_service.Configuration()); });
  };
  invokers.debugger_processes = [&executor, &debugger_service](std::uint32_t limit)
  {
    return executor.DebuggerFor(std::chrono::seconds(12), [&]() { return Debugger(debugger_service.Processes(limit)); });
  };
  invokers.debugger_info = [&executor, &debugger_service]()
  {
    return executor.DebuggerFor(std::chrono::seconds(12), [&debugger_service]() { return Debugger(debugger_service.Info()); });
  };
  invokers.debugger_breakpoint_list = [&executor, &debugger_service]()
  {
    return ReadFor(executor, [&debugger_service]() { return Debugger(debugger_service.Breakpoints()); });
  };
  invokers.debugger_registers = [&executor, &debugger_service](const AgentDebuggerRegistersArguments &args)
  {
    return ReadFor(executor, [&debugger_service, args]() { return Debugger(debugger_service.Registers(
        {args.thread_mode, args.thread_ids, args.register_mode, args.names})); });
  };
  invokers.debugger_stacktrace = [&executor, &debugger_service](const AgentDebuggerStacktraceArguments &args)
  {
    return ReadFor(executor, [&debugger_service, args]() { return Debugger(debugger_service.StackTrace(
        args.thread_id == 0 ? std::nullopt : std::optional<std::int64_t>(args.thread_id), args.limit)); });
  };
  invokers.debugger_memory_read = [&executor, &debugger_service](const AgentAddressLimitArguments &args)
  {
    return ReadFor(executor, [&debugger_service, args]() { return Debugger(
        debugger_service.ReadMemory(args.address, args.limit)); });
  };
  invokers.changeset_audit = [&executor, &changeset_service](const AgentAuditArguments &args)
  {
    return ReadFor(executor, [&changeset_service, args]() { return ChangeSet(
        changeset_service.Audit(args.offset, args.limit)); });
  };
  invokers.debugger_threads = [&executor, &debugger_service](std::uint32_t limit)
  {
    return ReadFor(executor, [&debugger_service, limit]() {
      return Query(debugger_service.DebuggerThreads(limit, 0));
    });
  };
  invokers.debugger_modules = [&executor, &debugger_service](std::uint32_t limit)
  {
    return ReadFor(executor, [&debugger_service, limit]() {
      return Query(debugger_service.DebuggerModules(limit, 0));
    });
  };
  invokers.changeset_preview = [&executor, &changeset_service](
      const AgentChangeSetPreviewArguments &args)
  {
    return ReadFor(executor, [&changeset_service, args]() {
      return ChangeSetPreview(changeset_service.Preview(args.operations));
    });
  };
  invokers.database_survey = [&executor, &database_service, &function_service,
      &string_service, &symbol_service](const AgentDatabaseSurveyArguments &args)
  {
    return ReadFor(executor, [&database_service, &function_service, &string_service,
        &symbol_service, args]() {
      return composite::DatabaseSurvey(
          database_service, function_service, string_service, symbol_service, args);
    });
  };
  invokers.function_profile = [&executor, &function_service](
      const AgentFunctionProfileArguments &args)
  {
    return ReadFor(executor, [&function_service, args]() {
      return composite::FunctionProfile(function_service, args);
    });
  };
  invokers.function_export = [&executor, &function_service](
      const AgentFunctionExportArguments &args)
  {
    return ReadFor(executor, [&function_service, args]() {
      return composite::FunctionExport(function_service, args);
    });
  };
  invokers.function_analyze = [&executor, &function_service, &decompiler_service,
      &string_service, &xref_service](const AgentFunctionAnalyzeArguments &args)
  {
    return ReadFor(executor, [&function_service, &decompiler_service, &string_service,
        &xref_service, args]() {
      return composite::FunctionAnalyze(
          function_service, decompiler_service, string_service, xref_service, args);
    });
  };
  invokers.analysis_component = [&executor, &function_service, &string_service,
      &symbol_service, &xref_service](const AgentAnalysisComponentArguments &args)
  {
    return ReadFor(executor, [&function_service, &string_service, &symbol_service,
        &xref_service, args]() {
      return composite::AnalysisComponent(
          function_service, string_service, symbol_service, xref_service, args);
    });
  };
  invokers.analysis_trace_data_flow = [&executor, &function_service, &string_service,
      &symbol_service, &xref_service](const AgentTraceDataFlowArguments &args)
  {
    return ReadFor(executor, [&function_service, &string_service, &symbol_service,
        &xref_service, args]() {
      return composite::TraceDataFlow(
          function_service, string_service, symbol_service, xref_service, args);
    });
  };
  invokers.argument_callers = [&executor, &semantic_analysis_service](const services::semantic::CallersRequest &request) {
    return executor.ReadFor(std::chrono::seconds(60), [&semantic_analysis_service, request]() {
      return Query(semantic_analysis_service.TraceArgumentCallers(request));
    });
  };
  invokers.argument_analysis = [&executor, &semantic_analysis_service](const services::semantic::Request &args, bool guards)
  {
    return executor.ReadFor(std::chrono::seconds(60), [&semantic_analysis_service, args, guards]() {
      return Query(semantic_analysis_service.AnalyzeArgument(args, guards));
    });
  };
}

} // namespace ida_agent::ai
