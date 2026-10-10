#pragma once

#include "services/changeset_service.hpp"
#include "services/semantic_analysis/model.hpp"
#include "services/semantic_analysis/callers.hpp"

#include <nlohmann/json.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ida_agent::bridge
{
class IdaExecutor;
}

namespace ida_agent::services
{
class DatabaseService;
class ChangeSetService;
class DecompilerService;
class DebuggerService;
class FunctionService;
class MemoryService;
class SourceInfoService;
class AnnotationService;
class DecompilerInspectionService;
class SemanticAnalysisService;
class ReadonlyAnalysisService;
class SearchService;
class StringService;
class SymbolService;
class TypeService;
class XrefService;
}

namespace ida_agent::ai
{

class AgentFileService;

inline constexpr std::size_t MaxAgentToolCallIdBytes = 256;
inline constexpr std::size_t MaxAgentToolNameBytes = 64;
inline constexpr std::size_t MaxAgentToolArgumentsBytes = 64 * 1024;
// A 128 KiB UTF-8 file mutation can expand to roughly three times its byte
// size when non-BMP code points are emitted as JSON surrogate pairs.
inline constexpr std::size_t MaxAgentFileToolArgumentsBytes = 400 * 1024;
inline constexpr std::size_t MaxAgentToolResultBytes = 256 * 1024;
inline constexpr std::size_t MaxAgentFileToolResultBytes = 400 * 1024;

enum class AgentToolName
{
  SymbolExports,
  StringSearch,
  FunctionGet,
  Decompile,
  XrefQuery,
  MemoryRead,
  DatabaseInfo,
  DatabaseSegments,
  DatabaseEntryPoints,
  FunctionSearch,
  FunctionDisassemble,
  FunctionBasicBlocks,
  FunctionCallers,
  FunctionCallees,
  FunctionChunks,
  FunctionCallGraph,
  InstructionGet,
  FixupGet,
  SwitchGet,
  SymbolImports,
  SymbolSearch,
  StringSearchRegex,
  MemorySearchBytes,
  InstructionSearch,
  SignatureMake,
  PatchAssemble,
  TypeSearch,
  TypeGet,
  TypeInfer,
  TypeReadValue,
  TypeReadStruct,
  GlobalValue,
  XrefStructField,
  FixupList,
  ExceptionTryBlocks,
  AnalysisStatus,
  AnalysisProblems,
  ListingSearch,
  ListingSearchText,
  SignatureXrefs,
  FunctionStackFrame,
  SourceFiles,
  SourceLines,
  NameDemangle,
  CommentGet,
  BookmarkList,
  TypeXrefs,
  DecompilerLocals,
  DecompilerCtree,
  DecompilerLocalXrefs,
  DebuggerBackends,
  DebuggerConfiguration,
  DebuggerProcesses,
  DebuggerInfo,
  DebuggerBreakpointList,
  DebuggerRegisters,
  DebuggerStacktrace,
  DebuggerMemoryRead,
  ChangeSetAudit,
  DebuggerThreads,
  DebuggerModules,
  ChangeSetPreview,
  DatabaseSurvey,
  FunctionProfile,
  FunctionExport,
  FunctionAnalyze,
  AnalysisComponent,
  AnalysisTraceDataFlow,
  TraceArgument,
  TraceArgumentCallers,
  GuardEvidence,
  FileList,
  FileStat,
  FileRead,
  UiCursor,
  UiSelection,
  UiHighlight,
  UiView,
  AddressBoundaries,
};

struct AgentListArguments
{
  std::string first;
  std::string second;
  std::uint32_t limit = 20;
};

struct AgentFunctionSearchArguments
{
  std::string mode;
  std::string name;
  std::uint64_t address = 0;
  std::uint32_t limit = 20;
};

struct AgentPageArguments
{
  std::uint64_t address = 0;
  std::uint32_t offset = 0;
  std::uint32_t limit = 20;
};

struct AgentCallGraphArguments
{
  std::vector<std::uint64_t> roots;
  std::string direction;
  std::uint32_t max_depth = 2;
  std::uint32_t max_nodes = 100;
  std::uint32_t max_edges = 200;
  std::uint32_t per_function = 100;
};

struct AgentByteSearchArguments
{
  std::string pattern;
  std::uint64_t start = 0;
  std::uint64_t end = 0;
  std::uint32_t limit = 20;
};

struct AgentRegexArguments
{
  std::string pattern;
  std::uint32_t minimum_length = 4;
  std::uint32_t limit = 20;
  bool refresh = false;
};

struct AgentInstructionSearchArguments
{
  std::uint64_t start = 0;
  std::uint64_t end = 0;
  std::string mnemonic;
  std::string operand;
  std::uint32_t limit = 20;
};

struct AgentSignatureArguments
{
  std::string mode;
  std::uint64_t address = 0;
  std::uint64_t start = 0;
  std::uint64_t end = 0;
  std::string format;
  bool wildcard_operands = true;
  std::uint32_t max_length = 1000;
};

struct AgentAssemblyArguments
{
  std::uint64_t address = 0;
  std::string instruction;
};

struct AgentTypeSearchArguments
{
  std::string name;
  std::string kind;
  std::uint32_t ordinal = 1;
  std::uint32_t limit = 20;
};

struct AgentTypedReadArguments
{
  std::uint64_t address = 0;
  std::string name;
  std::uint32_t max_bytes = 4096;
};

struct AgentGlobalValueArguments
{
  std::string selector;
  std::uint64_t address = 0;
  std::string name;
  std::uint32_t max_bytes = 4096;
};

struct AgentOptionalRangeArguments
{
  bool has_range = false;
  std::uint64_t start = 0;
  std::uint64_t end = 0;
  std::uint32_t limit = 20;
};

struct AgentAddressLimitArguments
{
  std::uint64_t address = 0;
  std::uint32_t limit = 20;
};

struct AgentRangeArguments
{
  std::uint64_t start = 0;
  std::uint64_t end = 0;
  std::uint32_t limit = 20;
};

struct AgentAnalysisProblemsArguments
{
  std::string type;
  bool has_start = false;
  std::uint64_t start = 0;
  std::uint32_t limit = 20;
};

struct AgentListingArguments
{
  std::uint64_t start = 0;
  std::uint64_t end = 0;
  std::string mode;
  std::string pattern;
  bool include_disassembly = true;
  bool include_comments = true;
  std::uint32_t limit = 20;
};

struct AgentSignatureXrefsArguments
{
  std::uint64_t address = 0;
  std::string format;
  bool wildcard_operands = true;
  std::uint32_t max_length = 250;
  std::uint32_t top = 5;
};

struct AgentDemangleArguments
{
  std::string selector;
  std::uint64_t address = 0;
  std::string name;
};

struct AgentCommentArguments
{
  std::uint64_t address = 0;
  std::string scope;
  bool repeatable = false;
};

struct AgentCtreeArguments
{
  std::uint64_t address = 0;
  std::uint32_t max_depth = 8;
  std::uint32_t max_nodes = 200;
};

struct AgentLocalXrefsArguments
{
  std::uint64_t address = 0;
  std::uint32_t local_index = 0;
  std::uint32_t max_depth = 16;
  std::uint32_t max_nodes = 1000;
  std::uint32_t max_items = 100;
};

struct AgentDebuggerRegistersArguments
{
  std::string thread_mode;
  std::vector<std::int64_t> thread_ids;
  std::string register_mode;
  std::vector<std::string> names;
};

struct AgentDebuggerStacktraceArguments
{
  std::int64_t thread_id = 0;
  std::uint32_t limit = 100;
};

struct AgentAuditArguments
{
  std::uint32_t offset = 0;
  std::uint32_t limit = 100;
};

struct AgentChangeSetPreviewArguments
{
  std::vector<services::ChangeOperation> operations;
};

struct AgentDatabaseSurveyArguments
{
  std::string mode;
  std::uint32_t budget = 60;
};

struct AgentFunctionProfileArguments
{
  std::string name;
  std::uint32_t minimum_size = 0;
  std::uint32_t maximum_size = 1024 * 1024;
  std::optional<bool> library;
  std::optional<bool> thunk;
  bool include_prototype = false;
  std::uint32_t sample_limit = 0;
  std::uint32_t limit = 20;
};

struct AgentFunctionExportArguments
{
  std::vector<std::uint64_t> addresses;
  std::string format;
  std::uint32_t max_bytes = 32768;
};

struct AgentFunctionAnalyzeArguments
{
  std::vector<std::uint64_t> addresses;
  std::vector<std::string> sections;
  std::uint32_t per_section = 50;
  std::uint32_t decompile_bytes = 16384;
};

struct AgentAnalysisComponentArguments
{
  std::vector<std::uint64_t> roots;
  std::uint32_t max_depth = 2;
  std::uint32_t max_nodes = 100;
  std::uint32_t max_edges = 200;
  std::uint32_t per_function = 50;
  std::uint32_t shared_limit = 100;
};

struct AgentTraceDataFlowArguments
{
  std::uint64_t address = 0;
  std::string direction;
  std::uint32_t max_depth = 3;
  std::uint32_t max_nodes = 200;
  std::uint32_t max_edges = 500;
};

struct AgentFileListArguments
{
  std::string path;
  std::uint32_t limit = 50;
};

struct AgentFileReadArguments
{
  std::string path;
  std::uint64_t offset = 0;
  std::uint32_t max_bytes = 64 * 1024;
};

struct AgentToolInvokers
{
  using Json = nlohmann::json;
  std::function<Json()> database_info;
  std::function<Json(const AgentListArguments &)> database_segments;
  std::function<Json(const AgentListArguments &)> database_entry_points;
  std::function<Json(const AgentFunctionSearchArguments &)> function_search;
  std::function<Json(const AgentPageArguments &)> function_disassemble;
  std::function<Json(const AgentPageArguments &)> function_basic_blocks;
  std::function<Json(const AgentPageArguments &)> function_callers;
  std::function<Json(const AgentPageArguments &)> function_callees;
  std::function<Json(const AgentPageArguments &)> function_chunks;
  std::function<Json(const AgentCallGraphArguments &)> function_call_graph;
  std::function<Json(std::uint64_t)> instruction_get;
  std::function<Json(std::uint64_t)> fixup_get;
  std::function<Json(std::uint64_t)> switch_get;
  std::function<Json(const AgentListArguments &)> symbol_imports;
  std::function<Json(const AgentListArguments &)> symbol_search;
  std::function<Json(const AgentRegexArguments &)> string_search_regex;
  std::function<Json(const AgentByteSearchArguments &)> memory_search_bytes;
  std::function<Json(const AgentInstructionSearchArguments &)> instruction_search;
  std::function<Json(const AgentSignatureArguments &)> signature_make;
  std::function<Json(const AgentAssemblyArguments &)> patch_assemble;
  std::function<Json(const AgentTypeSearchArguments &)> type_search;
  std::function<Json(std::string_view)> type_get;
  std::function<Json(std::uint64_t)> type_infer;
  std::function<Json(const AgentTypedReadArguments &)> type_read_value;
  std::function<Json(const AgentTypedReadArguments &)> type_read_struct;
  std::function<Json(const AgentGlobalValueArguments &)> global_value;
  std::function<Json(const AgentListArguments &)> xref_struct_field;
  std::function<Json(const AgentOptionalRangeArguments &)> fixup_list;
  std::function<Json(const AgentAddressLimitArguments &)> exception_try_blocks;
  std::function<Json()> analysis_status;
  std::function<Json(const AgentAnalysisProblemsArguments &)> analysis_problems;
  std::function<Json(const AgentListingArguments &)> listing_search;
  std::function<Json(const AgentListingArguments &)> listing_search_text;
  std::function<Json(const AgentSignatureXrefsArguments &)> signature_xrefs;
  std::function<Json(std::uint64_t)> function_stack_frame;
  std::function<Json(std::uint32_t)> source_files;
  std::function<Json(const AgentRangeArguments &)> source_lines;
  std::function<Json(const AgentDemangleArguments &)> name_demangle;
  std::function<Json(const AgentCommentArguments &)> comment_get;
  std::function<Json(std::uint32_t)> bookmark_list;
  std::function<Json(const AgentListArguments &)> type_xrefs;
  std::function<Json(const AgentAddressLimitArguments &)> decompiler_locals;
  std::function<Json(const AgentCtreeArguments &)> decompiler_ctree;
  std::function<Json(const AgentLocalXrefsArguments &)> decompiler_local_xrefs;
  std::function<Json()> debugger_backends;
  std::function<Json()> debugger_configuration;
  std::function<Json(std::uint32_t)> debugger_processes;
  std::function<Json()> debugger_info;
  std::function<Json()> debugger_breakpoint_list;
  std::function<Json(const AgentDebuggerRegistersArguments &)> debugger_registers;
  std::function<Json(const AgentDebuggerStacktraceArguments &)> debugger_stacktrace;
  std::function<Json(const AgentAddressLimitArguments &)> debugger_memory_read;
  std::function<Json(const AgentAuditArguments &)> changeset_audit;
  std::function<Json(std::uint32_t)> debugger_threads;
  std::function<Json(std::uint32_t)> debugger_modules;
  std::function<Json(const AgentChangeSetPreviewArguments &)> changeset_preview;
  std::function<Json(const AgentDatabaseSurveyArguments &)> database_survey;
  std::function<Json(const AgentFunctionProfileArguments &)> function_profile;
  std::function<Json(const AgentFunctionExportArguments &)> function_export;
  std::function<Json(const AgentFunctionAnalyzeArguments &)> function_analyze;
  std::function<Json(const AgentAnalysisComponentArguments &)> analysis_component;
  std::function<Json(const AgentTraceDataFlowArguments &)> analysis_trace_data_flow;
  std::function<Json(const services::semantic::Request &, bool)> argument_analysis;
  std::function<Json(const services::semantic::CallersRequest &)> argument_callers;
  std::function<Json(const AgentFileListArguments &)> file_list;
  std::function<Json(std::string_view)> file_stat;
  std::function<Json(const AgentFileReadArguments &)> file_read;
  std::function<Json()> ui_cursor;
  std::function<Json()> ui_selection;
  std::function<Json()> ui_highlight;
  std::function<Json()> ui_view;
  std::function<Json(std::uint64_t)> address_boundaries;
};

struct AgentToolDefinition
{
  std::string name;
  std::string description;
  nlohmann::json parameters;
};

struct AgentToolCall
{
  std::string id;
  std::string name;
  std::string arguments_json;
};

struct AgentToolResult
{
  std::string call_id;
  std::string name;
  bool success = false;
  std::string output;
  std::string safe_message;
};

inline std::optional<std::size_t> AgentToolResultContentBytes(
    const AgentToolResult &result) noexcept
{
  if ( result.output.size()
      > (std::numeric_limits<std::size_t>::max)() - result.safe_message.size() )
  {
    return std::nullopt;
  }
  return result.output.size() + result.safe_message.size();
}

const std::vector<AgentToolDefinition> &AgentToolDefinitions();
const std::vector<AgentToolDefinition> &ExtendedAgentToolDefinitions();

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
    services::ChangeSetService &changeset_service);

class AgentToolRegistry
{
public:
  using JobId = std::uint64_t;

  AgentToolRegistry(
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
      AgentFileService &file_service);

  AgentToolRegistry(const AgentToolRegistry &) = delete;
  AgentToolRegistry &operator=(const AgentToolRegistry &) = delete;
  ~AgentToolRegistry();

  const std::vector<AgentToolDefinition> &Definitions() const noexcept;
  AgentToolResult Invoke(const AgentToolCall &call) const noexcept;
  JobId Submit(std::vector<AgentToolCall> calls);
  std::optional<std::vector<AgentToolResult>> TryTake(JobId job_id);
  void CancelAndForget(JobId job_id) noexcept;
  void SetAvailable(bool available) noexcept;
  bool Available() const noexcept;

#ifdef IDA_AGENT_AGENT_TOOL_REGISTRY_TESTING
  static AgentToolRegistry ForTesting(
      std::function<nlohmann::json(std::string_view, std::uint32_t)> exports,
      std::function<nlohmann::json(
          std::string_view, std::uint32_t, std::uint32_t, bool)> strings);
  static AgentToolRegistry ForTesting(
      std::function<nlohmann::json(std::string_view, std::uint32_t)> exports,
      std::function<nlohmann::json(
          std::string_view, std::uint32_t, std::uint32_t, bool)> strings,
      std::function<nlohmann::json(std::uint64_t)> function_get,
      std::function<nlohmann::json(
          std::uint64_t, std::uint32_t, std::uint32_t)> decompile,
      std::function<nlohmann::json(
          std::uint64_t, std::string_view, std::string_view, bool,
          std::uint32_t)> xrefs,
      std::function<nlohmann::json(
          std::uint64_t, std::string_view, std::uint32_t,
          std::uint32_t)> memory);
  static AgentToolRegistry ForTesting(AgentToolInvokers invokers);
#endif

private:
  using ExportInvoker =
      std::function<nlohmann::json(std::string_view, std::uint32_t)>;
  using StringInvoker = std::function<nlohmann::json(
      std::string_view, std::uint32_t, std::uint32_t, bool)>;
  using FunctionInvoker = std::function<nlohmann::json(std::uint64_t)>;
  using DecompileInvoker = std::function<nlohmann::json(
      std::uint64_t, std::uint32_t, std::uint32_t)>;
  using XrefInvoker = std::function<nlohmann::json(
      std::uint64_t, std::string_view, std::string_view, bool,
      std::uint32_t)>;
  using MemoryInvoker = std::function<nlohmann::json(
      std::uint64_t, std::string_view, std::uint32_t, std::uint32_t)>;

  AgentToolRegistry(
      ExportInvoker exports,
      StringInvoker strings,
      FunctionInvoker function_get,
      DecompileInvoker decompile,
      XrefInvoker xrefs,
      MemoryInvoker memory,
      int);
  AgentToolRegistry(AgentToolInvokers invokers, int, int);

  ExportInvoker exports_;
  StringInvoker strings_;
  FunctionInvoker function_get_;
  DecompileInvoker decompile_;
  XrefInvoker xrefs_;
  MemoryInvoker memory_;
  std::shared_ptr<AgentToolInvokers> fixed_invokers_;
  std::atomic<bool> available_{false};
  struct Jobs;
  std::unique_ptr<Jobs> jobs_;
};

} // namespace ida_agent::ai
