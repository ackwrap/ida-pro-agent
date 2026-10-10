#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ida_agent::services
{

struct FunctionFlags
{
  bool no_return = false;
  bool far = false;
  bool library = false;
  bool static_definition = false;
  bool frame = false;
  bool hidden = false;
  bool thunk = false;
  bool lumina = false;
  bool outlined = false;
};

struct FunctionStatistics
{
  std::uint64_t size_bytes = 0;
  std::uint64_t instruction_count = 0;
  std::uint64_t basic_block_count = 0;
  std::uint64_t chunk_count = 0;
};

struct FunctionInfo
{
  std::uint64_t entry_address;
  std::uint64_t range_start;
  std::uint64_t range_end;
  std::string name;
  std::optional<std::string> signature;
  FunctionFlags flags;
  FunctionStatistics statistics;
};

enum class FunctionLookupStatus
{
  Found,
  InvalidAddress,
  NotFound,
  OutputLimit,
};

struct FunctionLookup
{
  FunctionLookupStatus status;
  std::optional<FunctionInfo> info;
};

struct FunctionSummary
{
  std::uint64_t entry_address;
  std::string name;
};

struct FunctionSearchResult
{
  std::vector<FunctionSummary> items;
  std::optional<std::string> next_cursor;
  bool has_more = false;
};

enum class FunctionSearchStatus
{
  Success,
  InvalidAddress,
  InvalidCursor,
  OutputLimit,
};

struct FunctionSearchOutcome
{
  FunctionSearchStatus status;
  std::optional<FunctionSearchResult> result;
};

struct FunctionPageQuery
{
  std::uint64_t address;
  std::uint32_t offset;
  std::uint32_t limit;
};

struct DisassemblyItem
{
  std::uint64_t address;
  std::string text;
};

struct FunctionDisassemblyResult
{
  std::uint64_t entry_address;
  std::vector<DisassemblyItem> items;
  std::optional<std::uint32_t> next_offset;
  bool has_more = false;
};

enum class BasicBlockType
{
  Normal,
  IndirectJump,
  Return,
  ConditionalReturn,
  NoReturn,
  ExternalNoReturn,
  External,
  Error,
};

struct BasicBlock
{
  std::uint64_t start;
  std::uint64_t end;
  BasicBlockType type;
  std::vector<std::uint64_t> successors;
  std::vector<std::uint64_t> predecessors;
};

struct FunctionBasicBlocksResult
{
  std::uint64_t entry_address;
  std::vector<BasicBlock> items;
  std::optional<std::uint32_t> next_offset;
  bool has_more = false;
};

struct FunctionCallee
{
  std::uint64_t address;
  std::string name;
  bool internal;
};

struct FunctionCalleesResult
{
  std::uint64_t entry_address;
  std::vector<FunctionCallee> items;
  std::optional<std::uint32_t> next_offset;
  bool has_more = false;
};

struct FunctionCaller
{
  std::uint64_t address;
  std::string name;
  std::vector<std::uint64_t> call_sites;
};

struct FunctionCallersResult
{
  std::uint64_t entry_address;
  std::vector<FunctionCaller> items;
  std::optional<std::uint32_t> next_offset;
  bool has_more = false;
};

enum class CallGraphDirection
{
  Callers,
  Callees,
  Both,
};

struct CallGraphQuery
{
  std::vector<std::uint64_t> roots;
  CallGraphDirection direction;
  std::uint32_t max_depth;
  std::uint32_t max_nodes;
  std::uint32_t max_edges;
  std::uint32_t per_function;
};

struct CallGraphNode
{
  std::uint64_t address;
  std::string name;
  std::uint32_t depth;
};

struct CallGraphEdge
{
  std::uint64_t from;
  std::uint64_t to;
};

struct FunctionCallGraphResult
{
  std::vector<CallGraphNode> nodes;
  std::vector<CallGraphEdge> edges;
  bool truncated = false;
};

enum class FunctionAnalysisStatus
{
  Success,
  InvalidAddress,
  NotFound,
  OutputLimit,
};

template <typename Result>
struct FunctionAnalysisOutcome
{
  FunctionAnalysisStatus status;
  std::optional<Result> result;
};

using FunctionDisassemblyOutcome = FunctionAnalysisOutcome<FunctionDisassemblyResult>;
using FunctionBasicBlocksOutcome = FunctionAnalysisOutcome<FunctionBasicBlocksResult>;
using FunctionCalleesOutcome = FunctionAnalysisOutcome<FunctionCalleesResult>;
using FunctionCallersOutcome = FunctionAnalysisOutcome<FunctionCallersResult>;
using FunctionCallGraphOutcome = FunctionAnalysisOutcome<FunctionCallGraphResult>;

class FunctionService
{
public:
  // The caller must run this read operation through IdaExecutor.
  FunctionLookup Get(std::uint64_t address) const;
  FunctionSearchOutcome SearchByName(
      std::string_view name,
      std::uint32_t limit,
      const std::optional<std::string> &cursor) const;
  FunctionSearchOutcome SearchByAddress(std::uint64_t address) const;
  FunctionDisassemblyOutcome Disassemble(const FunctionPageQuery &query) const;
  FunctionBasicBlocksOutcome BasicBlocks(const FunctionPageQuery &query) const;
  FunctionCalleesOutcome Callees(const FunctionPageQuery &query) const;
  FunctionCallersOutcome Callers(const FunctionPageQuery &query) const;
  FunctionCallGraphOutcome CallGraph(const CallGraphQuery &query) const;

private:
  struct PageCache;
  PageCache &Pages() const;
  mutable std::shared_ptr<PageCache> page_cache_;
};

nlohmann::json ToJson(const FunctionInfo &info);
nlohmann::json ToJson(const FunctionSearchResult &result);
nlohmann::json ToJson(const FunctionDisassemblyResult &result);
nlohmann::json ToJson(const FunctionBasicBlocksResult &result);
nlohmann::json ToJson(const FunctionCalleesResult &result);
nlohmann::json ToJson(const FunctionCallersResult &result);
nlohmann::json ToJson(const FunctionCallGraphResult &result);

} // namespace ida_agent::services
