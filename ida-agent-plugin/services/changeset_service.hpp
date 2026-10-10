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

enum class ChangeKind
{
  Rename,
  CommentSet,
  CommentAppend,
  PseudocodeComment,
  Bookmark,
  TypeApply,
  PatchBytes,
  PatchInteger,
  DefineFunction,
  DefineCode,
  Undefine,
  ForceRecompile,
  MakeData,
  OperandHex,
  OperandDec,
  OperandChar,
  OperandBinary,
  OperandOctal,
  OperandOffset,
  OperandStructOffset,
  OperandStackVariable,
  DeclareType,
  EnumUpsert,
  InvalidateAllDecompilations,
  StackDeclare,
  StackDelete,
  LocalRename,
  LocalType,
  SegmentRename,
  SegmentPermissions,
  XrefCodeAdd,
  XrefCodeDelete,
  XrefDataAdd,
  XrefDataDelete,
  FunctionFlags,
  FunctionEnd,
  FunctionChunkAdd,
  FunctionChunkDelete,
};
struct ChangeOperation
{
  ChangeKind kind;
  std::uint64_t address;
  std::string value;
  std::optional<std::string> expected;
  bool repeatable = false;
  std::optional<std::int64_t> offset;
  std::optional<std::uint32_t> size;
  std::optional<std::string> subject;
};
struct ChangePreviewItem { std::uint32_t index; std::string before; std::string after; bool conflict; };
struct ChangePreview { std::string preview_id; std::vector<ChangePreviewItem> items; bool applicable; };
struct ChangeApplyItem { std::uint32_t index; bool applied; std::optional<std::string> error; };
struct ChangeApplyResult { std::string change_id; std::vector<ChangeApplyItem> items; bool applied; };
struct AuditEntry
{
  std::string change_id;
  std::string session_id;
  std::string operation;
  std::uint64_t address;
  std::string before;
  std::string after;
  bool success;
  std::uint64_t timestamp_ms;
};

enum class ChangeStatus { Success, InvalidAddress, InvalidArgument, Conflict, NotFound, CapabilityUnavailable, Failed, OutputLimit };
template <typename Result> struct ChangeOutcome { ChangeStatus status; std::optional<Result> result; };
using PreviewOutcome = ChangeOutcome<ChangePreview>;
using ApplyOutcome = ChangeOutcome<ChangeApplyResult>;
using AuditOutcome = ChangeOutcome<std::vector<AuditEntry>>;

struct LocalSnapshot;

class ChangeSetService
{
public:
  void SetDecompilerAvailable(bool available) noexcept { decompiler_available_ = available; }
  PreviewOutcome Preview(const std::vector<ChangeOperation> &operations) const;
  ApplyOutcome Apply(std::string_view preview_id, const std::vector<ChangeOperation> &operations, std::string_view session_id);
  ApplyOutcome Rollback(std::string_view change_id, std::string_view session_id);
  AuditOutcome Audit(std::uint32_t offset, std::uint32_t limit) const;
  void Reset() noexcept;

private:
  void RecordAudit(std::string_view change_id, std::string_view session_id, std::string_view operation,
      std::uint64_t address, std::string_view before, std::string_view after, bool success);
  struct AppliedChange
  {
    std::string id;
    std::vector<ChangeOperation> operations;
    std::vector<ChangeOperation> inverse;
    std::vector<std::shared_ptr<LocalSnapshot>> local_snapshots;
    bool rollbackable;
    bool rolled_back = false;
  };
  std::vector<AppliedChange> changes_;
  std::vector<AuditEntry> audit_;
  std::uint64_t next_change_sequence_ = 1;
  bool decompiler_available_ = false;
};

nlohmann::json ToJson(const ChangePreview &result);
nlohmann::json ToJson(const ChangeApplyResult &result);
nlohmann::json ToJson(const std::vector<AuditEntry> &result);

} // namespace ida_agent::services
