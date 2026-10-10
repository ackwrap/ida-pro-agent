#include "changeset_service.hpp"
#include "changeset_annotations.hpp"
#include "changeset_integer.hpp"
#include "changeset_operands.hpp"
#include "changeset_types.hpp"

#include "address.hpp"

#include <bytes.hpp>
#include <funcs.hpp>
#include <frame.hpp>
#include <hexrays.hpp>
#include <kernwin.hpp>
#include <name.hpp>
#include <segment.hpp>
#include <typeinf.hpp>
#include <ua.hpp>
#include <xref.hpp>

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <sstream>

#include "changeset_internal.hpp"

namespace ida_agent::services
{
using namespace changeset_detail;
namespace
{
std::string Identifier(
    const std::vector<ChangePreviewItem> &items,
    const std::vector<ChangeOperation> &operations)
{
  std::size_t hash = 1469598103934665603ULL;
  const auto mix = [&hash](std::string_view value)
  {
    for ( unsigned char byte : value ) { hash ^= byte; hash *= 1099511628211ULL; }
    hash ^= 0xFF; hash *= 1099511628211ULL;
  };
  for ( std::size_t index = 0; index < items.size(); ++index )
  {
    const auto &item = items[index];
    const auto &operation = operations[index];
    mix(Kind(operation.kind));
    mix(std::to_string(operation.address));
    mix(operation.value);
    mix(operation.expected.value_or("<none>"));
    mix(operation.subject.value_or("<none>"));
    mix(operation.offset ? std::to_string(*operation.offset) : "<none>");
    mix(operation.size ? std::to_string(*operation.size) : "<none>");
    mix(operation.repeatable ? "repeatable" : "nonrepeatable");
    mix(item.before);
    mix(item.after);
    mix(std::to_string(item.index));
  }
  std::ostringstream output; output << std::hex << hash; return output.str();
}

bool AppliedAsPreviewed(const ChangeOperation &operation, const std::string &after)
{
  if ( operation.kind == ChangeKind::XrefCodeAdd || operation.kind == ChangeKind::XrefDataAdd
    || operation.kind == ChangeKind::XrefCodeDelete || operation.kind == ChangeKind::XrefDataDelete )
  {
    const auto current = Current(operation);
    const bool add = operation.kind == ChangeKind::XrefCodeAdd || operation.kind == ChangeKind::XrefDataAdd;
    return current && *current == (add ? "user" : "absent");
  }
  if ( operation.kind == ChangeKind::FunctionChunkAdd || operation.kind == ChangeKind::FunctionChunkDelete )
  {
    const auto current = Current(operation);
    const bool add = operation.kind == ChangeKind::FunctionChunkAdd;
    return current && (add ? *current == "owned" || *current == "owned_shared"
                           : *current == "absent" || *current == "absent_shared");
  }
  const bool exact = operation.kind == ChangeKind::Bookmark || operation.kind == ChangeKind::PseudocodeComment
      || operation.kind == ChangeKind::PatchBytes || operation.kind == ChangeKind::PatchInteger
      || operation.kind == ChangeKind::OperandHex || operation.kind == ChangeKind::OperandDec
      || operation.kind == ChangeKind::OperandChar || operation.kind == ChangeKind::OperandBinary
      || operation.kind == ChangeKind::OperandOctal || operation.kind == ChangeKind::OperandOffset
      || operation.kind == ChangeKind::OperandStructOffset || operation.kind == ChangeKind::OperandStackVariable
      || operation.kind == ChangeKind::EnumUpsert || operation.kind == ChangeKind::SegmentRename
      || operation.kind == ChangeKind::SegmentPermissions || operation.kind == ChangeKind::FunctionFlags
      || operation.kind == ChangeKind::XrefCodeAdd || operation.kind == ChangeKind::XrefCodeDelete
      || operation.kind == ChangeKind::XrefDataAdd || operation.kind == ChangeKind::XrefDataDelete
      || operation.kind == ChangeKind::FunctionEnd;
  if ( !exact ) return true;
  const auto current = Current(operation);
  return current && *current == after;
}

bool ApplyOne(const ChangeOperation &operation, const std::string &after)
{
  const ea_t ea = static_cast<ea_t>(operation.address);
  switch ( operation.kind )
  {
    case ChangeKind::Rename: return set_name(ea, after.c_str(), SN_CHECK | SN_NOWARN);
    case ChangeKind::CommentSet:
    case ChangeKind::CommentAppend: return set_cmt(ea, after.c_str(), operation.repeatable);
    case ChangeKind::PseudocodeComment: return detail::ApplyPseudocodeComment(operation.address, after);
    case ChangeKind::Bookmark: return detail::ApplyBookmark(operation.address, after);
    case ChangeKind::TypeApply:
    {
      tinfo_t type; if ( !type.parse(after.c_str(), nullptr, PT_SIL) ) return false;
      return apply_tinfo(ea, type, TINFO_DEFINITE);
    }
    case ChangeKind::PatchBytes:
    case ChangeKind::PatchInteger:
    {
      const auto bytes = DecodeHex(after); if ( !bytes ) return false;
      patch_bytes(ea, bytes->data(), bytes->size()); return true;
    }
    case ChangeKind::DefineFunction:
    {
      ea_t end = BADADDR;
      if ( !after.empty() )
      {
        try { end = static_cast<ea_t>(rpc::ParseAddress(after)); }
        catch ( const std::invalid_argument & ) { return false; }
      }
      return add_func(ea, end);
    }
    case ChangeKind::DefineCode:
      return create_insn(ea) > 0;
    case ChangeKind::Undefine:
    {
      std::uint64_t size = 0;
      try { size = std::stoull(after); } catch ( const std::exception & ) { return false; }
      return size > 0 && size <= 65536 && del_items(ea, DELIT_SIMPLE, static_cast<asize_t>(size));
    }
    case ChangeKind::ForceRecompile:
      return mark_cfunc_dirty(ea, false);
    case ChangeKind::InvalidateAllDecompilations:
      if ( !init_hexrays_plugin(0) ) return false;
      clear_cached_cfuncs(); return true;
    case ChangeKind::MakeData:
    {
      tinfo_t type;
      if ( !type.parse(after.c_str(), nullptr, PT_SIL) ) return false;
      size_t size = 0;
      flags64_t flags = 0;
      opinfo_t metadata;
      if ( !get_idainfo_by_type(&size, &flags, &metadata, type) || size == 0 || size > 65536 ) return false;
      if ( !del_items(ea, DELIT_SIMPLE, size) || !create_data(ea, flags, size, BADNODE) ) return false;
      return apply_tinfo(ea, type, TINFO_DEFINITE);
    }
    case ChangeKind::OperandHex:
    case ChangeKind::OperandDec:
    case ChangeKind::OperandChar:
    case ChangeKind::OperandBinary:
    case ChangeKind::OperandOctal:
    case ChangeKind::OperandOffset:
    case ChangeKind::OperandStructOffset:
    case ChangeKind::OperandStackVariable:
      return detail::ApplyOperand(operation);
    case ChangeKind::DeclareType:
    case ChangeKind::EnumUpsert:
      return detail::ApplyTypeDeclaration(operation.kind, after);
    case ChangeKind::StackDeclare:
    {
      if ( !operation.offset || *operation.offset < 0 ) return false;
      tinfo_t type;
      qstring name;
      if ( !parse_decl(&type, &name, get_idati(), after.c_str(), PT_SIL | PT_VAR) || type.empty() ) return false;
      return add_frame_member_ea(ea, name.empty() ? nullptr : name.c_str(), static_cast<uval_t>(*operation.offset), type);
    }
    case ChangeKind::StackDelete:
      return operation.offset && operation.size && *operation.offset >= 0 && *operation.size > 0
          && delete_frame_members_ea(ea, static_cast<uval_t>(*operation.offset), static_cast<uval_t>(*operation.offset) + *operation.size);
    case ChangeKind::LocalRename:
      return false;
    case ChangeKind::LocalType:
    {
      return false;
    }
    case ChangeKind::SegmentRename:
      return !after.empty() && after.size() <= 255 && set_segment_name(ea, after.c_str()) != 0;
    case ChangeKind::SegmentPermissions:
    {
      const auto permissions = SegmentPermissions(after);
      segment_info_t segment;
      if ( !permissions || !get_segment_info(&segment, ea) ) return false;
      segment.set_perm(static_cast<uchar>(*permissions));
      return set_segment_info(&segment);
    }
    case ChangeKind::FunctionFlags:
    {
      const auto managed = FunctionFlags(after);
      func_t *function = get_func(ea);
      if ( !managed || function == nullptr ) return false;
      return set_func_flags(function->start_ea, (function->flags & ~ManagedFunctionFlags) | *managed);
    }
    case ChangeKind::FunctionEnd:
    {
      ea_t target;
      try { target = static_cast<ea_t>(rpc::ParseAddress(after)); }
      catch ( const std::invalid_argument & ) { return false; }
      return target != BADADDR && set_func_end(ea, target);
    }
    case ChangeKind::FunctionChunkAdd:
    case ChangeKind::FunctionChunkDelete:
    {
      const auto range = FunctionChunkRange(operation);
      if ( !range ) return false;
      const auto state = FunctionChunkState(ea, range->first, range->second);
      if ( !state ) return false;
      const bool add = operation.kind == ChangeKind::FunctionChunkAdd;
      const std::string desired = add
          ? (*state == "absent_shared" ? "owned_shared" : "owned")
          : (*state == "owned_shared" ? "absent_shared" : "absent");
      if ( add && (*state == "absent" || *state == "absent_shared") )
        static_cast<void>(append_func_tail_ea(ea, range->first, range->second));
      else if ( !add && (*state == "owned" || *state == "owned_shared") )
        static_cast<void>(remove_func_tail_ea(ea, range->first));
      return FunctionChunkState(ea, range->first, range->second) == desired;
    }
    case ChangeKind::XrefCodeAdd:
    case ChangeKind::XrefCodeDelete:
    case ChangeKind::XrefDataAdd:
    case ChangeKind::XrefDataDelete:
    {
      if ( !operation.subject ) return false;
      ea_t target;
      try { target = static_cast<ea_t>(rpc::ParseAddress(operation.value)); }
      catch ( const std::invalid_argument & ) { return false; }
      const bool code = operation.kind == ChangeKind::XrefCodeAdd || operation.kind == ChangeKind::XrefCodeDelete;
      const bool add = operation.kind == ChangeKind::XrefCodeAdd || operation.kind == ChangeKind::XrefDataAdd;
      const auto type = XrefType(*operation.subject, code);
      if ( !type || target == BADADDR || !is_mapped(target) ) return false;
      const std::string state = XrefState(ea, target, *type, code);
      if ( add && state == "absent" )
      {
        if ( code ) static_cast<void>(add_cref(ea, target, static_cast<cref_t>(*type | XREF_USER)));
        else static_cast<void>(add_dref(ea, target, static_cast<dref_t>(*type | XREF_USER)));
      }
      else if ( !add && state == "user" )
      {
        if ( code ) static_cast<void>(del_cref(ea, target, false));
        else del_dref(ea, target);
      }
      return XrefState(ea, target, *type, code) == (add ? "user" : "absent");
    }
  }
  return false;
}

std::optional<ChangeOperation> Inverse(
    const ChangeOperation &operation,
    const ChangePreviewItem &preview)
{
  ChangeOperation inverse = operation;
  inverse.value = preview.before;
  inverse.expected = preview.after;
  if ( operation.kind == ChangeKind::CommentAppend )
    inverse.kind = ChangeKind::CommentSet;
  if ( operation.kind == ChangeKind::PatchInteger )
    inverse.kind = ChangeKind::PatchBytes;
  if ( operation.kind == ChangeKind::LocalRename )
    inverse.subject = preview.after;
  if ( operation.kind == ChangeKind::TypeApply && preview.before.empty() )
    return std::nullopt;
  if ( operation.kind == ChangeKind::EnumUpsert )
    return preview.before.empty() ? std::nullopt : std::optional<ChangeOperation>(inverse);
  if ( operation.kind == ChangeKind::XrefCodeAdd || operation.kind == ChangeKind::XrefCodeDelete
    || operation.kind == ChangeKind::XrefDataAdd || operation.kind == ChangeKind::XrefDataDelete )
  {
    inverse.kind = operation.kind == ChangeKind::XrefCodeAdd ? ChangeKind::XrefCodeDelete
        : operation.kind == ChangeKind::XrefCodeDelete ? ChangeKind::XrefCodeAdd
        : operation.kind == ChangeKind::XrefDataAdd ? ChangeKind::XrefDataDelete
        : ChangeKind::XrefDataAdd;
    inverse.value = operation.value;
    return inverse;
  }
  if ( operation.kind == ChangeKind::FunctionChunkAdd || operation.kind == ChangeKind::FunctionChunkDelete )
  {
    inverse.kind = operation.kind == ChangeKind::FunctionChunkAdd
        ? ChangeKind::FunctionChunkDelete : ChangeKind::FunctionChunkAdd;
    inverse.value = operation.value;
    return inverse;
  }
  switch ( operation.kind )
  {
    case ChangeKind::Rename:
    case ChangeKind::CommentSet:
    case ChangeKind::CommentAppend:
    case ChangeKind::PseudocodeComment:
    case ChangeKind::TypeApply:
    case ChangeKind::PatchBytes:
    case ChangeKind::PatchInteger:
    case ChangeKind::LocalRename:
    case ChangeKind::LocalType:
    case ChangeKind::SegmentRename:
    case ChangeKind::SegmentPermissions:
    case ChangeKind::FunctionFlags:
    case ChangeKind::FunctionEnd:
      return inverse;
    case ChangeKind::XrefCodeAdd:
    case ChangeKind::XrefCodeDelete:
    case ChangeKind::XrefDataAdd:
    case ChangeKind::XrefDataDelete:
    case ChangeKind::FunctionChunkAdd:
    case ChangeKind::FunctionChunkDelete:
      return std::nullopt;
    case ChangeKind::Bookmark:
    case ChangeKind::DefineFunction:
    case ChangeKind::DefineCode:
    case ChangeKind::Undefine:
    case ChangeKind::ForceRecompile:
    case ChangeKind::MakeData:
    case ChangeKind::OperandHex:
    case ChangeKind::OperandDec:
    case ChangeKind::OperandChar:
    case ChangeKind::OperandBinary:
    case ChangeKind::OperandOctal:
    case ChangeKind::OperandOffset:
    case ChangeKind::OperandStructOffset:
    case ChangeKind::OperandStackVariable:
    case ChangeKind::DeclareType:
    case ChangeKind::EnumUpsert:
    case ChangeKind::InvalidateAllDecompilations:
    case ChangeKind::StackDeclare:
    case ChangeKind::StackDelete:
      return std::nullopt;
  }
  return std::nullopt;
}

bool MatchesExpected(const ChangeOperation &operation)
{
  if ( !operation.expected ) return true;
  const auto current = Current(operation);
  return current && *current == *operation.expected;
}

std::optional<ChangeOperation> Redo(const ChangeOperation &inverse)
{
  if ( !inverse.expected ) return std::nullopt;
  ChangeOperation redo = inverse;
  if ( inverse.kind == ChangeKind::XrefCodeAdd || inverse.kind == ChangeKind::XrefCodeDelete
    || inverse.kind == ChangeKind::XrefDataAdd || inverse.kind == ChangeKind::XrefDataDelete )
  {
    redo.kind = inverse.kind == ChangeKind::XrefCodeAdd ? ChangeKind::XrefCodeDelete
        : inverse.kind == ChangeKind::XrefCodeDelete ? ChangeKind::XrefCodeAdd
        : inverse.kind == ChangeKind::XrefDataAdd ? ChangeKind::XrefDataDelete
        : ChangeKind::XrefDataAdd;
    const bool add = redo.kind == ChangeKind::XrefCodeAdd || redo.kind == ChangeKind::XrefDataAdd;
    redo.expected = add ? "absent" : "user";
    return redo;
  }
  if ( inverse.kind == ChangeKind::FunctionChunkAdd || inverse.kind == ChangeKind::FunctionChunkDelete )
  {
    const std::string original_after = *inverse.expected;
    redo.kind = inverse.kind == ChangeKind::FunctionChunkAdd
        ? ChangeKind::FunctionChunkDelete : ChangeKind::FunctionChunkAdd;
    redo.expected = redo.kind == ChangeKind::FunctionChunkAdd
        ? (original_after == "owned_shared" ? "absent_shared" : "absent")
        : (original_after == "absent_shared" ? "owned_shared" : "owned");
    return redo;
  }
  redo.value = *inverse.expected;
  redo.expected = inverse.value;
  if ( redo.kind == ChangeKind::LocalRename ) redo.subject = inverse.value;
  return redo;
}

std::string RollbackKind(ChangeKind kind)
{
  return std::string("rollback.") + Kind(kind);
}

std::uint64_t Now()
{
  return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
}
}

PreviewOutcome ChangeSetService::Preview(const std::vector<ChangeOperation> &operations) const
{
  if ( operations.empty() || operations.size() > 100 ) return {ChangeStatus::InvalidArgument, std::nullopt};
  if ( !decompiler_available_ && std::any_of(operations.begin(), operations.end(), [](const ChangeOperation &operation) { return LocalKind(operation.kind); }) )
    return {ChangeStatus::CapabilityUnavailable, std::nullopt};
  if ( operations.size() != 1 && std::any_of(operations.begin(), operations.end(), [](const ChangeOperation &operation)
      { return operation.kind == ChangeKind::InvalidateAllDecompilations; }) ) return {ChangeStatus::InvalidArgument, std::nullopt};
  ChangePreview result; result.applicable = true;
  std::size_t output_bytes = 0;
  for ( std::size_t index = 0; index < operations.size(); ++index )
  {
    if ( LocalKind(operations[index].kind) )
    {
      if ( !operations[index].subject ) return {ChangeStatus::InvalidArgument, std::nullopt};
      const auto local = CaptureLocal(operations[index].address, std::string_view(*operations[index].subject));
      if ( !local ) return {ChangeStatus::InvalidAddress, std::nullopt};
      const bool rollbackable = local->saved_exists && (operations[index].kind == ChangeKind::LocalRename
          ? !local->saved.name.empty() : !local->saved.type.empty());
      if ( !rollbackable ) return {ChangeStatus::CapabilityUnavailable, std::nullopt};
    }
    const auto type_status = detail::ValidateTypeChange(operations[index].kind, operations[index].value);
    if ( type_status != ChangeStatus::Success ) return {type_status, std::nullopt};
    const auto before = Current(operations[index]);
    if ( !before )
      return {operations[index].kind == ChangeKind::DeclareType || operations[index].kind == ChangeKind::EnumUpsert
          ? ChangeStatus::InvalidArgument : ChangeStatus::InvalidAddress, std::nullopt};
    const auto after = After(operations[index], *before); if ( !after ) return {ChangeStatus::InvalidArgument, std::nullopt};
    output_bytes += 6 * (before->size() + after->size()) + 128;
    if ( output_bytes > 524288 ) return {ChangeStatus::OutputLimit, std::nullopt};
    std::optional<std::string> expected = operations[index].expected;
    if ( (operations[index].kind == ChangeKind::PatchBytes
       || operations[index].kind == ChangeKind::PatchInteger) && expected )
    {
      const auto bytes = DecodeHex(*expected);
      if ( !bytes ) return {ChangeStatus::InvalidArgument, std::nullopt};
      expected = Hex(*bytes);
    }
    const bool conflict = expected && *expected != *before;
    result.items.push_back({static_cast<std::uint32_t>(index), *before, *after, conflict});
    if ( !Inverse(operations[index], result.items.back()) )
      return {ChangeStatus::InvalidArgument, std::nullopt};
    result.applicable = result.applicable && !conflict;
  }
  if ( operations.size() > 1 )
  {
    for ( std::size_t index = 0; index < operations.size(); ++index )
    {
      for ( std::size_t prior = 0; prior < index; ++prior )
        if ( operations[prior].address == operations[index].address ) return {ChangeStatus::InvalidArgument, std::nullopt};
    }
  }
  result.preview_id = Identifier(result.items, operations);
  return {ChangeStatus::Success, std::move(result)};
}

ApplyOutcome ChangeSetService::Apply(std::string_view preview_id, const std::vector<ChangeOperation> &operations, std::string_view session_id)
{
  changes_.erase(std::remove_if(changes_.begin(), changes_.end(), [](const AppliedChange &change) { return change.rolled_back; }), changes_.end());
  while ( changes_.size() >= 256 )
  {
    const auto disposable = std::find_if(changes_.begin(), changes_.end(), [](const AppliedChange &change) { return !change.rollbackable; });
    if ( disposable == changes_.end() ) break;
    changes_.erase(disposable);
  }
  if ( changes_.size() >= 256 ) return {ChangeStatus::OutputLimit, std::nullopt};
  const auto preview = Preview(operations);
  if ( preview.status != ChangeStatus::Success || !preview.result ) return {preview.status, std::nullopt};
  if ( !preview.result->applicable || preview.result->preview_id != preview_id ) return {ChangeStatus::Conflict, std::nullopt};
  ChangeApplyResult result{preview.result->preview_id + "-" + std::to_string(Now()) + "-" + std::to_string(next_change_sequence_++)};
  std::vector<ChangeOperation> inverse;
  std::vector<std::shared_ptr<LocalSnapshot>> local_snapshots(operations.size());
  for ( std::size_t index = 0; index < operations.size(); ++index )
  {
    const auto undo = Inverse(operations[index], preview.result->items[index]);
    if ( !undo ) return {ChangeStatus::InvalidArgument, std::nullopt};
    inverse.push_back(*undo);
  }
  for ( std::size_t index = 0; index < operations.size(); ++index )
  {
    const auto &item = preview.result->items[index];
    bool changed = false;
    if ( LocalKind(operations[index].kind) )
    {
      LocalSnapshot snapshot;
      changed = ApplyLocal(operations[index], item.after, &snapshot);
      if ( changed ) local_snapshots[index] = std::make_shared<LocalSnapshot>(std::move(snapshot));
    }
    else
    {
      changed = ApplyOne(operations[index], item.after) && AppliedAsPreviewed(operations[index], item.after);
    }
    if ( !changed )
    {
      result.items.push_back({static_cast<std::uint32_t>(index), false, "IDA rejected the operation"});
      RecordAudit(result.change_id, session_id, Kind(operations[index].kind), operations[index].address, item.before, item.after, false);
      std::vector<ChangeOperation> remaining_operations;
      std::vector<ChangeOperation> remaining_inverse;
      std::vector<std::shared_ptr<LocalSnapshot>> remaining_snapshots;
      for ( std::size_t attempted = index + 1; attempted > 0; --attempted )
      {
        const std::size_t original_index = attempted - 1;
        auto undo = inverse[original_index];
        const auto rollback_before = Current(undo);
        const bool local = local_snapshots[original_index] != nullptr;
        const bool already_reverted = !local && rollback_before && *rollback_before == undo.value;
        const bool may_revert = original_index == index || local || MatchesExpected(undo);
        bool reverted = already_reverted || (may_revert && (local
            ? RestoreLocal(local_snapshots[original_index]->after, local_snapshots[original_index]->before, operations[original_index].kind)
            : ApplyOne(undo, undo.value) && AppliedAsPreviewed(undo, undo.value)));
        std::optional<std::string> residual;
        if ( !reverted && !local )
        {
          residual = Current(undo);
          reverted = residual && *residual == undo.value;
          if ( residual && !reverted ) undo.expected = *residual;
        }
        RecordAudit(result.change_id, session_id, RollbackKind(operations[original_index].kind), operations[original_index].address,
            rollback_before.value_or(preview.result->items[original_index].after),
            preview.result->items[original_index].before, reverted);
        if ( reverted )
        {
          result.items[original_index].applied = false;
          result.items[original_index].error = original_index == index
              ? (already_reverted
                    ? "operation failed; no changes remain"
                    : "operation failed; partial changes were rolled back")
              : "rolled back after a later operation failed";
        }
        else
        {
          remaining_operations.push_back(operations[original_index]);
          remaining_inverse.push_back(undo);
          remaining_snapshots.push_back(local_snapshots[original_index]);
          result.items[original_index].error = original_index == index
              ? "operation failed and automatic rollback failed; changeset.rollback can retry"
              : "automatic rollback failed; changeset.rollback can retry";
        }
      }
      std::reverse(remaining_operations.begin(), remaining_operations.end());
      std::reverse(remaining_inverse.begin(), remaining_inverse.end());
      std::reverse(remaining_snapshots.begin(), remaining_snapshots.end());
      if ( !remaining_inverse.empty() )
        changes_.push_back({result.change_id, std::move(remaining_operations), std::move(remaining_inverse), std::move(remaining_snapshots), true, false});
      return {ChangeStatus::Failed, std::move(result)};
    }
    result.items.push_back({static_cast<std::uint32_t>(index), true, std::nullopt});
    RecordAudit(result.change_id, session_id, Kind(operations[index].kind), operations[index].address, item.before, item.after, true);
  }
  result.applied = true; changes_.push_back({result.change_id, operations, std::move(inverse), std::move(local_snapshots), true, false});
  return {ChangeStatus::Success, std::move(result)};
}

ApplyOutcome ChangeSetService::Rollback(std::string_view change_id, std::string_view session_id)
{
  for ( auto &change : changes_ )
  {
    if ( change.id != change_id ) continue;
    if ( change.rolled_back || !change.rollbackable ) return {ChangeStatus::Conflict, std::nullopt};
    ChangeApplyResult result{change.id};
    for ( std::size_t index = change.inverse.size(); index > 0; --index )
    {
      const auto &snapshot = change.local_snapshots[index - 1];
      const bool matches = snapshot
          ? ([&snapshot]() { const auto current = CaptureLocal(snapshot->after.entry, std::nullopt, &snapshot->after.locator); return current && SameLocalState(*current, snapshot->after); })()
          : MatchesExpected(change.inverse[index - 1]);
      if ( matches ) continue;
      RecordAudit(change.id, session_id, RollbackKind(change.operations[index - 1].kind), change.operations[index - 1].address,
          change.inverse[index - 1].expected.value_or("unknown"), change.inverse[index - 1].value, false);
      return {ChangeStatus::Conflict, std::nullopt};
    }
    std::vector<bool> active(change.inverse.size(), true);
    for ( std::size_t index = 0; index < change.inverse.size(); ++index )
    {
      const std::size_t original_index = change.inverse.size() - index - 1;
      const auto operation = change.inverse[original_index];
      const auto rollback_before = Current(operation);
      bool applied = change.local_snapshots[original_index]
          ? RestoreLocal(change.local_snapshots[original_index]->after, change.local_snapshots[original_index]->before, change.operations[original_index].kind)
          : ApplyOne(operation, operation.value) && AppliedAsPreviewed(operation, operation.value);
      std::optional<std::string> residual;
      if ( !applied && !change.local_snapshots[original_index] )
      {
        residual = Current(operation);
        applied = residual && *residual == operation.value;
      }
      result.items.push_back({static_cast<std::uint32_t>(original_index), applied, applied ? std::nullopt : std::optional<std::string>("rollback failed")});
      RecordAudit(change.id, session_id, RollbackKind(change.operations[original_index].kind), change.operations[original_index].address,
          rollback_before.value_or(operation.expected.value_or("unknown")), operation.value, applied);
      if ( applied ) { active[original_index] = false; continue; }
      if ( residual ) change.inverse[original_index].expected = *residual;
      for ( std::size_t restore = original_index + 1; restore < change.inverse.size(); ++restore )
      {
        if ( active[restore] ) continue;
        const auto redo = Redo(change.inverse[restore]);
        const bool restored = change.local_snapshots[restore]
            ? RestoreLocal(change.local_snapshots[restore]->before, change.local_snapshots[restore]->after, change.operations[restore].kind)
            : redo && MatchesExpected(*redo) && ApplyOne(*redo, redo->value) && AppliedAsPreviewed(*redo, redo->value);
        RecordAudit(change.id, session_id, "rollback.compensate", change.operations[restore].address,
            change.inverse[restore].value, change.inverse[restore].expected.value_or("unknown"), restored);
        if ( restored ) active[restore] = true;
      }
      std::vector<ChangeOperation> remaining_operations;
      std::vector<ChangeOperation> remaining_inverse;
      std::vector<std::shared_ptr<LocalSnapshot>> remaining_snapshots;
      for ( std::size_t retain = 0; retain < active.size(); ++retain )
      {
        if ( !active[retain] ) continue;
        remaining_operations.push_back(change.operations[retain]);
        remaining_inverse.push_back(change.inverse[retain]);
        remaining_snapshots.push_back(change.local_snapshots[retain]);
      }
      change.operations = std::move(remaining_operations);
      change.inverse = std::move(remaining_inverse);
      change.local_snapshots = std::move(remaining_snapshots);
      if ( change.inverse.empty() ) change.rolled_back = true;
      return {ChangeStatus::Failed, std::move(result)};
    }
    change.rolled_back = true; result.applied = true; return {ChangeStatus::Success, std::move(result)};
  }
  return {ChangeStatus::NotFound, std::nullopt};
}

void ChangeSetService::Reset() noexcept
{
  changes_.clear();
  audit_.clear();
  next_change_sequence_ = 1;
}

} // namespace ida_agent::services
