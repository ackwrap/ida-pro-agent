#include "workflow_handlers.hpp"

#include "ida_executor.hpp"
#include "rpc/address.hpp"
#include "services/changeset_service.hpp"
#include "services/database_service.hpp"
#include "services/decompiler_service.hpp"

#include <chrono>
#include <limits>
#include <optional>
#include <string>

namespace ida_agent::bridge
{
namespace
{

Dispatcher::MethodResult Error(
    rpc::ErrorCode code,
    const char *message,
    bool retryable = false)
{
  return rpc::RpcError{code, message, retryable};
}

Dispatcher::MethodResult RecoveryError(
    const char *message,
    std::string recovery_change_id)
{
  return rpc::RpcError{
      rpc::ErrorCode::InternalError,
      message,
      false,
      std::move(recovery_change_id),
  };
}

bool Fields(
    const nlohmann::json &params,
    std::initializer_list<const char *> allowed)
{
  for ( auto field = params.begin(); field != params.end(); ++field )
  {
    bool found = false;
    for ( const char *name : allowed )
      found = found || field.key() == name;
    if ( !found )
      return false;
  }
  return true;
}

std::optional<services::ChangeKind> ChangeKind(std::string_view name)
{
  using services::ChangeKind;
  if ( name == "rename" ) return ChangeKind::Rename;
  if ( name == "comment.set" ) return ChangeKind::CommentSet;
  if ( name == "comment.append" ) return ChangeKind::CommentAppend;
  if ( name == "comment.pseudocode" ) return ChangeKind::PseudocodeComment;
  if ( name == "bookmark.add" ) return ChangeKind::Bookmark;
  if ( name == "type.apply" ) return ChangeKind::TypeApply;
  if ( name == "patch.bytes" ) return ChangeKind::PatchBytes;
  if ( name == "patch.integer" ) return ChangeKind::PatchInteger;
  if ( name == "define.function" ) return ChangeKind::DefineFunction;
  if ( name == "define.code" ) return ChangeKind::DefineCode;
  if ( name == "undefine" ) return ChangeKind::Undefine;
  if ( name == "decompiler.invalidate" ) return ChangeKind::ForceRecompile;
  if ( name == "decompiler.invalidate_all" ) return ChangeKind::InvalidateAllDecompilations;
  if ( name == "define.data" ) return ChangeKind::MakeData;
  if ( name == "operand.hex" ) return ChangeKind::OperandHex;
  if ( name == "operand.decimal" ) return ChangeKind::OperandDec;
  if ( name == "operand.character" ) return ChangeKind::OperandChar;
  if ( name == "operand.binary" ) return ChangeKind::OperandBinary;
  if ( name == "operand.octal" ) return ChangeKind::OperandOctal;
  if ( name == "operand.offset" ) return ChangeKind::OperandOffset;
  if ( name == "operand.struct_offset" ) return ChangeKind::OperandStructOffset;
  if ( name == "operand.stack_variable" ) return ChangeKind::OperandStackVariable;
  if ( name == "type.declare" ) return ChangeKind::DeclareType;
  if ( name == "enum.upsert" ) return ChangeKind::EnumUpsert;
  if ( name == "stack.declare" ) return ChangeKind::StackDeclare;
  if ( name == "stack.delete" ) return ChangeKind::StackDelete;
  if ( name == "local.rename" ) return ChangeKind::LocalRename;
  if ( name == "local.type" ) return ChangeKind::LocalType;
  if ( name == "segment.rename" ) return ChangeKind::SegmentRename;
  if ( name == "segment.permissions" ) return ChangeKind::SegmentPermissions;
  if ( name == "xref.code.add" ) return ChangeKind::XrefCodeAdd;
  if ( name == "xref.code.delete" ) return ChangeKind::XrefCodeDelete;
  if ( name == "xref.data.add" ) return ChangeKind::XrefDataAdd;
  if ( name == "xref.data.delete" ) return ChangeKind::XrefDataDelete;
  if ( name == "function.flags" ) return ChangeKind::FunctionFlags;
  if ( name == "function.end" ) return ChangeKind::FunctionEnd;
  if ( name == "function.chunk.add" ) return ChangeKind::FunctionChunkAdd;
  if ( name == "function.chunk.delete" ) return ChangeKind::FunctionChunkDelete;
  return std::nullopt;
}

std::optional<services::ChangeOperation> Operation(const nlohmann::json &item)
{
  if ( !item.is_object()
    || !Fields(item, {
        "kind", "address", "value", "expected", "repeatable",
        "offset", "size", "subject"})
    || !item.contains("kind") || !item["kind"].is_string()
    || !item.contains("value") || !item["value"].is_string()
    || item["value"].get_ref<const std::string &>().size() > 65536 )
  {
    return std::nullopt;
  }
  const auto kind = ChangeKind(item["kind"].get<std::string>());
  if ( !kind )
    return std::nullopt;

  std::uint64_t address = 0;
  const bool addressless = *kind == services::ChangeKind::DeclareType || *kind == services::ChangeKind::EnumUpsert
      || *kind == services::ChangeKind::InvalidateAllDecompilations;
  if ( !addressless )
  {
    if ( !item.contains("address") || !item["address"].is_string() )
      return std::nullopt;
    try
    {
      address = rpc::ParseAddress(item["address"].get<std::string>());
    }
    catch ( const std::invalid_argument & )
    {
      return std::nullopt;
    }
  }
  else if ( item.contains("address") )
  {
    return std::nullopt;
  }

  std::optional<std::string> expected;
  if ( item.contains("expected") )
  {
    if ( !item["expected"].is_string() )
      return std::nullopt;
    expected = item["expected"].get<std::string>();
    if ( expected->size() > 65536 )
      return std::nullopt;
  }
  bool repeatable = false;
  if ( item.contains("repeatable") )
  {
    if ( !item["repeatable"].is_boolean() )
      return std::nullopt;
    repeatable = item["repeatable"].get<bool>();
  }
  std::optional<std::int64_t> offset;
  if ( item.contains("offset") )
  {
    if ( item["offset"].is_number_unsigned() )
    {
      const auto value = item["offset"].get<std::uint64_t>();
      if ( value > static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()) ) return std::nullopt;
      offset = static_cast<std::int64_t>(value);
    }
    else if ( item["offset"].is_number_integer() ) offset = item["offset"].get<std::int64_t>();
    else return std::nullopt;
  }
  std::optional<std::uint32_t> size;
  if ( item.contains("size") )
  {
    if ( !item["size"].is_number_unsigned() )
      return std::nullopt;
    const std::uint64_t parsed = item["size"].get<std::uint64_t>();
    if ( parsed > (std::numeric_limits<std::uint32_t>::max)() )
      return std::nullopt;
    size = static_cast<std::uint32_t>(parsed);
  }
  std::optional<std::string> subject;
  if ( item.contains("subject") )
  {
    if ( !item["subject"].is_string() )
      return std::nullopt;
    subject = item["subject"].get<std::string>();
    if ( subject->empty() || subject->size() > 1024 )
      return std::nullopt;
  }
  if ( *kind == services::ChangeKind::InvalidateAllDecompilations
    && !item["value"].get_ref<const std::string &>().empty() ) return std::nullopt;
  const bool extra_fields = repeatable || offset.has_value() || size.has_value();
  switch ( *kind )
  {
    case services::ChangeKind::XrefCodeAdd:
    case services::ChangeKind::XrefCodeDelete:
    case services::ChangeKind::XrefDataAdd:
    case services::ChangeKind::XrefDataDelete:
    case services::ChangeKind::FunctionChunkAdd:
    case services::ChangeKind::FunctionChunkDelete:
      if ( extra_fields || !subject ) return std::nullopt;
      break;
    case services::ChangeKind::SegmentRename:
    case services::ChangeKind::SegmentPermissions:
    case services::ChangeKind::FunctionFlags:
    case services::ChangeKind::FunctionEnd:
      if ( extra_fields || subject ) return std::nullopt;
      break;
    default:
      break;
  }
  return services::ChangeOperation{
      *kind,
      address,
      item["value"].get<std::string>(),
      std::move(expected),
      repeatable,
      offset,
      size,
      std::move(subject),
  };
}

Dispatcher::MethodResult ChangeFailure(services::ChangeStatus status)
{
  switch ( status )
  {
    case services::ChangeStatus::InvalidAddress:
      return Error(rpc::ErrorCode::InvalidAddress, "diff action address is invalid");
    case services::ChangeStatus::InvalidArgument:
      return Error(rpc::ErrorCode::InvalidArgument, "diff action is invalid");
    case services::ChangeStatus::Conflict:
      return Error(rpc::ErrorCode::Conflict, "diff action conflicts with current state");
    case services::ChangeStatus::NotFound:
      return Error(rpc::ErrorCode::NotFound, "diff action target was not found");
    case services::ChangeStatus::CapabilityUnavailable:
      return Error(rpc::ErrorCode::CapabilityUnavailable, "required diff capability is unavailable");
    case services::ChangeStatus::Failed:
      return Error(rpc::ErrorCode::InternalError, "IDA rejected the diff action");
    case services::ChangeStatus::OutputLimit:
      return Error(rpc::ErrorCode::OutputLimit, "diff action output limit exceeded");
    case services::ChangeStatus::Success:
      break;
  }
  return Error(rpc::ErrorCode::InternalError, "diff action result is unavailable");
}

Dispatcher::MethodResult DecompileFailure(
    services::DecompileStatus status,
    const char *fallback)
{
  switch ( status )
  {
    case services::DecompileStatus::InvalidAddress:
      return Error(rpc::ErrorCode::InvalidAddress, "diff action address is invalid");
    case services::DecompileStatus::NotFound:
      return Error(rpc::ErrorCode::NotFound, "diff action function was not found");
    case services::DecompileStatus::CapabilityUnavailable:
      return Error(rpc::ErrorCode::CapabilityUnavailable, "decompiler is unavailable");
    case services::DecompileStatus::InvalidArgument:
      return Error(rpc::ErrorCode::InvalidArgument, "diff decompile request is invalid");
    case services::DecompileStatus::Busy:
      return Error(rpc::ErrorCode::IdaBusy, "IDA is busy", true);
    case services::DecompileStatus::OutputLimit:
      return Error(rpc::ErrorCode::OutputLimit, "diff pseudocode output limit exceeded");
    case services::DecompileStatus::Failed:
      return Error(rpc::ErrorCode::DecompileFailed, fallback);
    case services::DecompileStatus::Success:
      break;
  }
  return Error(rpc::ErrorCode::InternalError, "diff decompile result is unavailable");
}

} // namespace

Dispatcher::MethodHandlers BuildWorkflowHandlers(
    IdaExecutor &executor,
    services::DatabaseService &database_service,
    const services::DecompilerService &decompiler_service,
    services::ChangeSetService &changeset_service)
{
  Dispatcher::MethodHandlers handlers;
  handlers.emplace("database.save", [&executor, &database_service](const rpc::Request &request) -> Dispatcher::MethodResult
  {
    if ( !Fields(request.params, {"compact", "backup"}) )
      return Error(rpc::ErrorCode::InvalidArgument, "database.save contains an unknown parameter");
    bool compact = false;
    bool backup = false;
    if ( request.params.contains("compact") )
    {
      if ( !request.params["compact"].is_boolean() )
        return Error(rpc::ErrorCode::InvalidArgument, "database.save compact must be boolean");
      compact = request.params["compact"].get<bool>();
    }
    if ( request.params.contains("backup") )
    {
      if ( !request.params["backup"].is_boolean() )
        return Error(rpc::ErrorCode::InvalidArgument, "database.save backup must be boolean");
      backup = request.params["backup"].get<bool>();
    }
    try
    {
      const auto outcome = executor.WriteFor(
          std::chrono::milliseconds(request.timeout_ms),
          [&database_service, compact, backup]()
          {
            return database_service.Save(std::nullopt, compact, backup);
          });
      if ( outcome.status == services::DatabaseSaveStatus::InvalidArgument )
        return Error(rpc::ErrorCode::InvalidArgument, "database.save target is invalid");
      if ( outcome.status == services::DatabaseSaveStatus::Failed || !outcome.result )
        return Error(rpc::ErrorCode::InternalError, "IDA failed to save the database");
      return services::ToJson(*outcome.result);
    }
    catch ( const IdaTimeoutError & )
    {
      return Error(rpc::ErrorCode::Timeout, "IDA save timed out", true);
    }
    catch ( const IdaBusyError & )
    {
      return Error(rpc::ErrorCode::IdaBusy, "IDA is busy", true);
    }
  });

  handlers.emplace("analysis.diff_before_after", [&executor, &decompiler_service, &changeset_service](const rpc::Request &request) -> Dispatcher::MethodResult
  {
    if ( request.params.size() != 1 || !request.params.contains("action") )
      return Error(rpc::ErrorCode::InvalidArgument, "analysis.diff_before_after requires one action");
    const auto operation = Operation(request.params["action"]);
    if ( !operation )
      return Error(rpc::ErrorCode::InvalidArgument, "analysis.diff_before_after action is invalid");
    if ( operation->kind == services::ChangeKind::DeclareType || operation->kind == services::ChangeKind::EnumUpsert
      || operation->kind == services::ChangeKind::InvalidateAllDecompilations )
      return Error(rpc::ErrorCode::InvalidArgument, "analysis.diff_before_after requires an address-targeting action");
    const std::vector<services::ChangeOperation> operations{*operation};
    const nlohmann::json action = request.params["action"];
    const std::string session = request.session_id;
    try
    {
      return executor.WriteFor(
          std::chrono::milliseconds(request.timeout_ms),
          [&decompiler_service, &changeset_service, operations, action, session]() -> Dispatcher::MethodResult
          {
            const auto before = decompiler_service.Decompile({operations.front().address, 0, 65536});
            if ( before.status != services::DecompileStatus::Success || !before.result )
              return DecompileFailure(before.status, "failed to decompile before the action");
            const auto preview = changeset_service.Preview(operations);
            if ( preview.status != services::ChangeStatus::Success ) return ChangeFailure(preview.status);
            if ( !preview.result || preview.result->items.size() != 1 )
              return Error(rpc::ErrorCode::InternalError, "changeset preview result is unavailable");
            const auto item = preview.result->items.front();
            if ( item.conflict || !preview.result->applicable )
              return Error(rpc::ErrorCode::Conflict, "diff action conflicts with current state");
            if ( item.before == item.after )
              return nlohmann::json{{"before", before.result->pseudocode}, {"after", before.result->pseudocode},
                  {"action", action}, {"changed", false}};
            const auto applied = changeset_service.Apply(preview.result->preview_id, operations, session);
            if ( applied.status != services::ChangeStatus::Success ) return ChangeFailure(applied.status);
            if ( !applied.result || !applied.result->applied )
              return Error(rpc::ErrorCode::InternalError, "diff action was not applied");
            if ( !decompiler_service.Invalidate(operations.front().address) )
            {
              const auto rollback = changeset_service.Rollback(applied.result->change_id, session);
              if ( rollback.status == services::ChangeStatus::Success )
                return Error(rpc::ErrorCode::InternalError, "failed to invalidate pseudocode; action was rolled back");
              return RecoveryError(
                  "failed to invalidate pseudocode and rollback failed",
                  applied.result->change_id);
            }
            const auto after = decompiler_service.Decompile({operations.front().address, 0, 65536});
            if ( after.status != services::DecompileStatus::Success || !after.result )
            {
              const auto rollback = changeset_service.Rollback(applied.result->change_id, session);
              if ( rollback.status == services::ChangeStatus::Success )
                return DecompileFailure(after.status, "failed to decompile after the action; action was rolled back");
              return RecoveryError(
                  "failed to decompile after the action and rollback failed",
                  applied.result->change_id);
            }
            const std::string after_text = after.result->pseudocode;
            const auto rollback = changeset_service.Rollback(applied.result->change_id, session);
            if ( rollback.status != services::ChangeStatus::Success || !rollback.result || !rollback.result->applied )
              return RecoveryError("diff action rollback failed", applied.result->change_id);
            if ( !decompiler_service.Invalidate(operations.front().address) )
              return Error(rpc::ErrorCode::InternalError, "failed to invalidate pseudocode after diff rollback");
            return nlohmann::json{{"before", before.result->pseudocode}, {"after", after_text},
                {"action", action}, {"changed", before.result->pseudocode != after_text}};
          });
    }
    catch ( const IdaTimeoutError & )
    {
      return Error(rpc::ErrorCode::Timeout, "IDA diff action timed out", true);
    }
    catch ( const IdaBusyError & )
    {
      return Error(rpc::ErrorCode::IdaBusy, "IDA is busy", true);
    }
  });
  return handlers;
}

} // namespace ida_agent::bridge
