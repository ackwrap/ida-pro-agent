#include "changeset_handlers.hpp"

#include "ida_executor.hpp"
#include "rpc/address.hpp"
#include "services/changeset_service.hpp"

#include <algorithm>
#include <chrono>
#include <limits>
#include <optional>
#include <string>
#include <vector>

namespace ida_agent::bridge
{
namespace
{
Dispatcher::MethodResult Error(rpc::ErrorCode code, const char *message, bool retryable = false) { return rpc::RpcError{code, message, retryable}; }

bool FieldsMatchKind(const nlohmann::json &item, services::ChangeKind kind)
{
  const bool repeatable = item.contains("repeatable");
  const bool offset = item.contains("offset");
  const bool size = item.contains("size");
  const bool subject = item.contains("subject");
  switch ( kind )
  {
    case services::ChangeKind::CommentSet:
    case services::ChangeKind::CommentAppend:
      return !offset && !size && !subject;
    case services::ChangeKind::PatchInteger:
      return !repeatable && !offset && !size && subject;
    case services::ChangeKind::OperandOffset:
      return !repeatable && !offset && !size;
    case services::ChangeKind::OperandStructOffset:
      return !repeatable && !size && subject;
    case services::ChangeKind::StackDeclare:
      return !repeatable && offset && !size && !subject;
    case services::ChangeKind::StackDelete:
      return !repeatable && offset && size && !subject;
    case services::ChangeKind::LocalRename:
    case services::ChangeKind::LocalType:
    case services::ChangeKind::XrefCodeAdd:
    case services::ChangeKind::XrefCodeDelete:
    case services::ChangeKind::XrefDataAdd:
    case services::ChangeKind::XrefDataDelete:
    case services::ChangeKind::FunctionChunkAdd:
    case services::ChangeKind::FunctionChunkDelete:
      return !repeatable && !offset && !size && subject;
    case services::ChangeKind::Rename:
    case services::ChangeKind::PseudocodeComment:
    case services::ChangeKind::Bookmark:
    case services::ChangeKind::TypeApply:
    case services::ChangeKind::PatchBytes:
    case services::ChangeKind::DefineFunction:
    case services::ChangeKind::DefineCode:
    case services::ChangeKind::Undefine:
    case services::ChangeKind::ForceRecompile:
    case services::ChangeKind::MakeData:
    case services::ChangeKind::OperandHex:
    case services::ChangeKind::OperandDec:
    case services::ChangeKind::OperandChar:
    case services::ChangeKind::OperandBinary:
    case services::ChangeKind::OperandOctal:
    case services::ChangeKind::OperandStackVariable:
    case services::ChangeKind::DeclareType:
    case services::ChangeKind::EnumUpsert:
    case services::ChangeKind::InvalidateAllDecompilations:
    case services::ChangeKind::SegmentRename:
    case services::ChangeKind::SegmentPermissions:
    case services::ChangeKind::FunctionFlags:
    case services::ChangeKind::FunctionEnd:
      return !repeatable && !offset && !size && !subject;
  }
  return false;
}

bool IntegerType(std::string_view value)
{
  if ( value.size() < 2 || (value.front() != 'u' && value.front() != 'i') ) return false;
  value.remove_prefix(1);
  if ( value.size() > 2 && (value.substr(value.size() - 2) == "le" || value.substr(value.size() - 2) == "be") )
    value.remove_suffix(2);
  return value == "8" || value == "16" || value == "32" || value == "64";
}

bool OperandKind(services::ChangeKind kind)
{
  switch ( kind )
  {
    case services::ChangeKind::OperandHex:
    case services::ChangeKind::OperandDec:
    case services::ChangeKind::OperandChar:
    case services::ChangeKind::OperandBinary:
    case services::ChangeKind::OperandOctal:
    case services::ChangeKind::OperandOffset:
    case services::ChangeKind::OperandStructOffset:
    case services::ChangeKind::OperandStackVariable:
      return true;
    case services::ChangeKind::Rename:
    case services::ChangeKind::CommentSet:
    case services::ChangeKind::CommentAppend:
    case services::ChangeKind::PseudocodeComment:
    case services::ChangeKind::Bookmark:
    case services::ChangeKind::TypeApply:
    case services::ChangeKind::PatchBytes:
    case services::ChangeKind::PatchInteger:
    case services::ChangeKind::DefineFunction:
    case services::ChangeKind::DefineCode:
    case services::ChangeKind::Undefine:
    case services::ChangeKind::ForceRecompile:
    case services::ChangeKind::MakeData:
    case services::ChangeKind::DeclareType:
    case services::ChangeKind::EnumUpsert:
    case services::ChangeKind::InvalidateAllDecompilations:
    case services::ChangeKind::StackDeclare:
    case services::ChangeKind::StackDelete:
    case services::ChangeKind::LocalRename:
    case services::ChangeKind::LocalType:
    case services::ChangeKind::SegmentRename:
    case services::ChangeKind::SegmentPermissions:
    case services::ChangeKind::XrefCodeAdd:
    case services::ChangeKind::XrefCodeDelete:
    case services::ChangeKind::XrefDataAdd:
    case services::ChangeKind::XrefDataDelete:
    case services::ChangeKind::FunctionFlags:
    case services::ChangeKind::FunctionEnd:
    case services::ChangeKind::FunctionChunkAdd:
    case services::ChangeKind::FunctionChunkDelete:
      return false;
  }
  return false;
}

std::optional<std::vector<services::ChangeOperation>> Operations(const nlohmann::json &params)
{
  if ( !params.is_object() || !params.contains("operations") || !params["operations"].is_array()
    || params["operations"].empty() || params["operations"].size() > 100 ) return std::nullopt;
  std::vector<services::ChangeOperation> result;
  for ( const auto &item : params["operations"] )
  {
    if ( !item.is_object() ) return std::nullopt;
    for ( auto field = item.begin(); field != item.end(); ++field )
    {
      if ( field.key() != "kind" && field.key() != "address" && field.key() != "value"
        && field.key() != "expected" && field.key() != "repeatable"
        && field.key() != "offset" && field.key() != "size" && field.key() != "subject" ) return std::nullopt;
    }
    if ( !item.contains("kind") || !item["kind"].is_string()
      || !item.contains("value") || !item["value"].is_string() ) return std::nullopt;
    const std::string value = item["value"].get<std::string>();
    if ( value.size() > 65536 ) return std::nullopt;
    services::ChangeKind kind;
    const std::string kind_name = item["kind"].get<std::string>();
    if ( kind_name == "rename" ) kind = services::ChangeKind::Rename;
    else if ( kind_name == "comment.set" ) kind = services::ChangeKind::CommentSet;
    else if ( kind_name == "comment.append" ) kind = services::ChangeKind::CommentAppend;
    else if ( kind_name == "comment.pseudocode" ) kind = services::ChangeKind::PseudocodeComment;
    else if ( kind_name == "bookmark.add" ) kind = services::ChangeKind::Bookmark;
    else if ( kind_name == "type.apply" ) kind = services::ChangeKind::TypeApply;
    else if ( kind_name == "patch.bytes" ) kind = services::ChangeKind::PatchBytes;
    else if ( kind_name == "patch.integer" ) kind = services::ChangeKind::PatchInteger;
    else if ( kind_name == "define.function" ) kind = services::ChangeKind::DefineFunction;
    else if ( kind_name == "define.code" ) kind = services::ChangeKind::DefineCode;
    else if ( kind_name == "undefine" ) kind = services::ChangeKind::Undefine;
    else if ( kind_name == "decompiler.invalidate" ) kind = services::ChangeKind::ForceRecompile;
    else if ( kind_name == "define.data" ) kind = services::ChangeKind::MakeData;
    else if ( kind_name == "operand.hex" ) kind = services::ChangeKind::OperandHex;
    else if ( kind_name == "operand.decimal" ) kind = services::ChangeKind::OperandDec;
    else if ( kind_name == "operand.character" ) kind = services::ChangeKind::OperandChar;
    else if ( kind_name == "operand.binary" ) kind = services::ChangeKind::OperandBinary;
    else if ( kind_name == "operand.octal" ) kind = services::ChangeKind::OperandOctal;
    else if ( kind_name == "operand.offset" ) kind = services::ChangeKind::OperandOffset;
    else if ( kind_name == "operand.struct_offset" ) kind = services::ChangeKind::OperandStructOffset;
    else if ( kind_name == "operand.stack_variable" ) kind = services::ChangeKind::OperandStackVariable;
    else if ( kind_name == "type.declare" ) kind = services::ChangeKind::DeclareType;
    else if ( kind_name == "enum.upsert" ) kind = services::ChangeKind::EnumUpsert;
    else if ( kind_name == "decompiler.invalidate_all" ) kind = services::ChangeKind::InvalidateAllDecompilations;
    else if ( kind_name == "stack.declare" ) kind = services::ChangeKind::StackDeclare;
    else if ( kind_name == "stack.delete" ) kind = services::ChangeKind::StackDelete;
    else if ( kind_name == "local.rename" ) kind = services::ChangeKind::LocalRename;
    else if ( kind_name == "local.type" ) kind = services::ChangeKind::LocalType;
    else if ( kind_name == "segment.rename" ) kind = services::ChangeKind::SegmentRename;
    else if ( kind_name == "segment.permissions" ) kind = services::ChangeKind::SegmentPermissions;
    else if ( kind_name == "xref.code.add" ) kind = services::ChangeKind::XrefCodeAdd;
    else if ( kind_name == "xref.code.delete" ) kind = services::ChangeKind::XrefCodeDelete;
    else if ( kind_name == "xref.data.add" ) kind = services::ChangeKind::XrefDataAdd;
    else if ( kind_name == "xref.data.delete" ) kind = services::ChangeKind::XrefDataDelete;
    else if ( kind_name == "function.flags" ) kind = services::ChangeKind::FunctionFlags;
    else if ( kind_name == "function.end" ) kind = services::ChangeKind::FunctionEnd;
    else if ( kind_name == "function.chunk.add" ) kind = services::ChangeKind::FunctionChunkAdd;
    else if ( kind_name == "function.chunk.delete" ) kind = services::ChangeKind::FunctionChunkDelete;
    else return std::nullopt;
    if ( !FieldsMatchKind(item, kind) ) return std::nullopt;
    if ( kind == services::ChangeKind::Bookmark && (value.empty() || value.size() > 1024) ) return std::nullopt;
    if ( OperandKind(kind) && (value.size() != 1 || value.front() < '0' || value.front() > '7') ) return std::nullopt;
    std::uint64_t address = 0;
    const bool addressless = kind == services::ChangeKind::DeclareType || kind == services::ChangeKind::EnumUpsert
        || kind == services::ChangeKind::InvalidateAllDecompilations;
    if ( !addressless )
    {
      if ( !item.contains("address") || !item["address"].is_string() ) return std::nullopt;
      try { address = rpc::ParseAddress(item["address"].get<std::string>()); }
      catch ( const std::invalid_argument & ) { return std::nullopt; }
    }
    else if ( item.contains("address") )
    {
      return std::nullopt;
    }
    std::optional<std::string> expected;
    if ( item.contains("expected") ) { if ( !item["expected"].is_string() || item["expected"].get<std::string>().size() > 65536 ) return std::nullopt; expected = item["expected"].get<std::string>(); }
    bool repeatable = false;
    if ( item.contains("repeatable") ) { if ( !item["repeatable"].is_boolean() ) return std::nullopt; repeatable = item["repeatable"].get<bool>(); }
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
    if ( item.contains("size") ) { if ( !item["size"].is_number_unsigned() || item["size"].get<std::uint64_t>() > (std::numeric_limits<std::uint32_t>::max)() ) return std::nullopt; size = static_cast<std::uint32_t>(item["size"].get<std::uint64_t>()); if ( *size == 0 ) return std::nullopt; }
    std::optional<std::string> subject;
    if ( item.contains("subject") ) { if ( !item["subject"].is_string() || item["subject"].get<std::string>().empty() || item["subject"].get<std::string>().size() > 1024 ) return std::nullopt; subject = item["subject"].get<std::string>(); }
    if ( kind == services::ChangeKind::PatchInteger && (!subject || !IntegerType(*subject)) ) return std::nullopt;
    if ( kind == services::ChangeKind::InvalidateAllDecompilations && !value.empty() ) return std::nullopt;
    if ( kind == services::ChangeKind::SegmentRename && (value.empty() || value.size() > 255) ) return std::nullopt;
    if ( kind == services::ChangeKind::SegmentPermissions
      && (value.size() != 3 || (value[0] != 'r' && value[0] != '-')
        || (value[1] != 'w' && value[1] != '-') || (value[2] != 'x' && value[2] != '-')) ) return std::nullopt;
    if ( kind == services::ChangeKind::XrefCodeAdd || kind == services::ChangeKind::XrefCodeDelete
      || kind == services::ChangeKind::XrefDataAdd || kind == services::ChangeKind::XrefDataDelete )
    {
      if ( !subject ) return std::nullopt;
      const bool code = kind == services::ChangeKind::XrefCodeAdd || kind == services::ChangeKind::XrefCodeDelete;
      const bool valid_type = code
          ? *subject == "call_far" || *subject == "call_near" || *subject == "jump_far" || *subject == "jump_near"
          : *subject == "offset" || *subject == "write" || *subject == "read" || *subject == "text" || *subject == "informational";
      if ( !valid_type ) return std::nullopt;
      try { static_cast<void>(rpc::ParseAddress(value)); }
      catch ( const std::invalid_argument & ) { return std::nullopt; }
    }
    if ( kind == services::ChangeKind::FunctionFlags )
    {
      std::string_view remaining(value);
      while ( !remaining.empty() )
      {
        const std::size_t separator = remaining.find(',');
        const std::string_view flag = remaining.substr(0, separator);
        if ( flag != "noreturn" && flag != "library" && flag != "static" && flag != "hidden" && flag != "thunk" ) return std::nullopt;
        if ( separator == std::string_view::npos ) break;
        remaining.remove_prefix(separator + 1);
        if ( remaining.empty() ) return std::nullopt;
      }
    }
    if ( kind == services::ChangeKind::FunctionEnd )
    {
      try { static_cast<void>(rpc::ParseAddress(value)); }
      catch ( const std::invalid_argument & ) { return std::nullopt; }
    }
    if ( kind == services::ChangeKind::FunctionChunkAdd || kind == services::ChangeKind::FunctionChunkDelete )
    {
      if ( !subject ) return std::nullopt;
      try
      {
        const std::uint64_t start = rpc::ParseAddress(value);
        const std::uint64_t end = rpc::ParseAddress(*subject);
        if ( start >= end || end - start > 16 * 1024 * 1024 ) return std::nullopt;
      }
      catch ( const std::invalid_argument & ) { return std::nullopt; }
    }
    if ( kind == services::ChangeKind::OperandOffset && subject )
    {
      try { static_cast<void>(rpc::ParseAddress(*subject)); }
      catch ( const std::invalid_argument & ) { return std::nullopt; }
    }
    if ( (kind == services::ChangeKind::StackDeclare || kind == services::ChangeKind::StackDelete) && (!offset || *offset < 0) ) return std::nullopt;
    result.push_back({kind, address, value, std::move(expected), repeatable, offset, size, std::move(subject)});
  }
  if ( result.size() != 1 && std::any_of(result.begin(), result.end(), [](const services::ChangeOperation &operation)
      { return operation.kind == services::ChangeKind::InvalidateAllDecompilations; }) ) return std::nullopt;
  return result;
}

template <typename Outcome>
Dispatcher::MethodResult Result(Outcome outcome)
{
  switch ( outcome.status )
  {
    case services::ChangeStatus::InvalidAddress: return Error(rpc::ErrorCode::InvalidAddress, "changeset address is invalid");
    case services::ChangeStatus::InvalidArgument: return Error(rpc::ErrorCode::InvalidArgument, "changeset operation is invalid");
    case services::ChangeStatus::Conflict: return Error(rpc::ErrorCode::Conflict, "changeset preview is stale or conflicts");
    case services::ChangeStatus::NotFound: return Error(rpc::ErrorCode::NotFound, "changeset was not found");
    case services::ChangeStatus::CapabilityUnavailable: return Error(rpc::ErrorCode::CapabilityUnavailable, "Hex-Rays decompiler is unavailable");
    case services::ChangeStatus::Failed: return Error(rpc::ErrorCode::InternalError, "IDA rejected the changeset");
    case services::ChangeStatus::OutputLimit: return Error(rpc::ErrorCode::OutputLimit, "changeset output limit exceeded");
    case services::ChangeStatus::Success: break;
  }
  if ( !outcome.result ) return Error(rpc::ErrorCode::InternalError, "changeset result is unavailable");
  return services::ToJson(*outcome.result);
}

template <typename Operation>
Dispatcher::MethodResult Read(IdaExecutor &executor, const rpc::Request &request, Operation operation)
{
  try { return executor.ReadFor(std::chrono::milliseconds(request.timeout_ms), std::move(operation)); }
  catch ( const IdaTimeoutError & ) { return Error(rpc::ErrorCode::Timeout, "IDA request timed out", true); }
  catch ( const IdaBusyError & ) { return Error(rpc::ErrorCode::IdaBusy, "IDA is busy", true); }
}
template <typename Operation>
Dispatcher::MethodResult Write(IdaExecutor &executor, const rpc::Request &request, Operation operation)
{
  try { return executor.WriteFor(std::chrono::milliseconds(request.timeout_ms), std::move(operation)); }
  catch ( const IdaTimeoutError & ) { return Error(rpc::ErrorCode::Timeout, "IDA write timed out", true); }
  catch ( const IdaBusyError & ) { return Error(rpc::ErrorCode::IdaBusy, "IDA is busy", true); }
}
}

Dispatcher::MethodHandlers BuildChangeSetHandlers(IdaExecutor &executor, services::ChangeSetService &service)
{
  Dispatcher::MethodHandlers handlers;
  handlers.emplace("changeset.preview", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult
  {
    if ( request.params.size() != 1 ) return Error(rpc::ErrorCode::InvalidArgument, "changeset.preview requires operations");
    const auto operations = Operations(request.params); if ( !operations ) return Error(rpc::ErrorCode::InvalidArgument, "changeset operations are invalid");
    return Read(executor, request, [&service, operations]() { return Result(service.Preview(*operations)); });
  });
  handlers.emplace("changeset.apply", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult
  {
    if ( request.params.size() != 2 || !request.params.contains("previewId") || !request.params["previewId"].is_string()
      || request.params["previewId"].get<std::string>().empty() || request.params["previewId"].get<std::string>().size() > 128 ) return Error(rpc::ErrorCode::InvalidArgument, "changeset.apply requires previewId and operations");
    const auto operations = Operations(request.params); if ( !operations ) return Error(rpc::ErrorCode::InvalidArgument, "changeset operations are invalid");
    const std::string preview = request.params["previewId"].get<std::string>();
    return Write(executor, request, [&service, preview, operations, session = request.session_id]() { return Result(service.Apply(preview, *operations, session)); });
  });
  handlers.emplace("changeset.rollback", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult
  {
    if ( request.params.size() != 1 || !request.params.contains("changeId") || !request.params["changeId"].is_string()
      || request.params["changeId"].get<std::string>().empty() || request.params["changeId"].get<std::string>().size() > 256 ) return Error(rpc::ErrorCode::InvalidArgument, "changeset.rollback requires changeId");
    const std::string id = request.params["changeId"].get<std::string>();
    return Write(executor, request, [&service, id, session = request.session_id]() { return Result(service.Rollback(id, session)); });
  });
  handlers.emplace("changeset.audit", [&executor, &service](const rpc::Request &request) -> Dispatcher::MethodResult
  {
    for ( auto field = request.params.begin(); field != request.params.end(); ++field ) if ( field.key() != "offset" && field.key() != "limit" ) return Error(rpc::ErrorCode::InvalidArgument, "changeset.audit contains an unknown parameter");
    std::uint32_t offset = 0, limit = 100;
    if ( request.params.contains("offset") ) { if ( !request.params["offset"].is_number_unsigned() || request.params["offset"].get<std::uint64_t>() > (std::numeric_limits<std::uint32_t>::max)() ) return Error(rpc::ErrorCode::InvalidArgument, "audit offset is invalid"); offset = static_cast<std::uint32_t>(request.params["offset"].get<std::uint64_t>()); }
    if ( request.params.contains("limit") ) { if ( !request.params["limit"].is_number_unsigned() || request.params["limit"].get<std::uint64_t>() > 1000 ) return Error(rpc::ErrorCode::InvalidArgument, "audit limit is invalid"); limit = static_cast<std::uint32_t>(request.params["limit"].get<std::uint64_t>()); if ( limit == 0 ) return Error(rpc::ErrorCode::InvalidArgument, "audit limit is invalid"); }
    return Read(executor, request, [&service, offset, limit]() { return Result(service.Audit(offset, limit)); });
  });
  return handlers;
}
} // namespace ida_agent::bridge
