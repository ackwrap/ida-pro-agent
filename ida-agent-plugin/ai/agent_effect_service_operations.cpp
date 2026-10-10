#include "ai/agent_effect_service_operations.hpp"
#include "ai/agent_effect_digest.hpp"
#include "ai/agent_effect_file_operations.hpp"

#ifndef IDA_AGENT_AGENT_EFFECT_SERVICE_TESTING
#include "bridge/ida_executor.hpp"
#endif

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <limits>
#include <optional>
#include <sstream>
#include <string_view>
#include <utility>

namespace ida_agent::ai
{
namespace
{
using Json = nlohmann::json;
constexpr std::size_t MaxResultBytes = 256 * 1024;
constexpr std::string_view LocalSession = "local-agent";

const char *Name(AgentEffectName effect)
{
  switch ( effect )
  {
    case AgentEffectName::ChangeSetApply: return "ida_changeset_apply";
    case AgentEffectName::ChangeSetRollback: return "ida_changeset_rollback";
    case AgentEffectName::DatabaseSave: return "ida_database_save";
    case AgentEffectName::AnalysisPlan: return "ida_analysis_plan";
    case AgentEffectName::DebuggerSelect: return "ida_debugger_select";
    case AgentEffectName::DebuggerConfigure: return "ida_debugger_configure";
    case AgentEffectName::DebuggerAttach: return "ida_debugger_attach";
    case AgentEffectName::DebuggerDetach: return "ida_debugger_detach";
    case AgentEffectName::DebuggerSuspend: return "ida_debugger_suspend";
    case AgentEffectName::DebuggerStart: return "ida_debugger_start";
    case AgentEffectName::DebuggerExit: return "ida_debugger_exit";
    case AgentEffectName::DebuggerControl: return "ida_debugger_control";
    case AgentEffectName::DebuggerBreakpoint: return "ida_debugger_breakpoint_mutate";
    case AgentEffectName::DebuggerMemoryWrite: return "ida_debugger_memory_write";
    case AgentEffectName::FileMutate: return "ida_file_mutate";
    case AgentEffectName::ScriptExecuteFile: return "ida_script_execute_file";
  }
  return "";
}

AgentEffectPreparation PreparationFailure(std::string message)
{
  return {{}, std::move(message)};
}

AgentToolResult Failure(const AgentToolCall &call, const char *message)
{
  return {call.id, call.name, false, {}, message};
}

AgentToolResult Success(const AgentToolCall &call, Json value) noexcept
{
  try
  {
    if ( !value.is_object() )
      return Failure(call, "The side effect returned an invalid result.");
    std::string output = value.dump();
    if ( output.size() > MaxResultBytes )
      return Failure(call, "The side effect result exceeded the safe output limit.");
    return {call.id, call.name, true, std::move(output), {}};
  }
  catch ( ... )
  {
    return Failure(call, "The side effect result could not be encoded safely.");
  }
}

bool Fields(const Json &value, std::initializer_list<const char *> names)
{
  if ( !value.is_object() || value.size() != names.size() ) return false;
  return std::all_of(names.begin(), names.end(), [&](const char *name) {
    return value.contains(name);
  });
}

std::optional<std::uint64_t> Address(const Json &value)
{
  if ( !value.is_string() ) return std::nullopt;
  const std::string text = value.get<std::string>();
  if ( text.size() < 3 || text.size() > 18 || text[0] != '0' || text[1] != 'x' )
    return std::nullopt;
  std::uint64_t result = 0;
  for ( std::size_t index = 2; index < text.size(); ++index )
  {
    const unsigned char ch = static_cast<unsigned char>(text[index]);
    unsigned digit = 0;
    if ( ch >= '0' && ch <= '9' ) digit = ch - '0';
    else if ( ch >= 'a' && ch <= 'f' ) digit = ch - 'a' + 10;
    else if ( ch >= 'A' && ch <= 'F' ) digit = ch - 'A' + 10;
    else return std::nullopt;
    result = (result << 4) | digit;
  }
  return result;
}

std::string HexAddress(std::uint64_t value)
{
  std::ostringstream output;
  output << "0x" << std::hex << value;
  return output.str();
}

bool ValidUtf8(std::string_view value)
{
  for ( std::size_t index = 0; index < value.size(); )
  {
    const unsigned char lead = static_cast<unsigned char>(value[index++]);
    if ( lead < 0x80 ) continue;
    std::size_t count = 0;
    std::uint32_t point = 0;
    if ( lead >= 0xC2 && lead <= 0xDF ) { count = 1; point = lead & 0x1F; }
    else if ( lead >= 0xE0 && lead <= 0xEF ) { count = 2; point = lead & 0x0F; }
    else if ( lead >= 0xF0 && lead <= 0xF4 ) { count = 3; point = lead & 0x07; }
    else return false;
    if ( index + count > value.size() ) return false;
    for ( std::size_t part = 0; part < count; ++part )
    {
      const unsigned char continuation = static_cast<unsigned char>(value[index++]);
      if ( (continuation & 0xC0) != 0x80 ) return false;
      point = (point << 6) | (continuation & 0x3F);
    }
    if ( (count == 2 && point < 0x800) || (count == 3 && point < 0x10000)
      || point > 0x10FFFF || (point >= 0xD800 && point <= 0xDFFF) ) return false;
  }
  return true;
}

std::optional<std::string> HexBytes(const Json &value)
{
  if ( !value.is_string() ) return std::nullopt;
  std::string text = value.get<std::string>();
  if ( text.empty() || text.size() > 131072 || text.size() % 2 != 0 )
    return std::nullopt;
  if ( !std::all_of(text.begin(), text.end(), [](unsigned char ch) {
         return std::isxdigit(ch) != 0;
       }) ) return std::nullopt;
  return text;
}

std::optional<services::ChangeKind> ChangeKind(std::string_view name)
{
  using K = services::ChangeKind;
  static const std::pair<std::string_view, K> values[]{
      {"rename",K::Rename},{"comment.set",K::CommentSet},{"comment.append",K::CommentAppend},
      {"comment.pseudocode",K::PseudocodeComment},{"bookmark.add",K::Bookmark},{"type.apply",K::TypeApply},
      {"patch.bytes",K::PatchBytes},{"patch.integer",K::PatchInteger},{"define.function",K::DefineFunction},
      {"define.code",K::DefineCode},{"undefine",K::Undefine},{"decompiler.invalidate",K::ForceRecompile},
      {"define.data",K::MakeData},{"operand.hex",K::OperandHex},{"operand.decimal",K::OperandDec},
      {"operand.character",K::OperandChar},{"operand.binary",K::OperandBinary},{"operand.octal",K::OperandOctal},
      {"operand.offset",K::OperandOffset},{"operand.struct_offset",K::OperandStructOffset},
      {"operand.stack_variable",K::OperandStackVariable},{"type.declare",K::DeclareType},{"enum.upsert",K::EnumUpsert},
      {"decompiler.invalidate_all",K::InvalidateAllDecompilations},{"stack.declare",K::StackDeclare},
      {"stack.delete",K::StackDelete},{"local.rename",K::LocalRename},{"local.type",K::LocalType},
      {"segment.rename",K::SegmentRename},{"segment.permissions",K::SegmentPermissions},
      {"xref.code.add",K::XrefCodeAdd},{"xref.code.delete",K::XrefCodeDelete},{"xref.data.add",K::XrefDataAdd},
      {"xref.data.delete",K::XrefDataDelete},{"function.flags",K::FunctionFlags},{"function.end",K::FunctionEnd},
      {"function.chunk.add",K::FunctionChunkAdd},{"function.chunk.delete",K::FunctionChunkDelete}};
  for ( const auto &value : values ) if ( value.first == name ) return value.second;
  return std::nullopt;
}

const char *ChangeKindName(services::ChangeKind kind)
{
  using K = services::ChangeKind;
  switch ( kind )
  {
    case K::Rename:return "rename"; case K::CommentSet:return "comment.set"; case K::CommentAppend:return "comment.append";
    case K::PseudocodeComment:return "comment.pseudocode"; case K::Bookmark:return "bookmark.add"; case K::TypeApply:return "type.apply";
    case K::PatchBytes:return "patch.bytes"; case K::PatchInteger:return "patch.integer"; case K::DefineFunction:return "define.function";
    case K::DefineCode:return "define.code"; case K::Undefine:return "undefine"; case K::ForceRecompile:return "decompiler.invalidate";
    case K::MakeData:return "define.data"; case K::OperandHex:return "operand.hex"; case K::OperandDec:return "operand.decimal";
    case K::OperandChar:return "operand.character"; case K::OperandBinary:return "operand.binary"; case K::OperandOctal:return "operand.octal";
    case K::OperandOffset:return "operand.offset"; case K::OperandStructOffset:return "operand.struct_offset";
    case K::OperandStackVariable:return "operand.stack_variable"; case K::DeclareType:return "type.declare"; case K::EnumUpsert:return "enum.upsert";
    case K::InvalidateAllDecompilations:return "decompiler.invalidate_all"; case K::StackDeclare:return "stack.declare";
    case K::StackDelete:return "stack.delete"; case K::LocalRename:return "local.rename"; case K::LocalType:return "local.type";
    case K::SegmentRename:return "segment.rename"; case K::SegmentPermissions:return "segment.permissions";
    case K::XrefCodeAdd:return "xref.code.add"; case K::XrefCodeDelete:return "xref.code.delete"; case K::XrefDataAdd:return "xref.data.add";
    case K::XrefDataDelete:return "xref.data.delete"; case K::FunctionFlags:return "function.flags"; case K::FunctionEnd:return "function.end";
    case K::FunctionChunkAdd:return "function.chunk.add"; case K::FunctionChunkDelete:return "function.chunk.delete";
  }
  return "";
}

bool IntegerType(std::string_view value)
{
  if ( value.size() < 2 || (value.front() != 'u' && value.front() != 'i') ) return false;
  value.remove_prefix(1);
  if ( value.size() > 2 && (value.substr(value.size() - 2) == "le" || value.substr(value.size() - 2) == "be") ) value.remove_suffix(2);
  return value == "8" || value == "16" || value == "32" || value == "64";
}

bool OperandKind(services::ChangeKind kind)
{
  using K = services::ChangeKind;
  return kind == K::OperandHex || kind == K::OperandDec || kind == K::OperandChar
      || kind == K::OperandBinary || kind == K::OperandOctal || kind == K::OperandOffset
      || kind == K::OperandStructOffset || kind == K::OperandStackVariable;
}

bool OptionalFieldsMatch(const services::ChangeOperation &operation)
{
  using K = services::ChangeKind;
  const bool repeatable = operation.repeatable, offset = operation.offset.has_value();
  const bool size = operation.size.has_value(), subject = operation.subject.has_value();
  switch ( operation.kind )
  {
    case K::CommentSet: case K::CommentAppend: return !offset && !size && !subject;
    case K::PatchInteger:return !repeatable && !offset && !size && subject;
    case K::OperandOffset:return !repeatable && !offset && !size;
    case K::OperandStructOffset:return !repeatable && !size && subject;
    case K::StackDeclare:return !repeatable && offset && !size && !subject;
    case K::StackDelete:return !repeatable && offset && size && !subject;
    case K::LocalRename: case K::LocalType: case K::XrefCodeAdd: case K::XrefCodeDelete:
    case K::XrefDataAdd: case K::XrefDataDelete: case K::FunctionChunkAdd: case K::FunctionChunkDelete:
      return !repeatable && !offset && !size && subject;
    default:return !repeatable && !offset && !size && !subject;
  }
}

std::optional<std::vector<services::ChangeOperation>> Operations(const Json &arguments)
{
  if ( !Fields(arguments, {"operations"}) || !arguments["operations"].is_array()
    || arguments["operations"].empty() || arguments["operations"].size() > 100 ) return std::nullopt;
  std::vector<services::ChangeOperation> result;
  for ( const Json &item : arguments["operations"] )
  {
    if ( !Fields(item, {"kind","address","value","expected","repeatable","offset","size","subject"})
      || !item["kind"].is_string() || !item["value"].is_string() || !item["repeatable"].is_boolean() ) return std::nullopt;
    const auto kind = ChangeKind(item["kind"].get<std::string>());
    const std::string value = item["value"].get<std::string>();
    if ( !kind || value.size() > 65536 ) return std::nullopt;
    services::ChangeOperation operation{*kind, 0, value, std::nullopt, item["repeatable"].get<bool>(), std::nullopt, std::nullopt, std::nullopt};
    const bool addressless = *kind == services::ChangeKind::DeclareType || *kind == services::ChangeKind::EnumUpsert
        || *kind == services::ChangeKind::InvalidateAllDecompilations;
    if ( item["address"].is_null() ) { if ( !addressless ) return std::nullopt; }
    else { const auto address = Address(item["address"]); if ( addressless || !address ) return std::nullopt; operation.address = *address; }
    if ( !item["expected"].is_null() ) { if ( !item["expected"].is_string() ) return std::nullopt; operation.expected = item["expected"].get<std::string>(); if ( operation.expected->size() > 65536 ) return std::nullopt; }
    if ( !item["offset"].is_null() )
    {
      if ( item["offset"].is_number_unsigned() ) { const auto number = item["offset"].get<std::uint64_t>(); if ( number > static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()) ) return std::nullopt; operation.offset = static_cast<std::int64_t>(number); }
      else if ( item["offset"].is_number_integer() ) operation.offset = item["offset"].get<std::int64_t>(); else return std::nullopt;
    }
    if ( !item["size"].is_null() ) { if ( !item["size"].is_number_unsigned() ) return std::nullopt; const auto number = item["size"].get<std::uint64_t>(); if ( number == 0 || number > (std::numeric_limits<std::uint32_t>::max)() ) return std::nullopt; operation.size = static_cast<std::uint32_t>(number); }
    if ( !item["subject"].is_null() ) { if ( !item["subject"].is_string() ) return std::nullopt; operation.subject = item["subject"].get<std::string>(); if ( operation.subject->empty() || operation.subject->size() > 1024 ) return std::nullopt; }
    if ( !OptionalFieldsMatch(operation) ) return std::nullopt;
    if ( *kind == services::ChangeKind::Bookmark && (value.empty() || value.size() > 1024) ) return std::nullopt;
    if ( OperandKind(*kind) && (value.size() != 1 || value[0] < '0' || value[0] > '7') ) return std::nullopt;
    if ( *kind == services::ChangeKind::PatchBytes && !HexBytes(Json(value)) ) return std::nullopt;
    if ( *kind == services::ChangeKind::PatchInteger && !IntegerType(*operation.subject) ) return std::nullopt;
    if ( *kind == services::ChangeKind::InvalidateAllDecompilations && !value.empty() ) return std::nullopt;
    if ( *kind == services::ChangeKind::SegmentRename && (value.empty() || value.size() > 255) ) return std::nullopt;
    if ( *kind == services::ChangeKind::SegmentPermissions && (value.size() != 3 || (value[0]!='r'&&value[0]!='-') || (value[1]!='w'&&value[1]!='-') || (value[2]!='x'&&value[2]!='-')) ) return std::nullopt;
    const bool xref_code = *kind == services::ChangeKind::XrefCodeAdd || *kind == services::ChangeKind::XrefCodeDelete;
    const bool xref_data = *kind == services::ChangeKind::XrefDataAdd || *kind == services::ChangeKind::XrefDataDelete;
    if ( xref_code || xref_data ) { if ( !Address(Json(value)) ) return std::nullopt; const auto &type = *operation.subject; if ( xref_code ? type!="call_far"&&type!="call_near"&&type!="jump_far"&&type!="jump_near" : type!="offset"&&type!="write"&&type!="read"&&type!="text"&&type!="informational" ) return std::nullopt; }
    if ( *kind == services::ChangeKind::FunctionEnd && !Address(Json(value)) ) return std::nullopt;
    if ( *kind == services::ChangeKind::FunctionFlags )
    {
      std::string_view remaining(value);
      while ( !remaining.empty() )
      {
        const std::size_t separator=remaining.find(','); const std::string_view flag=remaining.substr(0,separator);
        if(flag!="noreturn"&&flag!="library"&&flag!="static"&&flag!="hidden"&&flag!="thunk")return std::nullopt;
        if(separator==std::string_view::npos)break; remaining.remove_prefix(separator+1); if(remaining.empty())return std::nullopt;
      }
    }
    if ( *kind == services::ChangeKind::FunctionChunkAdd || *kind == services::ChangeKind::FunctionChunkDelete ) { const auto start = Address(Json(value)), end = Address(Json(*operation.subject)); if ( !start || !end || *start >= *end || *end - *start > 16ULL*1024*1024 ) return std::nullopt; }
    if ( *kind == services::ChangeKind::OperandOffset && operation.subject && !Address(Json(*operation.subject)) ) return std::nullopt;
    if ( (*kind == services::ChangeKind::StackDeclare || *kind == services::ChangeKind::StackDelete) && (!operation.offset || *operation.offset < 0) ) return std::nullopt;
    result.push_back(std::move(operation));
  }
  if ( result.size() != 1 && std::any_of(result.begin(), result.end(), [](const auto &operation) { return operation.kind == services::ChangeKind::InvalidateAllDecompilations; }) ) return std::nullopt;
  return result;
}

Json OperationJson(const services::ChangeOperation &operation)
{
  return {{"kind",ChangeKindName(operation.kind)}, {"address",operation.kind == services::ChangeKind::DeclareType || operation.kind == services::ChangeKind::EnumUpsert || operation.kind == services::ChangeKind::InvalidateAllDecompilations ? Json(nullptr) : Json(HexAddress(operation.address))},
          {"value",operation.value}, {"expected",operation.expected ? Json(*operation.expected) : Json(nullptr)}, {"repeatable",operation.repeatable},
          {"offset",operation.offset ? Json(*operation.offset) : Json(nullptr)}, {"size",operation.size ? Json(*operation.size) : Json(nullptr)}, {"subject",operation.subject ? Json(*operation.subject) : Json(nullptr)}};
}

Json Payload(AgentEffectName effect, Json values)
{
  values["version"] = 1;
  values["effect"] = Name(effect);
  return values;
}

Json OwnedPayload(AgentEffectName effect, const std::string &payload, std::initializer_list<const char *> fields)
{
  Json value = Json::parse(payload.begin(), payload.end(), nullptr, true, false);
  if ( !value.is_object() || value.size() != fields.size() + 2 || !value.contains("version") || value["version"] != 1
    || !value.contains("effect") || !value["effect"].is_string() || value["effect"] != Name(effect) ) throw std::invalid_argument("payload");
  for ( const char *field : fields ) if ( !value.contains(field) ) throw std::invalid_argument("payload");
  return value;
}

std::string SafeText(std::string_view value, std::size_t maximum = 64)
{
  std::string result;
  for ( unsigned char ch : value )
  {
    if ( result.size() >= maximum ) break;
    result.push_back(ch >= 0x20 && ch < 0x7F ? static_cast<char>(ch) : '?');
  }
  if ( value.size() > maximum ) result += "...";
  return result;
}

const char *ChangeMessage(services::ChangeStatus status)
{
  switch ( status )
  {
    case services::ChangeStatus::InvalidAddress:return "The change set contains an invalid address.";
    case services::ChangeStatus::InvalidArgument:return "The change set is invalid.";
    case services::ChangeStatus::Conflict:return "The change set conflicts with the current database state.";
    case services::ChangeStatus::NotFound:return "The requested change set was not found.";
    case services::ChangeStatus::CapabilityUnavailable:return "A required IDA capability is unavailable.";
    case services::ChangeStatus::Failed:return "IDA rejected the change set.";
    case services::ChangeStatus::OutputLimit:return "The change set result exceeded the safe output limit.";
    case services::ChangeStatus::Success:return "";
  }
  return "The change set failed.";
}

const char *DebuggerMessage(services::DebuggerStatus status)
{
  switch ( status )
  {
    case services::DebuggerStatus::Unavailable:return "The debugger is unavailable.";
    case services::DebuggerStatus::AlreadyRunning:return "The debugger is already running.";
    case services::DebuggerStatus::NotRunning:return "The debugger is not running.";
    case services::DebuggerStatus::NotSuspended:return "The debugger is not suspended.";
    case services::DebuggerStatus::InvalidAddress:return "The debugger address is invalid.";
    case services::DebuggerStatus::InvalidArgument:return "The debugger request is invalid.";
    case services::DebuggerStatus::NotFound:return "The debugger object was not found.";
    case services::DebuggerStatus::Failed:return "The debugger rejected the request.";
    case services::DebuggerStatus::StateUncertain:return "The debugger state may have changed.";
    case services::DebuggerStatus::OutputLimit:return "The debugger result exceeded the safe output limit.";
    case services::DebuggerStatus::Success:return "";
  }
  return "The debugger request failed.";
}

Json ApplyJson(const services::ChangeApplyResult &result)
{
  Json items = Json::array();
  for ( const auto &item : result.items ) items.push_back({{"index",item.index},{"applied",item.applied},{"error",item.error ? Json(*item.error) : Json(nullptr)}});
  return {{"changeId",result.change_id},{"items",std::move(items)},{"applied",result.applied}};
}

Json DebuggerJson(const services::DebuggerAction &result)
{
  return {{"accepted",result.accepted},{"state",result.state},{"running",result.running},{"suspended",result.suspended},
          {"instructionPointer",result.instruction_pointer ? Json(HexAddress(*result.instruction_pointer)) : Json(nullptr)},
          {"threadId",result.thread_id ? Json(*result.thread_id) : Json(nullptr)}};
}

AgentToolResult ChangeResult(const AgentToolCall &call, services::ApplyOutcome outcome)
{
  if ( outcome.status != services::ChangeStatus::Success ) return Failure(call, ChangeMessage(outcome.status));
  if ( !outcome.result || !outcome.result->applied ) return Failure(call, "IDA did not apply the requested change set.");
  return Success(call, ApplyJson(*outcome.result));
}

AgentToolResult DebuggerResult(const AgentToolCall &call, services::DebuggerActionOutcome outcome)
{
  if ( outcome.status == services::DebuggerStatus::StateUncertain ) throw AgentEffectStateUncertain();
  if ( outcome.status != services::DebuggerStatus::Success ) return Failure(call, DebuggerMessage(outcome.status));
  if ( !outcome.result ) return Failure(call, "The debugger result is unavailable.");
  return Success(call, DebuggerJson(*outcome.result));
}

template <typename Operation, typename Convert>
AgentToolResult Write(const AgentToolCall &call, Operation operation, Convert convert)
{
  try { return convert(operation()); }
  catch ( const AgentEffectStateUncertain & ) { throw; }
#ifndef IDA_AGENT_AGENT_EFFECT_SERVICE_TESTING
  catch ( const bridge::IdaBusyError & ) { return Failure(call, "IDA is busy; the side effect was not started."); }
  catch ( const bridge::IdaTimeoutError & ) { return Failure(call, "The side effect timed out before it started."); }
#endif
  catch ( ... ) { throw AgentEffectStateUncertain(); }
}

std::optional<services::BreakpointMutation> Breakpoint(const Json &value, std::string *action, std::uint64_t *address)
{
  if ( !Fields(value,{"action","address","enabled","condition","type","size","language","lowLevel","passCount"})
    || !value["action"].is_string() ) return std::nullopt;
  *action = value["action"].get<std::string>();
  if ( *action!="add" && *action!="delete" && *action!="toggle" && *action!="condition" ) return std::nullopt;
  const auto parsed_address = Address(value["address"]); if ( !parsed_address ) return std::nullopt; *address = *parsed_address;
  services::BreakpointMutation result;
  if ( !value["enabled"].is_null() ) { if ( !value["enabled"].is_boolean() ) return std::nullopt; result.enabled=value["enabled"].get<bool>(); }
  if ( !value["condition"].is_null() ) { if ( !value["condition"].is_string() ) return std::nullopt; result.condition=value["condition"].get<std::string>(); if ( result.condition->size()>4096 || result.condition->find('\0')!=std::string::npos || !ValidUtf8(*result.condition) ) return std::nullopt; }
  if ( !value["type"].is_null() ) { if ( !value["type"].is_string() ) return std::nullopt; result.type=value["type"].get<std::string>(); if ( *result.type!="software" && *result.type!="hardware" ) return std::nullopt; }
  if ( !value["size"].is_null() ) { if ( !value["size"].is_number_unsigned() || value["size"].get<std::uint64_t>()>8 ) return std::nullopt; result.size=static_cast<std::uint32_t>(value["size"].get<std::uint64_t>()); }
  if ( !value["language"].is_null() ) { if ( !value["language"].is_string() ) return std::nullopt; result.language=value["language"].get<std::string>(); if ( result.language->empty() || result.language->size()>128 || result.language->find('\0')!=std::string::npos || !ValidUtf8(*result.language) ) return std::nullopt; }
  if ( !value["lowLevel"].is_null() ) { if ( !value["lowLevel"].is_boolean() ) return std::nullopt; result.low_level=value["lowLevel"].get<bool>(); }
  if ( !value["passCount"].is_null() ) { if ( !value["passCount"].is_number_unsigned() || value["passCount"].get<std::uint64_t>()>static_cast<std::uint64_t>((std::numeric_limits<int>::max)()) ) return std::nullopt; result.pass_count=static_cast<std::uint32_t>(value["passCount"].get<std::uint64_t>()); }
  const bool empty = !result.enabled&&!result.condition&&!result.type&&!result.size&&!result.language&&!result.low_level&&!result.pass_count;
  if ( *action=="add" ) { if ( result.enabled||result.condition||result.language||result.low_level||result.pass_count ) return std::nullopt; const std::string type=result.type.value_or("software"); const auto size=result.size.value_or(type=="hardware"?1U:0U); if ( (type=="software"&&size>1) || (type=="hardware"&&size!=1&&size!=2&&size!=4&&size!=8) ) return std::nullopt; }
  else if ( *action=="delete" ) { if ( !empty ) return std::nullopt; }
  else if ( *action=="toggle" ) { if ( !result.enabled||result.condition||result.type||result.size||result.language||result.low_level||result.pass_count ) return std::nullopt; }
  else if ( result.enabled||result.type||result.size||(!result.condition&&!result.language&&!result.low_level&&!result.pass_count) ) return std::nullopt;
  return result;
}

std::optional<std::string> DebuggerState(
    const AgentEffectServiceCallbacks &callbacks,
    std::string *failure)
{
  const auto outcome = callbacks.debugger_info();
  if ( outcome.status != services::DebuggerStatus::Success )
  {
    *failure = DebuggerMessage(outcome.status);
    return std::nullopt;
  }
  if ( !outcome.result )
  {
    *failure = "The debugger state is unavailable.";
    return std::nullopt;
  }
  return SafeText(outcome.result->state, 32);
}
} // namespace

namespace
{

AgentEffectPreparation PrepareChangeSet(
    const AgentEffectServiceCallbacks &callbacks,
    AgentEffectName effect,
    const AgentToolCall &,
    const Json &arguments)
{
  Json payload;
  std::ostringstream summary;
  if ( effect == AgentEffectName::ChangeSetApply )
  {
    const auto operations = Operations(arguments);
    if ( !operations ) return PreparationFailure("The change-set request is invalid.");
    const auto preview = callbacks.changeset_preview(*operations);
    if ( preview.status != services::ChangeStatus::Success ) return PreparationFailure(ChangeMessage(preview.status));
    if ( !preview.result || preview.result->preview_id.empty() || preview.result->preview_id.size() > 128
      || !preview.result->applicable || preview.result->items.size() != operations->size()
      || std::any_of(preview.result->items.begin(), preview.result->items.end(), [](const auto &item) { return item.conflict; }) )
      return PreparationFailure("The change set is not safely applicable.");
    Json encoded = Json::array();
    for ( const auto &operation : *operations ) encoded.push_back(OperationJson(operation));
    payload = Payload(effect, {{"previewId",preview.result->preview_id},{"operations",std::move(encoded)}});
    summary << "Apply " << operations->size() << " database operation(s).";
    for ( std::size_t index = 0; index < preview.result->items.size(); ++index )
    {
      const auto &item = preview.result->items[index];
      const auto kind = (*operations)[index].kind;
      summary << " [" << item.index << " " << ChangeKindName(kind);
      if ( kind != services::ChangeKind::DeclareType
          && kind != services::ChangeKind::EnumUpsert
          && kind != services::ChangeKind::InvalidateAllDecompilations )
      {
        summary << " @ " << HexAddress((*operations)[index].address);
      }
      if ( kind == services::ChangeKind::PatchBytes || kind == services::ChangeKind::PatchInteger )
        summary << ": bytes redacted; payload SHA-256 " << AgentEffectSha256((*operations)[index].value) << "]";
      else summary << ": " << SafeText(item.before) << " -> " << SafeText(item.after) << "]";
    }
  }
  else
  {
    if ( !Fields(arguments,{"changeId"}) || !arguments["changeId"].is_string() ) return PreparationFailure("The rollback request is invalid.");
    const std::string id = arguments["changeId"].get<std::string>();
    if ( id.empty() || id.size() > 256 ) return PreparationFailure("The rollback request is invalid.");
    payload = Payload(effect, {{"changeId",id}});
    summary << "Roll back change ID prefix " << SafeText(id, 8) << ".";
  }
  return {payload.dump(), summary.str()};
}

AgentEffectPreparation PrepareSaveAnalysis(
    const AgentEffectServiceCallbacks &,
    AgentEffectName effect,
    const AgentToolCall &,
    const Json &arguments)
{
  Json payload;
  std::ostringstream summary;
  if ( effect == AgentEffectName::DatabaseSave )
  {
    if ( !Fields(arguments,{"compact","backup"}) || !arguments["compact"].is_boolean() || !arguments["backup"].is_boolean() ) return PreparationFailure("The database-save request is invalid.");
    const bool compact = arguments["compact"].get<bool>(), backup = arguments["backup"].get<bool>();
    payload = Payload(effect, {{"compact",compact},{"backup",backup}});
    summary << "Save the current database" << (compact ? " with compaction" : " without compaction") << (backup ? " and create a backup." : " without creating a backup.");
  }
  else
  {
    if ( !Fields(arguments,{"start","end"}) ) return PreparationFailure("The analysis-plan request is invalid.");
    const auto start = Address(arguments["start"]), end = Address(arguments["end"]);
    if ( !start || !end || *start >= *end || *end - *start > 16ULL*1024*1024 ) return PreparationFailure("The analysis range is invalid.");
    payload = Payload(effect, {{"start",HexAddress(*start)},{"end",HexAddress(*end)}});
    summary << "Queue IDA analysis for " << HexAddress(*start) << " through " << HexAddress(*end) << ".";
  }
  return {payload.dump(), summary.str()};
}

bool IsDebuggerSetup(AgentEffectName effect)
{
  return effect == AgentEffectName::DebuggerSelect || effect == AgentEffectName::DebuggerConfigure
      || effect == AgentEffectName::DebuggerAttach || effect == AgentEffectName::DebuggerDetach
      || effect == AgentEffectName::DebuggerSuspend;
}

bool ValidDebuggerSetup(AgentEffectName effect, const Json &args)
{
  if ( effect == AgentEffectName::DebuggerSelect ) return services::ParseDebuggerSelect(args).has_value();
  if ( effect == AgentEffectName::DebuggerConfigure ) return services::ParseDebuggerConfigure(args).has_value();
  if ( effect == AgentEffectName::DebuggerAttach ) return services::ParseDebuggerAttach(args).has_value();
  return Fields(args, {});
}

AgentEffectPreparation PrepareDebuggerSetup(const AgentEffectServiceCallbacks &callbacks, AgentEffectName effect, Json arguments)
{
  // Provider strict schemas use null for omitted configuration options. Only
  // this boundary removes known null fields; the Internal RPC rejects null.
  if ( effect == AgentEffectName::DebuggerConfigure )
  {
    if ( !services::DebuggerSetupFields(arguments, {"path", "arguments", "directory", "host", "port", "password"}) )
      return PreparationFailure("The debugger configuration is invalid.");
    for ( auto it = arguments.begin(); it != arguments.end(); )
      if ( it.value().is_null() ) it = arguments.erase(it); else ++it;
  }
  if ( !ValidDebuggerSetup(effect, arguments) ) return PreparationFailure("The debugger setup request is invalid.");
  if ( !callbacks.debugger_info ) return PreparationFailure("Debugger state is unavailable.");
  const auto info = callbacks.debugger_info();
  const bool bootstrap = effect == AgentEffectName::DebuggerSelect || effect == AgentEffectName::DebuggerConfigure;
  if ( info.status != services::DebuggerStatus::Success && !(bootstrap && info.status == services::DebuggerStatus::Unavailable) )
    return PreparationFailure("The debugger is unavailable.");
  if ( info.status == services::DebuggerStatus::Success && !info.result ) return PreparationFailure("Debugger state is unavailable.");
  const std::string state = info.result ? info.result->state : "not_running";
  if ( state != "not_running" && state != "running" && state != "suspended" ) return PreparationFailure("Debugger state is unknown.");
  const char *action = effect == AgentEffectName::DebuggerSuspend ? "suspend" : effect == AgentEffectName::DebuggerDetach ? "detach" : "setup";
  if ( !services::DebuggerSetupStateAllows(action, state != "not_running", state == "suspended") )
    return PreparationFailure("The current process state does not permit this debugger operation.");
  std::ostringstream summary;
  summary << Name(effect) << ". Current state: " << state << ".";
  if ( effect == AgentEffectName::DebuggerSelect )
    summary << " Backend: " << SafeText(arguments["name"].get<std::string>(), 128) << "; remote: " << arguments.value("remote", false) << ".";
  else if ( effect == AgentEffectName::DebuggerAttach ) summary << " PID: " << arguments["pid"].get<int>() << ".";
  else if ( effect == AgentEffectName::DebuggerConfigure )
    for ( auto it = arguments.begin(); it != arguments.end(); ++it )
    {
      summary << " " << it.key() << ": ";
      if ( it.key() == "password" ) summary << (it.value().get_ref<const std::string &>().empty() ? "clear" : "replace (hidden)");
      else summary << SafeText(it.value().dump(), 256);
      summary << ".";
    }
  return {Payload(effect, {{"params", arguments}}).dump(), summary.str()};
}

AgentToolResult ExecuteDebuggerSetup(const AgentEffectServiceCallbacks &callbacks, AgentEffectName effect,
    const AgentToolCall &call, const std::string &payload)
{
  const auto saved = OwnedPayload(effect, payload, {"params"});
  const auto &params = saved["params"];
  if ( !ValidDebuggerSetup(effect, params) ) return Failure(call, "The prepared debugger setup is invalid.");
  const auto convert = [&](auto outcome) { return DebuggerResult(call, std::move(outcome)); };
  switch ( effect )
  {
    case AgentEffectName::DebuggerSelect:
      if ( !callbacks.debugger_select ) break;
      return Write(call, [&]() { return callbacks.debugger_select(*services::ParseDebuggerSelect(params)); }, convert);
    case AgentEffectName::DebuggerConfigure:
      if ( !callbacks.debugger_configure ) break;
      return Write(call, [&]() { return callbacks.debugger_configure(*services::ParseDebuggerConfigure(params)); }, convert);
    case AgentEffectName::DebuggerAttach:
      if ( !callbacks.debugger_attach ) break;
      return Write(call, [&]() { return callbacks.debugger_attach(*services::ParseDebuggerAttach(params)); }, convert);
    case AgentEffectName::DebuggerDetach:
      if ( !callbacks.debugger_detach ) break;
      return Write(call, [&]() { return callbacks.debugger_detach(); }, convert);
    case AgentEffectName::DebuggerSuspend:
      if ( !callbacks.debugger_suspend ) break;
      return Write(call, [&]() { return callbacks.debugger_suspend(); }, convert);
    default: break;
  }
  return Failure(call, "The debugger operation is unavailable.");
}

AgentEffectPreparation PrepareDebugger(
    const AgentEffectServiceCallbacks &callbacks,
    AgentEffectName effect,
    const AgentToolCall &,
    const Json &arguments)
{
  Json payload;
  std::ostringstream summary;
  std::string failure;
  if ( effect == AgentEffectName::DebuggerStart || effect == AgentEffectName::DebuggerExit )
  {
    if ( !Fields(arguments,{}) ) return PreparationFailure("The debugger request is invalid.");
    const auto state = DebuggerState(callbacks, &failure); if ( !state ) return PreparationFailure(std::move(failure));
    payload = Payload(effect, Json::object());
    summary << (effect == AgentEffectName::DebuggerStart ? "Start" : "Exit") << " the debugger. Current state: " << *state << ".";
  }
  else if ( effect == AgentEffectName::DebuggerControl )
  {
    if ( !Fields(arguments,{"action","address"}) || !arguments["action"].is_string() ) return PreparationFailure("The debugger-control request is invalid.");
    const std::string action = arguments["action"].get<std::string>(); const bool run_to = action == "run_to";
    if ( action != "continue" && action != "step_into" && action != "step_over" && action != "step_until_return" && !run_to ) return PreparationFailure("The debugger-control request is invalid.");
    std::optional<std::uint64_t> address; if ( !arguments["address"].is_null() ) address = Address(arguments["address"]);
    if ( run_to != address.has_value() ) return PreparationFailure("The debugger-control request is invalid.");
    const auto state = DebuggerState(callbacks, &failure); if ( !state ) return PreparationFailure(std::move(failure));
    payload = Payload(effect, {{"action",action},{"address",address ? Json(HexAddress(*address)) : Json(nullptr)}});
    summary << "Debugger action " << action; if ( address ) summary << " at " << HexAddress(*address); summary << ". Current state: " << *state << ".";
  }
  else if ( effect == AgentEffectName::DebuggerBreakpoint )
  {
    std::string action; std::uint64_t address = 0; const auto mutation = Breakpoint(arguments, &action, &address);
    if ( !mutation ) return PreparationFailure("The breakpoint request is invalid.");
    const auto state = DebuggerState(callbacks, &failure); if ( !state ) return PreparationFailure(std::move(failure));
    payload = Payload(effect, arguments);
    summary << "Breakpoint action " << action << " at " << HexAddress(address) << ". Condition text is not displayed. Current state: " << *state << ".";
  }
  else
  {
    if ( !Fields(arguments,{"address","bytes"}) ) return PreparationFailure("The debugger-memory request is invalid.");
    const auto address = Address(arguments["address"]); const auto bytes = HexBytes(arguments["bytes"]);
    if ( !address || !bytes ) return PreparationFailure("The debugger-memory request is invalid.");
    const auto state = DebuggerState(callbacks, &failure); if ( !state ) return PreparationFailure(std::move(failure));
    payload = Payload(effect, {{"address",HexAddress(*address)},{"bytes",*bytes}});
    summary << "Write " << bytes->size()/2 << " byte(s) to debugged memory at " << HexAddress(*address) << ". SHA-256: " << AgentEffectSha256(*bytes) << ". Raw bytes are not displayed. Current state: " << *state << ".";
  }
  return {payload.dump(), summary.str()};
}

AgentToolResult ExecuteChangeSet(const AgentEffectServiceCallbacks &callbacks, AgentEffectName effect, const AgentToolCall &call, const std::string &payload)
{
  if ( effect == AgentEffectName::ChangeSetApply )
  {
    const Json saved = OwnedPayload(effect,payload,{"previewId","operations"}); if ( !saved["previewId"].is_string() ) return Failure(call,"The prepared change set is invalid.");
    const std::string preview = saved["previewId"].get<std::string>(); const auto operations = Operations(Json{{"operations",saved["operations"]}}); if ( preview.empty() || preview.size() > 128 || !operations ) return Failure(call,"The prepared change set is invalid.");
    return Write(call,[&](){return callbacks.changeset_apply(preview,*operations,LocalSession);},[&](auto outcome){return ChangeResult(call,std::move(outcome));});
  }
  const Json saved = OwnedPayload(effect,payload,{"changeId"}); if ( !saved["changeId"].is_string() ) return Failure(call,"The prepared rollback is invalid.");
  const std::string id = saved["changeId"].get<std::string>(); if ( id.empty() || id.size() > 256 ) return Failure(call,"The prepared rollback is invalid.");
  return Write(call,[&](){return callbacks.changeset_rollback(id,LocalSession);},[&](auto outcome){return ChangeResult(call,std::move(outcome));});
}

AgentToolResult ExecuteSaveAnalysis(const AgentEffectServiceCallbacks &callbacks, AgentEffectName effect, const AgentToolCall &call, const std::string &payload)
{
  if ( effect == AgentEffectName::DatabaseSave )
  {
    const Json saved = OwnedPayload(effect,payload,{"compact","backup"}); if ( !saved["compact"].is_boolean() || !saved["backup"].is_boolean() ) return Failure(call,"The prepared database save is invalid.");
    return Write(call,[&](){return callbacks.database_save(saved["compact"].get<bool>(),saved["backup"].get<bool>());},[&](services::DatabaseSaveOutcome outcome){if(outcome.status==services::DatabaseSaveStatus::InvalidArgument)return Failure(call,"The database-save request is invalid.");if(outcome.status!=services::DatabaseSaveStatus::Success)return Failure(call,"IDA could not save the database.");if(!outcome.result||outcome.result->explicit_target)return Failure(call,"The database-save result is invalid.");return Success(call,{{"saved",true},{"explicitTarget",false}});});
  }
  const Json saved = OwnedPayload(effect,payload,{"start","end"}); const auto start = Address(saved["start"]), end = Address(saved["end"]); if ( !start || !end || *start >= *end || *end-*start > 16ULL*1024*1024 ) return Failure(call,"The prepared analysis plan is invalid.");
  return Write(call,[&](){return callbacks.analysis_plan(*start,*end);},[&](services::ReadonlyResult result){if(result.status==services::ReadonlyStatus::InvalidAddress)return Failure(call,"The analysis range is invalid.");if(result.status==services::ReadonlyStatus::NotFound)return Failure(call,"The analysis target was not found.");if(result.status==services::ReadonlyStatus::OutputLimit)return Failure(call,"The analysis result exceeded the safe output limit.");return Success(call,std::move(result.value));});
}

AgentToolResult ExecuteDebugger(const AgentEffectServiceCallbacks &callbacks, AgentEffectName effect, const AgentToolCall &call, const std::string &payload)
{
  if ( effect == AgentEffectName::DebuggerStart || effect == AgentEffectName::DebuggerExit )
  {
    static_cast<void>(OwnedPayload(effect,payload,{}));
    return Write(call,[&](){return effect==AgentEffectName::DebuggerStart?callbacks.debugger_start():callbacks.debugger_exit();},[&](auto outcome){return DebuggerResult(call,std::move(outcome));});
  }
  if ( effect == AgentEffectName::DebuggerControl )
  {
    const Json saved = OwnedPayload(effect,payload,{"action","address"}); if ( !saved["action"].is_string() ) return Failure(call,"The prepared debugger action is invalid."); const std::string action = saved["action"].get<std::string>(); std::optional<std::uint64_t> address; if ( !saved["address"].is_null() ) address = Address(saved["address"]); if ( (action=="run_to") != address.has_value() || (action!="continue"&&action!="step_into"&&action!="step_over"&&action!="step_until_return"&&action!="run_to") ) return Failure(call,"The prepared debugger action is invalid.");
    return Write(call,[&](){return callbacks.debugger_control(action,address);},[&](auto outcome){return DebuggerResult(call,std::move(outcome));});
  }
  if ( effect == AgentEffectName::DebuggerBreakpoint )
  {
    Json saved = OwnedPayload(effect,payload,{"action","address","enabled","condition","type","size","language","lowLevel","passCount"}); saved.erase("version"); saved.erase("effect"); std::string action; std::uint64_t address=0; const auto mutation=Breakpoint(saved,&action,&address); if ( !mutation ) return Failure(call,"The prepared breakpoint mutation is invalid.");
    return Write(call,[&](){return callbacks.debugger_breakpoint(action,address,*mutation);},[&](auto outcome){return DebuggerResult(call,std::move(outcome));});
  }
  const Json saved = OwnedPayload(effect,payload,{"address","bytes"}); const auto address=Address(saved["address"]); const auto bytes=HexBytes(saved["bytes"]); if ( !address || !bytes ) return Failure(call,"The prepared debugger-memory write is invalid.");
  return Write(call,[&](){return callbacks.debugger_memory_write(*address,*bytes);},[&](auto outcome){return DebuggerResult(call,std::move(outcome));});
}

} // namespace

namespace agent_effect_service_operations
{

const char *Name(AgentEffectName effect) noexcept
{
  return ::ida_agent::ai::Name(effect);
}

AgentEffectPreparation Prepare(
    const AgentEffectServiceCallbacks &callbacks,
    AgentEffectName effect,
    const AgentToolCall &call)
{
  const Json arguments = Json::parse(call.arguments_json.begin(), call.arguments_json.end(), nullptr, true, false);
  if ( IsDebuggerSetup(effect) ) return PrepareDebuggerSetup(callbacks, effect, arguments);
  if ( effect == AgentEffectName::ChangeSetApply || effect == AgentEffectName::ChangeSetRollback ) return PrepareChangeSet(callbacks, effect, call, arguments);
  if ( effect == AgentEffectName::DatabaseSave || effect == AgentEffectName::AnalysisPlan ) return PrepareSaveAnalysis(callbacks, effect, call, arguments);
  if ( effect == AgentEffectName::DebuggerStart || effect == AgentEffectName::DebuggerExit || effect == AgentEffectName::DebuggerControl || effect == AgentEffectName::DebuggerBreakpoint || effect == AgentEffectName::DebuggerMemoryWrite ) return PrepareDebugger(callbacks, effect, call, arguments);
  return agent_effect_file_operations::Prepare(callbacks, effect, call, arguments);
}

AgentToolResult Execute(
    const AgentEffectServiceCallbacks &callbacks,
    AgentEffectName effect,
    const AgentToolCall &call,
    const std::string &payload)
{
  if ( IsDebuggerSetup(effect) ) return ExecuteDebuggerSetup(callbacks, effect, call, payload);
  if ( effect == AgentEffectName::ChangeSetApply || effect == AgentEffectName::ChangeSetRollback ) return ExecuteChangeSet(callbacks, effect, call, payload);
  if ( effect == AgentEffectName::DatabaseSave || effect == AgentEffectName::AnalysisPlan ) return ExecuteSaveAnalysis(callbacks, effect, call, payload);
  if ( effect == AgentEffectName::DebuggerStart || effect == AgentEffectName::DebuggerExit || effect == AgentEffectName::DebuggerControl || effect == AgentEffectName::DebuggerBreakpoint || effect == AgentEffectName::DebuggerMemoryWrite ) return ExecuteDebugger(callbacks, effect, call, payload);
  return agent_effect_file_operations::Execute(callbacks, effect, call, payload);
}

} // namespace agent_effect_service_operations
} // namespace ida_agent::ai
