#include "ai/agent_effect_coordinator.hpp"

#include <algorithm>
#include <climits>
#include <limits>
#include <stdexcept>
#include <utility>

namespace ida_agent::ai
{
namespace
{

struct EffectDescriptor
{
  AgentEffectName name;
  AgentEffectRisk risk;
};

std::optional<EffectDescriptor> Classify(const AgentToolCall &call)
{
  if ( call.name == "ida_changeset_apply" ) return EffectDescriptor{AgentEffectName::ChangeSetApply, AgentEffectRisk::High};
  if ( call.name == "ida_changeset_rollback" ) return EffectDescriptor{AgentEffectName::ChangeSetRollback, AgentEffectRisk::High};
  if ( call.name == "ida_database_save" ) return EffectDescriptor{AgentEffectName::DatabaseSave, AgentEffectRisk::Medium};
  if ( call.name == "ida_analysis_plan" ) return EffectDescriptor{AgentEffectName::AnalysisPlan, AgentEffectRisk::Medium};
  if ( call.name == "ida_debugger_select" ) return EffectDescriptor{AgentEffectName::DebuggerSelect, AgentEffectRisk::High};
  if ( call.name == "ida_debugger_configure" ) return EffectDescriptor{AgentEffectName::DebuggerConfigure, AgentEffectRisk::High};
  if ( call.name == "ida_debugger_attach" ) return EffectDescriptor{AgentEffectName::DebuggerAttach, AgentEffectRisk::High};
  if ( call.name == "ida_debugger_detach" ) return EffectDescriptor{AgentEffectName::DebuggerDetach, AgentEffectRisk::High};
  if ( call.name == "ida_debugger_suspend" ) return EffectDescriptor{AgentEffectName::DebuggerSuspend, AgentEffectRisk::High};
  if ( call.name == "ida_debugger_start" ) return EffectDescriptor{AgentEffectName::DebuggerStart, AgentEffectRisk::High};
  if ( call.name == "ida_debugger_exit" ) return EffectDescriptor{AgentEffectName::DebuggerExit, AgentEffectRisk::High};
  if ( call.name == "ida_debugger_control" ) return EffectDescriptor{AgentEffectName::DebuggerControl, AgentEffectRisk::High};
  if ( call.name == "ida_debugger_breakpoint_mutate" ) return EffectDescriptor{AgentEffectName::DebuggerBreakpoint, AgentEffectRisk::High};
  if ( call.name == "ida_debugger_memory_write" ) return EffectDescriptor{AgentEffectName::DebuggerMemoryWrite, AgentEffectRisk::Critical};
  if ( call.name == "ida_file_mutate" ) return EffectDescriptor{AgentEffectName::FileMutate, AgentEffectRisk::High};
  if ( call.name == "ida_script_execute_file" ) return EffectDescriptor{AgentEffectName::ScriptExecuteFile, AgentEffectRisk::Critical};
  return std::nullopt;
}

using Json = nlohmann::json;

Json Nullable(const char *type, Json extra = Json::object())
{
  extra["type"] = Json::array({type, "null"});
  extra["default"] = nullptr;
  return extra;
}

Json Address(bool nullable = false)
{
  Json result{{"pattern", "^0x[0-9A-Fa-f]{1,16}$"}};
  if ( nullable ) return Nullable("string", std::move(result));
  result["type"] = "string";
  result["default"] = "0x0";
  return result;
}

Json Enum(std::initializer_list<const char *> values, const char *value)
{
  Json items = Json::array();
  for ( const char *item : values ) items.push_back(item);
  return {{"type", "string"}, {"enum", std::move(items)}, {"default", value}};
}

Json Strict(std::initializer_list<std::pair<const char *, Json>> fields)
{
  Json properties = Json::object(), required = Json::array();
  for ( const auto &field : fields )
  {
    properties[field.first] = field.second;
    required.push_back(field.first);
  }
  return {{"type", "object"}, {"additionalProperties", false},
          {"properties", std::move(properties)}, {"required", std::move(required)}};
}

AgentToolDefinition Tool(const char *name, const char *description, Json parameters)
{
  return {name, description, std::move(parameters)};
}

AgentToolResult SafeResult(
    const AgentToolCall *call,
    const char *message)
{
  AgentToolResult result;
  if ( call != nullptr )
  {
    result.call_id = call->id;
    result.name = call->name;
  }
  result.safe_message = message;
  return result;
}

} // namespace

const std::vector<AgentToolDefinition> &AgentEffectToolDefinitions()
{
  static const Json kinds = Json::array({
      "rename", "comment.set", "comment.append", "comment.pseudocode", "bookmark.add",
      "type.apply", "patch.bytes", "patch.integer", "define.function", "define.code",
      "undefine", "decompiler.invalidate", "define.data", "operand.hex", "operand.decimal",
      "operand.character", "operand.binary", "operand.octal", "operand.offset",
      "operand.struct_offset", "operand.stack_variable", "type.declare", "enum.upsert",
      "decompiler.invalidate_all", "stack.declare", "stack.delete", "local.rename",
      "local.type", "segment.rename", "segment.permissions", "xref.code.add",
      "xref.code.delete", "xref.data.add", "xref.data.delete", "function.flags",
      "function.end", "function.chunk.add", "function.chunk.delete"});
  static const Json operation = Strict({
      {"kind", {{"type", "string"}, {"enum", kinds}, {"default", "rename"}}},
      {"address", Address(true)},
      {"value", {{"type", "string"}, {"maxLength", 65536}, {"default", ""}}},
      {"expected", Nullable("string", {{"maxLength", 65536}})},
      {"repeatable", {{"type", "boolean"}, {"default", false}}},
      {"offset", Nullable("integer", {{"minimum", (std::numeric_limits<std::int64_t>::min)()},
                                        {"maximum", (std::numeric_limits<std::int64_t>::max)()}})},
      {"size", Nullable("integer", {{"minimum", 1}, {"maximum", UINT_MAX}})},
      {"subject", Nullable("string", {{"minLength", 1}, {"maxLength", 1024}})},
  });
  static const std::vector<AgentToolDefinition> definitions{
      Tool("ida_changeset_apply", "Prepare fixed database change operations under the conversation session side-effect policy.",
           Strict({{"operations", {{"type", "array"}, {"items", operation}, {"minItems", 1}, {"maxItems", 100}}}})),
      Tool("ida_changeset_rollback", "Roll back a known change set under the conversation session side-effect policy.",
           Strict({{"changeId", {{"type", "string"}, {"minLength", 1}, {"maxLength", 256}, {"default", ""}}}})),
      Tool("ida_database_save", "Save the current database under the conversation session side-effect policy without a caller-selected target.",
           Strict({{"compact", {{"type", "boolean"}, {"default", false}}}, {"backup", {{"type", "boolean"}, {"default", true}}}})),
      Tool("ida_analysis_plan", "Queue analysis for a bounded range under the conversation session side-effect policy.",
           Strict({{"start", Address()}, {"end", Address()}})),
      Tool("ida_debugger_select", "Select a debugger name and mode from ida_debugger_backends while idle, under the conversation side-effect policy.",
           Strict({{"name", {{"type", "string"}, {"minLength", 1}, {"maxLength", 128}, {"default", ""}}}, {"remote", {{"type", "boolean"}, {"default", false}}}})),
      Tool("ida_debugger_configure", "Update launch or remote options while idle under the conversation side-effect policy. Null preserves a field; an empty string clears it. Supply at least one non-null field. Password is never displayed in the approval summary or result.",
           Strict({{"path", Nullable("string", {{"maxLength", 32768}})}, {"arguments", Nullable("string", {{"maxLength", 32768}})},
                   {"directory", Nullable("string", {{"maxLength", 32768}})}, {"host", Nullable("string", {{"maxLength", 1024}})},
                   {"port", Nullable("integer", {{"minimum", -1}, {"maximum", 65535}, {"not", {{"const", 0}}}})},
                   {"password", Nullable("string", {{"maxLength", 4096}})}})),
      Tool("ida_debugger_attach", "Request attachment to an explicit PID while idle under the conversation side-effect policy.",
           Strict({{"pid", {{"type", "integer"}, {"minimum", 1}, {"maximum", INT_MAX}, {"default", 1}}}})),
      Tool("ida_debugger_detach", "Detach a suspended debuggee without terminating it under the conversation side-effect policy.", Strict({})),
      Tool("ida_debugger_suspend", "Request pause of a running debuggee under the conversation side-effect policy.", Strict({})),
      Tool("ida_debugger_start", "Start the configured debugger under the conversation session side-effect policy.", Strict({})),
      Tool("ida_debugger_exit", "Exit the active debugger under the conversation session side-effect policy.", Strict({})),
      Tool("ida_debugger_control", "Perform a fixed debugger control action under the conversation session side-effect policy.",
           Strict({{"action", Enum({"continue", "step_into", "step_over", "step_until_return", "run_to"}, "continue")},
                   {"address", Address(true)}})),
      Tool("ida_debugger_breakpoint_mutate", "Perform a fixed breakpoint mutation under the conversation session side-effect policy.",
           Strict({{"action", Enum({"add", "delete", "toggle", "condition"}, "add")}, {"address", Address()},
                   {"enabled", Nullable("boolean")}, {"condition", Nullable("string", {{"maxLength", 4096}})},
                   {"type", Nullable("string", {{"enum", Json::array({Json("software"), Json("hardware"), Json(nullptr)})}})},
                   {"size", Nullable("integer", {{"minimum", 0}, {"maximum", 8}})},
                   {"language", Nullable("string", {{"minLength", 1}, {"maxLength", 128}})},
                   {"lowLevel", Nullable("boolean")},
                   {"passCount", Nullable("integer", {{"minimum", 0}, {"maximum", INT_MAX}})}})),
      Tool("ida_debugger_memory_write", "Write bounded hexadecimal bytes to debugged memory under the conversation session side-effect policy.",
            Strict({{"address", Address()}, {"bytes", {{"type", "string"}, {"pattern", "^[0-9A-Fa-f]+$"},
                                                        {"minLength", 2}, {"maxLength", 131072}, {"default", ""}}}})),
      Tool("ida_file_mutate", "Prepare one restricted UTF-8 text-file, directory, or recursive-directory-deletion mutation under the current IDB directory and conversation session policy.",
           Strict({{"path", {{"type", "string"}, {"minLength", 1}, {"maxLength", 1024}, {"default", ""}}},
                   {"mode", Enum({"overwrite", "append", "create_file", "create_directory", "delete_file", "delete_directory"}, "overwrite")},
                   {"content", {{"type", "string"}, {"maxLength", 131072}, {"default", ""}}}})),
      Tool("ida_script_execute_file", "Execute a bounded UTF-8 Python or IDC file under the current IDB directory after a simple heuristic review. This gate is not a complete sandbox; use restricted file tools for file operations.",
           Strict({{"path", {{"type", "string"}, {"minLength", 1}, {"maxLength", 1024}, {"default", ""}}},
                   {"language", Enum({"python", "idc"}, "python")}})),
  };
  return definitions;
}

AgentEffectBinding::AgentEffectBinding(
    std::uint64_t generation,
    std::string database_context,
    std::string database_key)
    : generation_(generation),
      database_context_(std::move(database_context)),
      database_key_(std::move(database_key))
{
}

std::uint64_t AgentEffectBinding::generation() const noexcept
{
  return generation_;
}

const std::string &AgentEffectBinding::database_context() const noexcept
{
  return database_context_;
}

const std::string &AgentEffectBinding::database_key() const noexcept
{
  return database_key_;
}

bool operator==(
    const AgentEffectBinding &left,
    const AgentEffectBinding &right) noexcept
{
  return left.generation_ == right.generation_
      && left.database_context_ == right.database_context_
      && left.database_key_ == right.database_key_;
}

bool operator!=(
    const AgentEffectBinding &left,
    const AgentEffectBinding &right) noexcept
{
  return !(left == right);
}

AgentEffectPreparedPlan::AgentEffectPreparedPlan(
    std::string prepared_id,
    AgentEffectName effect,
    AgentEffectRisk risk,
    AgentEffectBinding binding,
    std::string safe_summary,
    AgentToolCall call,
    std::string payload)
    : prepared_id_(std::move(prepared_id)),
      effect_(effect),
      risk_(risk),
      binding_(std::move(binding)),
      safe_summary_(std::move(safe_summary)),
      call_(std::move(call)),
      payload_(std::move(payload))
{
}

const std::string &AgentEffectPreparedPlan::prepared_id() const noexcept
{
  return prepared_id_;
}

AgentEffectName AgentEffectPreparedPlan::effect() const noexcept
{
  return effect_;
}

AgentEffectRisk AgentEffectPreparedPlan::risk() const noexcept
{
  return risk_;
}

const AgentEffectBinding &AgentEffectPreparedPlan::binding() const noexcept
{
  return binding_;
}

const std::string &AgentEffectPreparedPlan::safe_summary() const noexcept
{
  return safe_summary_;
}

const AgentToolCall &AgentEffectPreparedPlan::call() const noexcept
{
  return call_;
}

const std::string &AgentEffectPreparedPlan::payload() const noexcept
{
  return payload_;
}

AgentEffectPrepareResult::AgentEffectPrepareResult(
    AgentEffectStatus status,
    std::string safe_message,
    std::optional<AgentEffectPreparedPlan> plan)
    : status_(status),
      safe_message_(std::move(safe_message)),
      plan_(std::move(plan))
{
}

AgentEffectStatus AgentEffectPrepareResult::status() const noexcept
{
  return status_;
}

const std::string &AgentEffectPrepareResult::safe_message() const noexcept
{
  return safe_message_;
}

const std::optional<AgentEffectPreparedPlan> &
AgentEffectPrepareResult::plan() const noexcept
{
  return plan_;
}

AgentEffectDecisionResult::AgentEffectDecisionResult(
    AgentEffectStatus status,
    AgentToolResult tool_result)
    : status_(status), tool_result_(std::move(tool_result))
{
}

AgentEffectStatus AgentEffectDecisionResult::status() const noexcept
{
  return status_;
}

const AgentToolResult &AgentEffectDecisionResult::tool_result() const noexcept
{
  return tool_result_;
}

AgentEffectCoordinator::AgentEffectCoordinator(
    AgentEffectBinding binding,
    PrepareInvoker prepare_invoker,
    ExecuteInvoker execute_invoker)
    : binding_(std::move(binding)),
      prepare_invoker_(std::move(prepare_invoker)),
      execute_invoker_(std::move(execute_invoker)),
      owner_thread_(std::this_thread::get_id())
{
  if ( !prepare_invoker_ || !execute_invoker_ )
    throw std::invalid_argument("effect coordinator invokers are required");
}

AgentEffectPrepareResult AgentEffectCoordinator::Prepare(
    const AgentToolCall &call)
{
  RequireOwnerThread();
  const auto descriptor = Classify(call);
  if ( !descriptor )
  {
    return AgentEffectPrepareResult(
        AgentEffectStatus::UnsupportedTool,
        "The requested tool is not a supported side effect.",
        std::nullopt);
  }

  try
  {
    AgentToolCall copied_call = call;
    AgentEffectPreparation preparation = prepare_invoker_(descriptor->name, copied_call);
    if ( preparation.opaque_payload.empty() || preparation.safe_summary.empty() )
      throw std::runtime_error("effect preparation was rejected");
    AgentEffectPreparedPlan plan(
        NextPreparedId(),
        descriptor->name,
        descriptor->risk,
        binding_,
        std::move(preparation.safe_summary),
        std::move(copied_call),
        std::move(preparation.opaque_payload));
    pending_.push_back(plan);
    return AgentEffectPrepareResult(
        AgentEffectStatus::Prepared,
        "A side effect is prepared and awaits the session policy decision.",
        std::move(plan));
  }
  catch ( ... )
  {
    return AgentEffectPrepareResult(
        AgentEffectStatus::PreparationFailed,
        "The side effect could not be prepared safely.",
        std::nullopt);
  }
}

AgentEffectDecisionResult AgentEffectCoordinator::Confirm(
    std::string_view prepared_id,
    const AgentEffectBinding &binding)
{
  RequireOwnerThread();
  const auto pending = std::find_if(
      pending_.begin(), pending_.end(),
      [prepared_id](const AgentEffectPreparedPlan &plan)
      { return plan.prepared_id() == prepared_id; });
  if ( pending == pending_.end() )
  {
    return AgentEffectDecisionResult(
        pending_.empty() ? AgentEffectStatus::NoPendingPlan
                         : AgentEffectStatus::PreparedIdMismatch,
        SafeResult(nullptr, "No matching prepared side effect is available."));
  }
  if ( binding != binding_ || binding != pending->binding() )
  {
    AgentEffectPreparedPlan plan = std::move(*pending);
    pending_.erase(pending);
    return AgentEffectDecisionResult(
        AgentEffectStatus::BindingMismatch,
        SafeResult(
            &plan.call(),
            "The database context changed; the side effect was not executed."));
  }

  // Consume first: execution can never be retried through this prepared ID,
  // including when the executor throws after beginning a side effect.
  AgentEffectPreparedPlan plan = std::move(*pending);
  pending_.erase(pending);
  try
  {
    AgentToolResult result = execute_invoker_(
        plan.effect(), plan.call(), plan.payload());
    result.call_id = plan.call().id;
    result.name = plan.call().name;
    return AgentEffectDecisionResult(
        result.success ? AgentEffectStatus::Confirmed
                       : AgentEffectStatus::ExecutionFailed,
        std::move(result));
  }
  catch ( ... )
  {
    return AgentEffectDecisionResult(
        AgentEffectStatus::StateUncertain,
        SafeResult(
            &plan.call(),
            "Execution began, but the final side-effect state is uncertain."));
  }
}

AgentEffectDecisionResult AgentEffectCoordinator::Reject(
    std::string_view prepared_id,
    const AgentEffectBinding &binding)
{
  RequireOwnerThread();
  const auto pending = std::find_if(
      pending_.begin(), pending_.end(),
      [prepared_id](const AgentEffectPreparedPlan &plan)
      { return plan.prepared_id() == prepared_id; });
  if ( pending == pending_.end() )
  {
    return AgentEffectDecisionResult(
        pending_.empty() ? AgentEffectStatus::NoPendingPlan
                         : AgentEffectStatus::PreparedIdMismatch,
        SafeResult(nullptr, "No matching prepared side effect is available."));
  }
  if ( binding != binding_ || binding != pending->binding() )
  {
    AgentEffectPreparedPlan plan = std::move(*pending);
    pending_.erase(pending);
    return AgentEffectDecisionResult(
        AgentEffectStatus::BindingMismatch,
        SafeResult(
            &plan.call(),
            "The database context changed; the side effect was not executed."));
  }

  AgentEffectPreparedPlan plan = std::move(*pending);
  pending_.erase(pending);
  return AgentEffectDecisionResult(
      AgentEffectStatus::Rejected,
      SafeResult(&plan.call(), "The prepared side effect was rejected."));
}

void AgentEffectCoordinator::Invalidate()
{
  RequireOwnerThread();
  pending_.clear();
}

void AgentEffectCoordinator::UpdateBinding(AgentEffectBinding binding)
{
  RequireOwnerThread();
  if ( binding != binding_ )
    pending_.clear();
  binding_ = std::move(binding);
}

std::vector<AgentEffectPreparedPlan> AgentEffectCoordinator::PendingPlans()
{
  RequireOwnerThread();
  return pending_;
}

void AgentEffectCoordinator::RequireOwnerThread() const
{
  if ( std::this_thread::get_id() != owner_thread_ )
    throw std::logic_error("effect coordinator used from a non-owner thread");
}

std::string AgentEffectCoordinator::NextPreparedId()
{
  if ( next_prepared_id_ == std::numeric_limits<std::uint64_t>::max() )
    throw std::overflow_error("effect coordinator prepared ID exhausted");
  return "effect-" + std::to_string(next_prepared_id_++);
}

} // namespace ida_agent::ai
