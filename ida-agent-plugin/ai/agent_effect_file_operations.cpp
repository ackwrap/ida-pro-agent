#include "ai/agent_effect_file_operations.hpp"
#include "ai/agent_effect_digest.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <string_view>

namespace ida_agent::ai::agent_effect_file_operations
{
namespace
{
using Json = nlohmann::json;
constexpr std::size_t MaxResultBytes = 256 * 1024;

const char *Name(AgentEffectName effect)
{
  return effect == AgentEffectName::FileMutate
      ? "ida_file_mutate" : "ida_script_execute_file";
}

bool Fields(const Json &value, std::initializer_list<const char *> names)
{
  if ( !value.is_object() || value.size() != names.size() ) return false;
  return std::all_of(names.begin(), names.end(), [&](const char *name) {
    return value.contains(name);
  });
}

AgentEffectPreparation PreparationFailure(const char *message)
{
  return {{}, message};
}

AgentToolResult Failure(const AgentToolCall &call, const char *message)
{
  return {call.id, call.name, false, {}, message};
}

AgentToolResult Success(const AgentToolCall &call, Json result)
{
  std::string output = result.dump();
  if ( !result.is_object() || output.size() > MaxResultBytes )
    return Failure(call, "The file operation returned an invalid result.");
  return {call.id, call.name, true, std::move(output), {}};
}

Json StateJson(const AgentFileState &state)
{
  return {{"exists",state.exists},{"type",state.type},{"size",state.size},
      {"sha256",state.sha256},{"volume",state.volume},{"fileIndex",state.file_index}};
}

std::optional<AgentFileState> State(const Json &value)
{
  if ( !Fields(value,{"exists","type","size","sha256","volume","fileIndex"})
      || !value["exists"].is_boolean() || !value["type"].is_string()
      || !value["size"].is_number_unsigned() || !value["sha256"].is_string()
      || !value["volume"].is_number_unsigned() || !value["fileIndex"].is_number_unsigned() )
    return std::nullopt;
  AgentFileState state{value["exists"].get<bool>(),value["type"].get<std::string>(),
      value["size"].get<std::uint64_t>(),value["sha256"].get<std::string>(),
      value["volume"].get<std::uint64_t>(),value["fileIndex"].get<std::uint64_t>()};
  if ( state.type != "file" && state.type != "directory" && !(state.type.empty() && !state.exists) )
    return std::nullopt;
  if ( state.sha256.size() != 64 && !(state.sha256.empty() && state.type != "file") )
    return std::nullopt;
  return state;
}

std::string Integrity(const Json &value)
{
  Json copy = value;
  copy.erase("integrity");
  return AgentEffectSha256(std::string("ida-agent-file-payload-v1\n") + copy.dump());
}

Json Seal(AgentEffectName effect, Json value)
{
  value["version"] = 1;
  value["effect"] = Name(effect);
  value["integrity"] = Integrity(value);
  return value;
}

std::optional<Json> OpenPayload(
    AgentEffectName effect,
    const std::string &payload,
    std::initializer_list<const char *> fields)
{
  Json value = Json::parse(payload.begin(), payload.end(), nullptr, false);
  if ( value.is_discarded() || !value.is_object() || value.size() != fields.size() + 3
      || value.value("version", 0) != 1 || value.value("effect", "") != Name(effect)
      || !value.contains("integrity") || !value["integrity"].is_string() ) return std::nullopt;
  for ( const char *field : fields ) if ( !value.contains(field) ) return std::nullopt;
  if ( value["integrity"].get<std::string>() != Integrity(value) ) return std::nullopt;
  return value;
}

std::string Lower(std::string value)
{
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return value;
}

bool IdentifierToken(std::string_view source, std::string_view token)
{
  std::size_t offset = 0;
  while ( (offset = source.find(token, offset)) != std::string_view::npos )
  {
    const auto identifier = [](unsigned char ch) { return std::isalnum(ch) != 0 || ch == '_'; };
    const bool left = offset != 0 && identifier(static_cast<unsigned char>(source[offset - 1]));
    const std::size_t end = offset + token.size();
    const bool right = end < source.size() && identifier(static_cast<unsigned char>(source[end]));
    if ( !left && !right ) return true;
    offset = end;
  }
  return false;
}

bool ObviousPath(std::string_view source)
{
  if ( source.find("..") != std::string_view::npos
      || source.find("\\\\") != std::string_view::npos
      || source.find("\\?\\") != std::string_view::npos
      || source.find("'/") != std::string_view::npos
      || source.find("\"/") != std::string_view::npos ) return true;
  for ( std::size_t index = 0; index + 2 < source.size(); ++index )
    if ( std::isalpha(static_cast<unsigned char>(source[index]))
        && source[index + 1] == ':' && (source[index + 2] == '\\' || source[index + 2] == '/') )
      return true;
  static const std::string_view environment[]{"%temp%","%tmp%","%appdata%","%localappdata%",
      "%userprofile%","os.environ","getenv","expanduser","tempdir","homedir","$env:"};
  return std::any_of(std::begin(environment), std::end(environment),
      [&](std::string_view token) { return source.find(token) != std::string_view::npos; });
}

bool StringLiteralConcatenation(std::string_view source)
{
  std::size_t plus = 0;
  while ( (plus = source.find('+', plus)) != std::string_view::npos )
  {
    std::size_t left = plus, right = plus + 1;
    while ( left != 0 && std::isspace(static_cast<unsigned char>(source[left - 1])) ) --left;
    while ( right < source.size() && std::isspace(static_cast<unsigned char>(source[right])) ) ++right;
    if ( left != 0 && right < source.size()
        && (source[left - 1] == '\'' || source[left - 1] == '"')
        && (source[right] == '\'' || source[right] == '"') ) return true;
    ++plus;
  }
  return false;
}

bool ScriptAllowed(std::string_view language, std::string_view source)
{
  const std::string lowered = Lower(std::string(source));
  if ( ObviousPath(lowered) || StringLiteralConcatenation(lowered)
      || lowered.find(".system") != std::string::npos ) return false;
  if ( language == "python" )
  {
    static const std::string_view denied[]{"open","os","pathlib","shutil","tempfile",
        "subprocess","ctypes","winreg","socket","ida_diskio","importlib","require",
        "__builtins__","getattr","__import__","eval","exec","compile",
        "save_database","save_database_ex","gen_file"};
    return std::none_of(std::begin(denied), std::end(denied),
        [&](std::string_view token) { return IdentifierToken(lowered, token); });
  }
  static const std::string_view denied[]{"fopen","fclose","fileopen","fileclose","file2base",
      "base2file","loadfile","savefile","exec","exec_system","call_system","launch_process","qexec","system",
      "save_database","save_database_ex","gen_file"};
  return std::none_of(std::begin(denied), std::end(denied),
      [&](std::string_view token) { return IdentifierToken(lowered, token); });
}

AgentEffectPreparation PrepareMutation(
    const AgentEffectServiceCallbacks &callbacks,
    AgentEffectName effect,
    const Json &arguments)
{
  if ( !Fields(arguments,{"path","mode","content"}) || !arguments["path"].is_string()
      || !arguments["mode"].is_string() || !arguments["content"].is_string()
      || !callbacks.file_prepare_mutation )
    return PreparationFailure("The file mutation request is invalid.");
  const std::string path = arguments["path"].get<std::string>();
  const std::string mode = arguments["mode"].get<std::string>();
  const std::string content = arguments["content"].get<std::string>();
  const auto plan = callbacks.file_prepare_mutation(path, mode, content);
  if ( !plan ) return PreparationFailure("The file mutation request is not safely applicable.");
  Json payload = Seal(effect, {{"path",plan->path},{"mode",plan->mode},{"content",plan->content},
      {"expected",StateJson(plan->expected)},{"parentVolume",plan->parent_volume},
      {"parentFileIndex",plan->parent_file_index}});
  std::ostringstream summary;
  summary << "File mutation " << plan->mode << " for relative path " << plan->path << ". ";
  if ( plan->mode == "delete_directory" )
    summary << "This permanently removes the directory and every file and subdirectory inside it.";
  if ( plan->expected.exists )
    summary << " Expected " << plan->expected.type << ", " << plan->expected.size
            << " byte(s), SHA-256 " << (plan->expected.sha256.empty() ? "not-applicable" : plan->expected.sha256) << ".";
  else summary << " Expected target to be absent.";
  if ( !plan->content.empty() )
    summary << " New content: " << plan->content.size() << " byte(s), SHA-256 "
            << AgentEffectSha256(plan->content) << "; content is not displayed.";
  return {payload.dump(), summary.str()};
}

AgentEffectPreparation PrepareScript(
    const AgentEffectServiceCallbacks &callbacks,
    AgentEffectName effect,
    const Json &arguments)
{
  if ( !Fields(arguments,{"path","language"}) || !arguments["path"].is_string()
      || !arguments["language"].is_string() || !callbacks.file_prepare_script )
    return PreparationFailure("The script-file request is invalid.");
  const std::string path = arguments["path"].get<std::string>();
  const std::string language = arguments["language"].get<std::string>();
  const auto snapshot = callbacks.file_prepare_script(path, language);
  if ( !snapshot || !ScriptAllowed(snapshot->language, snapshot->source) )
    return PreparationFailure("The script file was rejected by the restricted heuristic review.");
  Json payload = Seal(effect, {{"path",snapshot->path},{"language",snapshot->language},
      {"source",snapshot->source},{"sha256",snapshot->sha256}});
  std::ostringstream summary;
  summary << "Execute reviewed " << snapshot->language << " script file " << snapshot->path
          << " from an immutable in-memory snapshot (" << snapshot->source.size()
          << " byte(s), SHA-256 " << snapshot->sha256
          << "). Source is not displayed. The heuristic review is not a complete sandbox.";
  return {payload.dump(), summary.str()};
}

AgentToolResult ExecuteMutation(
    const AgentEffectServiceCallbacks &callbacks,
    AgentEffectName effect,
    const AgentToolCall &call,
    const std::string &payload)
{
  const auto saved = OpenPayload(effect,payload,
      {"path","mode","content","expected","parentVolume","parentFileIndex"});
  if ( !saved || !(*saved)["path"].is_string() || !(*saved)["mode"].is_string()
      || !(*saved)["content"].is_string() || !(*saved)["parentVolume"].is_number_unsigned()
      || !(*saved)["parentFileIndex"].is_number_unsigned() || !callbacks.file_execute_mutation )
    return Failure(call,"The prepared file mutation is invalid.");
  const auto expected = State((*saved)["expected"]);
  if ( !expected ) return Failure(call,"The prepared file mutation is invalid.");
  AgentFileMutationPlan plan{(*saved)["path"].get<std::string>(),(*saved)["mode"].get<std::string>(),
      (*saved)["content"].get<std::string>(),*expected,(*saved)["parentVolume"].get<std::uint64_t>(),
      (*saved)["parentFileIndex"].get<std::uint64_t>()};
  AgentFileMutationOutcome outcome;
  try { outcome = callbacks.file_execute_mutation(plan); }
  catch ( ... ) { throw AgentEffectStateUncertain(); }
  if ( outcome.status == AgentFileMutationStatus::StateUncertain ) throw AgentEffectStateUncertain();
  if ( outcome.status != AgentFileMutationStatus::Success )
    return Failure(call,"The prepared file mutation no longer matches the approved filesystem state.");
  return Success(call,outcome.result);
}

AgentToolResult ExecuteScript(
    const AgentEffectServiceCallbacks &callbacks,
    AgentEffectName effect,
    const AgentToolCall &call,
    const std::string &payload)
{
  const auto saved = OpenPayload(effect,payload,{"path","language","source","sha256"});
  if ( !saved || !(*saved)["path"].is_string() || !(*saved)["language"].is_string()
      || !(*saved)["source"].is_string() || !(*saved)["sha256"].is_string()
      || !callbacks.script_execute ) return Failure(call,"The prepared script file is invalid.");
  const std::string language = (*saved)["language"].get<std::string>();
  const std::string source = (*saved)["source"].get<std::string>();
  const std::string hash = (*saved)["sha256"].get<std::string>();
  if ( (language != "python" && language != "idc") || source.empty()
      || source.size() > MaxAgentScriptBytes || AgentEffectSha256(source) != hash
      || !ScriptAllowed(language, source) )
    return Failure(call,"The prepared script file is invalid.");
  services::ScriptExecutionOutcome outcome;
  try { outcome = callbacks.script_execute(language,source); }
  catch ( ... ) { throw AgentEffectStateUncertain(); }
  if ( outcome.status == services::ScriptStatus::Unavailable )
    return Failure(call,"The requested script language is unavailable.");
  if ( outcome.status != services::ScriptStatus::Success || !outcome.result )
    return Failure(call,"The script runtime did not return a result.");
  const auto &result = *outcome.result;
  return Success(call,{{"path",(*saved)["path"]},{"language",result.language},
      {"success",result.success},{"resultPresent",result.result.has_value()},
      {"resultBytes",result.result ? result.result->size() : 0},
      {"stdoutBytes",result.stdout_text.size()},{"stderrBytes",result.stderr_text.size()},
      {"truncated",result.truncated},{"originalSize",result.original_size}});
}

} // namespace

AgentEffectPreparation Prepare(
    const AgentEffectServiceCallbacks &callbacks,
    AgentEffectName effect,
    const AgentToolCall &,
    const Json &arguments)
{
  return effect == AgentEffectName::FileMutate
      ? PrepareMutation(callbacks,effect,arguments)
      : PrepareScript(callbacks,effect,arguments);
}

AgentToolResult Execute(
    const AgentEffectServiceCallbacks &callbacks,
    AgentEffectName effect,
    const AgentToolCall &call,
    const std::string &payload)
{
  return effect == AgentEffectName::FileMutate
      ? ExecuteMutation(callbacks,effect,call,payload)
      : ExecuteScript(callbacks,effect,call,payload);
}

} // namespace ida_agent::ai::agent_effect_file_operations
