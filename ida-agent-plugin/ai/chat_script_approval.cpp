#include "ai/chat_script_approval.hpp"

#include <nlohmann/json.hpp>

#include <string_view>
#include <utility>

namespace ida_agent::ai
{
namespace
{

constexpr std::string_view ScriptToolName = "ida_script_execute_file";
constexpr std::size_t MaxScriptPathBytes = 1024;

} // namespace

std::optional<std::vector<ChatScriptSource>> ParsePreparedScriptSources(
    const std::vector<AgentToolCall> &prepared_calls) noexcept
{
  try
  {
    std::vector<ChatScriptSource> sources;
    for ( const AgentToolCall &call : prepared_calls )
    {
      if ( call.name != ScriptToolName )
        continue;
      const nlohmann::json arguments = nlohmann::json::parse(
          call.arguments_json, nullptr, false);
      if ( arguments.is_discarded()
          || !arguments.is_object()
          || arguments.size() != 2
          || !arguments.contains("language")
          || !arguments.contains("path")
          || !arguments["language"].is_string()
          || !arguments["path"].is_string() )
      {
        return std::nullopt;
      }
      ChatScriptSource source{
          arguments["language"].get<std::string>(),
          arguments["path"].get<std::string>(),
      };
      if ( (source.language != "python" && source.language != "idc")
          || source.path.empty()
          || source.path.size() > MaxScriptPathBytes
          || source.path.find('\0') != std::string::npos )
      {
        return std::nullopt;
      }
      sources.push_back(std::move(source));
    }
    return sources;
  }
  catch ( ... )
  {
    return std::nullopt;
  }
}

ChatScriptApprovalRoute RoutePreparedScriptApproval(
    AgentEffectApprovalPolicy policy,
    const std::optional<std::vector<ChatScriptSource>> &sources) noexcept
{
  if ( policy != AgentEffectApprovalPolicy::Ask )
    return ChatScriptApprovalRoute::ContinueStandardFlow;
  if ( !sources.has_value() )
    return ChatScriptApprovalRoute::DenySession;
  return sources->empty()
      ? ChatScriptApprovalRoute::ContinueStandardFlow
      : ChatScriptApprovalRoute::ShowDialog;
}

ChatScriptApprovalDecision ChatScriptDecisionFromAccepted(bool accepted) noexcept
{
  return accepted
      ? ChatScriptApprovalDecision::AllowSessionAndExecute
      : ChatScriptApprovalDecision::DenySession;
}

std::string FormatChatScriptApprovalPreview(
    const std::vector<ChatScriptSource> &sources)
{
  std::string preview;
  for ( std::size_t index = 0; index < sources.size(); ++index )
  {
    if ( index != 0 )
      preview += "\n\n====================\n\n";
    preview += "Script " + std::to_string(index + 1) + " of "
        + std::to_string(sources.size()) + "\nLanguage: "
        + sources[index].language + "\nRelative path: " + sources[index].path
        + "\nSource was reviewed into an immutable snapshot and is not displayed.";
  }
  return preview;
}

} // namespace ida_agent::ai
