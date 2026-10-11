#include "ai/ai_menu.hpp"
#include "ai/agent_prompt.hpp"
#include "ai/agent_project_instructions.hpp"
#include "ai/provider_agent_protocol.hpp"
#include "ai/agent_tool_registry.hpp"
#include <cctype>
#include <stdexcept>

namespace ida_agent::ai
{
analysis_memory::BinaryContext AiMenuController::CaptureAnalysisContext() const
{
  analysis_memory::BinaryContext context;
  try
  {
    // The invoker reads all IDA state through IdaExecutor on the main thread.
    const auto snapshot = agent_tools_.AnalysisContext();
    if (!snapshot.is_object() || snapshot.at("databaseContextId").get<std::ptrdiff_t>() != database_context_id_) return context;
    const auto idb = snapshot.at("idb").get<std::string>();
    context.key = analysis_memory::BinaryKey(snapshot.at("sha256").get<std::string>(), idb);
    context.revision = analysis_memory::DatabaseRevision(idb, snapshot.at("changeCount").get<std::uint32_t>());
    const auto base = analysis_memory::ParseHex(snapshot.at("imageBase").get<std::string>());
    if (!base) return {};
    context.image_base = *base;
    const auto relative = [&](const char *field) -> std::optional<std::uint64_t> {
      if (!snapshot.at(field).is_string()) return {};
      const auto address = analysis_memory::ParseHex(snapshot.at(field).get<std::string>());
      return address && *address >= *base ? std::optional<std::uint64_t>(*address - *base) : std::nullopt; };
    context.cursor_rva = relative("cursor");
    context.function_rva = relative("function");
  }
  catch (...) { return {}; }
  return context;
}

void AiMenuController::BeginAnalysisTurn()
{
  analysis_session_.BeginTurn(CaptureAnalysisContext());
}

std::string AiMenuController::ProjectSystemPrompt(bool agent_tools)
{
  std::string prompt = BuildChatSystemPrompt(agent_tools);
  const std::size_t workflow_bytes = agent_tools ? analysis_session_.WorkflowPrompt().size() : 0;
  const std::size_t budget = prompt.size() <= MaxProviderSystemPromptBytes
      && workflow_bytes <= MaxProviderSystemPromptBytes - prompt.size()
      ? MaxProviderSystemPromptBytes - prompt.size() - workflow_bytes : 0;
  try
  {
    // Capture the IDB path through the main-thread executor; file reads use that fixed root.
    const auto snapshot = agent_tools_.AnalysisContext();
    if (!snapshot.is_object()
        || snapshot.at("databaseContextId").get<std::ptrdiff_t>() != database_context_id_) return prompt;
    const auto &instructions = project_instructions_.Get(snapshot.at("idb").get<std::string>());
    prompt += BuildProjectInstructionsPrompt(instructions, budget);
  }
  catch (...) { /* Unavailable project storage must not crash the chat panel. */ }
  return prompt;
}

void AiMenuController::ApplyProjectInstructionContext(std::vector<ProviderChatMessage> &messages) const
{
  for (auto message = messages.rbegin(); message != messages.rend(); ++message)
    if (message->role == ProviderChatRole::User)
    {
      message->text = WithProjectInstructions(project_instructions_.Snapshot(), message->text);
      return;
    }
}

std::string AiMenuController::AnalysisSystemPrompt(std::string_view text)
{
  analysis_session_.Bind(CaptureAnalysisContext());
  std::string prompt = ProjectSystemPrompt(true);
  const std::size_t budget = prompt.size() < MaxProviderSystemPromptBytes
      ? MaxProviderSystemPromptBytes - prompt.size() : 0;
  prompt += analysis_session_.Prompt(text, budget);
  return prompt;
}

void AiMenuController::ExecuteInstructionsCommand(std::string_view text)
{
  if (HasActiveRequest())
  {
    chat_panel_.AppendSystem("Cancel the active request before inspecting or reloading project instructions.");
    return;
  }
  if (!text.empty() && text != "reload")
  {
    chat_panel_.AppendSystem("Use /instructions for cached project guidance, or /instructions reload to read it again.");
    return;
  }
  if (text == "reload") project_instructions_.Reset();
  ProjectSystemPrompt(false);
  const auto &instructions = project_instructions_.Snapshot();
  if (instructions.status == AgentProjectInstructionStatus::NotLoaded)
    chat_panel_.AppendSystem("Project instructions: no file was safely loaded. Use /instructions reload after adding one.");
  else
  {
    const char *state = instructions.status == AgentProjectInstructionStatus::Loaded ? "cached"
        : instructions.status == AgentProjectInstructionStatus::NeedsRead ? "requires a file-tool read" : "unavailable";
    chat_panel_.AppendSystem("Project instructions: " + instructions.path + " (" + state + ", "
        + std::to_string(instructions.size) + " bytes). Use /instructions reload after changes.");
  }
  RefreshContextUsage();
}

void AiMenuController::ExecuteMemoryCommand(std::string_view text)
{
  if (HasActiveRequest())
  {
    chat_panel_.AppendSystem("Cancel the active request before managing analysis memory.");
    return;
  }
  analysis_session_.Bind(CaptureAnalysisContext());
  try { chat_panel_.AppendSystem(analysis_session_.Command(text, conversation_session_id_)); }
  catch (const std::exception &error) { chat_panel_.AppendSystem(error.what()); }
}

void AiMenuController::ExecuteWorkflowCommand(std::string_view text)
{
  if (HasActiveRequest())
  {
    chat_panel_.AppendSystem("Cancel the active request before selecting a workflow.");
    return;
  }
  const auto split = text.find_first_of(" \t\r\n");
  const auto name = text.substr(0, split);
  const auto question = split == std::string_view::npos ? std::string_view{} : text.substr(split + 1);
  if (name.empty())
  {
    chat_panel_.AppendSystem("Workflows: /workflow protection [question], /workflow function [question], "
        "/workflow types [question], /workflow status, /workflow off.");
    return;
  }
  if (name == "status")
  {
    analysis_session_.Bind(CaptureAnalysisContext());
    chat_panel_.AppendSystem(analysis_session_.Status().dump(2));
    return;
  }
  if (!analysis_session_.SelectWorkflow(name))
  {
    chat_panel_.AppendSystem("Unknown workflow. Choose protection, function or types.");
    return;
  }
  if (name == "off") { chat_panel_.AppendSystem("Analysis workflow disabled for this conversation."); return; }
  std::string request = "Run the " + std::string(name) + " analysis workflow for the current database";
  if (name != "protection") request += " and selected function";
  request += ". Return an evidence-based report with coverage and uncertainties. ";
  request += std::string(question);
  SubmitChatMessage(request);
}

bool AiMenuController::PrepareAnalysisTool(const AgentToolCall &call, std::size_t index)
{
  if (!analysis_memory::IsAnalysisTool(call.name)) return false;
  const auto policy = CurrentEffectPolicy();
  if (!analysis_memory::IsMemoryMutation(call.name))
  {
    pending_tool_results_[index] = analysis_session_.Invoke(call, false, conversation_session_id_);
    return true;
  }
  if (policy == AgentEffectApprovalPolicy::Deny)
  {
    pending_tool_results_[index] = analysis_session_.Invoke(call, false, conversation_session_id_);
    return true;
  }
  const auto preview = analysis_session_.Preview(call, conversation_session_id_);
  if (!preview.success) { pending_tool_results_[index] = preview; return true; }
  const auto context = CaptureAnalysisContext();
  pending_effect_calls_.push_back({index, "analysis-memory", preview.output, call, context.key, context.revision});
  return true;
}

AgentToolResult AiMenuController::DecideMemoryEffect(const PendingEffectCall &effect, bool confirm)
{
  if (!confirm) return {effect.call.id, effect.call.name, false, {}, "Memory mutation was denied by the conversation session policy."};
  const auto context = CaptureAnalysisContext();
  if (context.key != effect.memory_key || context.revision != effect.memory_revision)
    return {effect.call.id, effect.call.name, false, {}, "The database changed after memory preparation; revalidate and prepare again."};
  analysis_session_.Bind(context);
  const auto preview = analysis_session_.Preview(effect.call, conversation_session_id_);
  if (!preview.success || preview.output != effect.safe_summary)
    return {effect.call.id, effect.call.name, false, {}, "Analysis memory changed after preparation; prepare the mutation again."};
  return analysis_session_.Invoke(effect.call, true, conversation_session_id_);
}
} // namespace ida_agent::ai
