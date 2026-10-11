#include "ai/agent_prompt.hpp"
#include "ai/agent_project_instructions.hpp"
#include "ai/analysis_memory/session.hpp"
#include "ai/provider_chat.hpp"
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <stdexcept>

namespace
{
using namespace ida_agent::ai;
using Json = nlohmann::json;
void Require(bool value, const char *text) { if (!value) throw std::runtime_error(text); }
ProviderProfileDraft Profile(int codec, bool tools)
{
  ProviderProfileDraft profile;
  profile.id = "prompt-test";
  profile.settings = DraftForPreset(codec == 2 ? ProviderPreset::Claude : ProviderPreset::OpenAI);
  profile.settings.base_url = "https://provider.invalid/v1";
  profile.settings.openai_api_mode = codec == 1 ? OpenAIApiMode::ChatCompletions : OpenAIApiMode::Responses;
  profile.settings.model = "test-model";
  profile.models.push_back({"test-model", true, tools ? "tools" : "", 200000, 10000});
  return profile;
}
AgentToolDefinition Tool()
{
  return {"ida_database_info", "Read database metadata.", Json{{"type", "object"},
      {"properties", Json::object()}, {"required", Json::array()}, {"additionalProperties", false}}};
}
std::string System(const Json &body, int codec)
{
  if (codec == 0) return body.at("instructions").get<std::string>();
  if (codec == 2) return body.at("system").get<std::string>();
  Require(body.at("messages").at(0).at("role") == "system", "chat system role missing");
  return body.at("messages").at(0).at("content").get<std::string>();
}
void PlainAndRecoveryWires()
{
  const std::vector<ProviderChatMessage> messages{{ProviderChatRole::User, "Explain the supplied code."}};
  for (int codec = 0; codec < 3; ++codec)
  {
    AgentProjectInstructions project{AgentProjectInstructionStatus::Loaded,
        "Agents.md", "Prefer local symbol names and cite code addresses.", 0};
    project.size = project.content.size();
    const auto base = BuildChatSystemPrompt(false);
    const auto prompt = base + BuildProjectInstructionsPrompt(project, MaxProviderSystemPromptBytes - base.size());
    const std::vector<ProviderChatMessage> guided_messages{{ProviderChatRole::User,
        WithProjectInstructions(project, messages.front().text)}};
    const auto plain = BuildProviderChatRequest(Profile(codec, false), guided_messages, prompt);
    Require(!plain.error, "plain prompt needs tools to be enabled");
    const auto body = Json::parse(plain.request.body);
    Require(System(body, codec) == prompt && !body.contains("tools")
        && plain.messages.back().text == guided_messages.back().text,
        "plain chat lost shared rules or advertised tools");
    Require(plain.estimated_input_tokens > BuildProviderChatRequest(Profile(codec, false), messages).estimated_input_tokens,
        "plain prompt tokens were not included in context usage");
    const auto exact = BuildProviderChatRequest(Profile(codec, false), messages,
        std::string(MaxProviderSystemPromptBytes, 'x'));
    Require(!exact.error, "exact system-prompt byte limit rejected");
    Require(BuildProviderChatRequest(Profile(codec, false), messages,
        std::string(MaxProviderSystemPromptBytes + 1, 'x')).error, "overlong plain prompt accepted");
    const auto compact = BuildProviderChatRequest(Profile(codec, false), messages, ChatCompactionSystemPrompt());
    Require(!compact.error && System(Json::parse(compact.request.body), codec) == ChatCompactionSystemPrompt(),
        "compaction rules were not sent as system instructions");

    ProviderChatAgentOptions options;
    options.system_prompt = BuildChatSystemPrompt(true);
    options.tools = {Tool()};
    const AgentToolCall call{"unavailable", "ida_missing_tool", "{}"};
    const AgentToolResult failure{call.id, call.name, false, {}, "unknown_tool: No operation ran.",
        AgentToolFailureKind::ToolUnavailable};
    options.exchanges = {{"", {call}, {failure}}};
    auto request = BuildProviderAgentRequest(Profile(codec, true), messages, options);
    Require(!request.error && request.request.body.find("unknown_tool") != std::string::npos,
        "inert unknown-call failure could not be returned to the provider");
    const auto next = Json::parse(request.request.body);
    Require(next.at("tools").size() == 1, "recovery advertised an invented tool");
    if (codec == 2)
      Require(next.at("messages").back().at("content").at(0).at("is_error") == true,
          "Claude unavailable result was not marked as an error");
    for (int variant = 0; variant < 4; ++variant)
    {
      auto forged = options;
      auto &result = forged.exchanges[0].results[0];
      if (variant == 0) result.failure_kind = AgentToolFailureKind::None;
      if (variant == 1) result.success = true;
      if (variant == 2) result.output = "invented data";
      if (variant == 3) result.safe_message.clear();
      Require(BuildProviderAgentRequest(Profile(codec, true), messages, forged).error,
          "unknown-call success or untagged failure bypassed validation");
    }
  }
}
struct TestDirectory
{
  std::filesystem::path parent = std::filesystem::current_path();
  std::filesystem::path path = parent / ("prompt-budget-test-"
      + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
  TestDirectory()
  {
    Require(!std::filesystem::exists(path), "sandbox collision");
    std::filesystem::create_directory(path);
#ifndef _WIN32
    std::filesystem::permissions(path, std::filesystem::perms::owner_all);
#endif
  }
  ~TestDirectory()
  {
    std::error_code error;
    if (path.parent_path() == parent && path.filename().string().rfind("prompt-budget-test-", 0) == 0)
      std::filesystem::remove_all(path, error);
  }
};
void WorkflowAndMemoryBudget()
{
  TestDirectory directory;
  analysis_memory::Session session(directory.path / "memory.db", false);
  const analysis_memory::BinaryContext context{
      analysis_memory::BinaryKey(std::string(64, 'a'), "/prompt-test.i64"),
      analysis_memory::DatabaseRevision("/prompt-test.i64", 1), 0x400000, 0x1234, 0x1200};
  session.BeginTurn(context);
  std::vector<std::string> notes;
  for (int index = 0; index < 6; ++index)
  {
    std::string note = "protection evidence ";
    for (int word = 0; word < 100; ++word) note += "\xE8\xA7\x82\xE5\xAF\x9F";
    note += " end-" + std::to_string(index);
    notes.push_back(note);
    session.Command("add-local " + note, "user");
  }
  const auto base = BuildChatSystemPrompt(true);
  Require(base.size() < MaxProviderSystemPromptBytes,
      "mandatory rules exceed the system-prompt cap");
  Require(base.size() + session.Prompt("protection").size() > MaxProviderSystemPromptBytes,
      "heavy memory fixture does not reproduce the original composition overflow");
  for (const auto *workflow : {"off", "protection", "function", "types"})
  {
    Require(session.SelectWorkflow(workflow), "budget workflow selection failed");
    const auto workflow_bytes = session.WorkflowPrompt().size();
    Require(base.size() + workflow_bytes < MaxProviderSystemPromptBytes,
        "base instructions displaced mandatory workflow steps");
    for (bool oversized : {false, true})
    {
      AgentProjectInstructions project{AgentProjectInstructionStatus::Loaded, "AGENTS.md",
          oversized ? std::string(MaxAgentProjectInstructionBytes, 'p') : "Project rule: label static evidence.", 0};
      project.size = project.content.size();
      const auto guidance = BuildProjectInstructionsPrompt(project,
          MaxProviderSystemPromptBytes - base.size() - workflow_bytes);
      const auto document = Json::parse(guidance.substr(guidance.find('{')));
      Require(document.at("status") == "loaded", "cached project metadata was lost");
      const auto guided_question = WithProjectInstructions(project, "Analyze protection.");
      const auto extra = session.Prompt("protection", MaxProviderSystemPromptBytes - base.size() - guidance.size());
      const auto composed = base + guidance + extra;
      Require(composed.size() <= MaxProviderSystemPromptBytes,
          "workflow plus memory exceeded the complete system limit");
      if (std::string(workflow) != "off")
        Require(extra.find("Active analysis workflow") != std::string::npos
            && extra.find(analysis_memory::Workflow(workflow).dump()) != std::string::npos,
            "memory displaced or truncated the active workflow");
      const auto memory = extra.find("\nAnalysis memory (");
      Require(memory != std::string::npos, "bounded prompt lost every fitting complete memory record");
      const auto rows = Json::parse(extra.substr(extra.find('\n', memory + 1) + 1));
      Require(rows.is_array() && !rows.empty(), "bounded memory JSON was sliced");
      for (const auto &row : rows)
      {
        const auto text = row.at("text").get<std::string>();
        Require(std::find(notes.begin(), notes.end(), text) != notes.end(),
            "memory text or multibyte UTF-8 was truncated");
      }
      for (int codec = 0; codec < 3; ++codec)
      {
        ProviderChatAgentOptions options;
        options.system_prompt = composed; options.tools = {Tool()};
        const auto request = BuildProviderAgentRequest(Profile(codec, true),
            {{ProviderChatRole::User, guided_question}}, options);
        Require(!request.error && System(Json::parse(request.request.body), codec) == composed
            && request.messages.back().text == guided_question,
            "composed workflow/memory prompt was rejected or changed by a codec");
        if (oversized)
        {
          const auto baseline = BuildProviderAgentRequest(Profile(codec, true),
              {{ProviderChatRole::User, "Analyze protection."}}, options);
          Require(!baseline.error, "baseline model budget fixture failed");
          auto small_profile = Profile(codec, true);
          small_profile.models.front().context_length = static_cast<std::uint32_t>(
              baseline.estimated_input_tokens + ProviderChatReservedTokens + 4096 + 128);
          small_profile.models.front().max_output_tokens = 4096;
          Require(!BuildProviderAgentRequest(small_profile,
              {{ProviderChatRole::User, "Analyze protection."}}, options).error,
              "small model fixture cannot carry the base request without long instructions");
          Require(BuildProviderAgentRequest(small_profile,
              {{ProviderChatRole::User, guided_question}}, options).error,
              "insufficient model budget silently dropped required project instructions");
        }
      }
    }
  }
  Require(session.Prompt("protection", 0).empty(), "zero context budget emitted data");
  const auto small = session.Prompt("protection", 180);
  Require(small.size() <= 180 && small.find("types") != std::string::npos
      && small.find("ida_analysis_workflow_get") != std::string::npos,
      "small budget lost the active-workflow lookup marker");
  Require(session.Prompt("protection", 1).empty(), "tiny budget returned partial data");
}
} // namespace
void RunProviderPromptTests()
{
  PlainAndRecoveryWires(); WorkflowAndMemoryBudget();
}
