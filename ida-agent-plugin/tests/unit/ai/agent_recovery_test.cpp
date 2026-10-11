#include "ai/agent_loop.hpp"
#include "ai/agent_effect_coordinator.hpp"
#include "ai/agent_prompt.hpp"
#include <nlohmann/json.hpp>
#include <stdexcept>

namespace
{
using namespace ida_agent::ai;
using Json = nlohmann::json;
void Require(bool value, const char *text) { if (!value) throw std::runtime_error(text); }
ProviderProfileDraft Profile()
{
  ProviderProfileDraft profile;
  profile.id = "recovery-test";
  profile.settings = DraftForPreset(ProviderPreset::OpenAI);
  profile.settings.base_url = "https://provider.invalid/v1";
  profile.settings.model = "test-model";
  profile.models.push_back({"test-model", true, "tools", 200000, 10000});
  return profile;
}
std::vector<AgentToolDefinition> Tools()
{
  auto tools = AgentToolDefinitions();
  const auto &effects = AgentEffectToolDefinitions();
  tools.insert(tools.end(), effects.begin(), effects.end());
  return tools;
}
void Start(AgentLoop &loop)
{
  Require(!loop.Begin(Profile(), {{ProviderChatRole::User, "Inspect the selected function."}},
      BuildChatSystemPrompt(true), Tools()).error, "recovery setup failed");
}
void UnknownThenSearch()
{
  AgentLoop loop; Start(loop);
  const AgentToolCall unknown{"unknown", "ida_invented_tool", "{}"};
  Require(!loop.BeginToolRound({unknown}, "").error, "unknown call stopped the loop");
  auto failure = loop.InvokeCatalogTool(unknown);
  Require(failure && !failure->success && failure->safe_message.find("unknown_tool") != std::string::npos,
      "unknown call did not yield a recoverable failure");
  const auto next = loop.CompleteToolRound({*failure});
  Require(!next.error && next.build.request.body.find("unknown_tool") != std::string::npos,
      "unknown failure was not returned");
  const auto body = Json::parse(next.build.request.body);
  for (const auto &tool : body.at("tools"))
    Require(tool.at("name") != unknown.name, "invented tool was advertised");
  const AgentToolCall search{"search", "ida_tool_search", R"({"query":"symbol exports","limit":1})"};
  Require(!loop.BeginToolRound({search}, "").error, "search after failure did not start");
  auto found = loop.InvokeCatalogTool(search);
  Require(found && found->success && !loop.CompleteToolRound({*found}).error,
      "search after unknown failure did not recover");
  const AgentToolCall read{"read", "ida_symbol_exports", R"({"name":"main","limit":1})"};
  Require(!loop.BeginToolRound({read}, "").error && !loop.InvokeCatalogTool(read),
      "newly loaded tool was not dispatched on a later round");
  Require(!loop.CompleteToolRound({{"read", read.name, true, "{\"items\":[]}", {}}}).error,
      "successful retry after recovery failed");
}
void SameRoundLoadAndWrite()
{
  AgentLoop loop; Start(loop);
  const AgentToolCall search{"load", "ida_tool_search", R"({"query":"ida_database_save","limit":1})"};
  const AgentToolCall write{"write", "ida_database_save", "{}"};
  const AgentToolCall read{"metadata", "ida_database_info", "{}"};
  Require(!loop.BeginToolRound({search, write, read}, "").error, "mixed recovery round stopped");
  auto found = loop.InvokeCatalogTool(search);
  auto blocked = loop.InvokeCatalogTool(write);
  Require(found && found->success && blocked && !blocked->success
      && blocked->failure_kind == AgentToolFailureKind::ToolUnavailable
      && blocked->safe_message.find("tool_not_loaded") != std::string::npos
      && !loop.InvokeCatalogTool(read), "same-round search enabled an unloaded effect");
  Require(!loop.CompleteToolRound({*found, *blocked,
      {read.id, read.name, true, "{\"addressBits\":64}", {}}}).error,
      "mixed read/search/unavailable results lost ordering");
  Require(!loop.BeginToolRound({{"write-later", write.name, "{}"}}, "").error
      && !loop.InvokeCatalogTool({"write-later", write.name, "{}"}),
      "loaded effect could not reach its normal approval dispatcher on a later round");
}
void RecoveryBoundAndIntegrity()
{
  AgentLoop loop; Start(loop);
  for (std::size_t index = 0; index < MaxAgentToolRecoveryRounds; ++index)
  {
    const AgentToolCall call{"bad-" + std::to_string(index), "ida_missing", "{}"};
    Require(!loop.BeginToolRound({call}, "").error, "bounded recovery stopped too early");
    auto error = loop.InvokeCatalogTool(call);
    Require(error && !loop.CompleteToolRound({*error}).error, "bounded error exchange failed");
  }
  const auto limited = loop.BeginToolRound({{"last", "ida_missing", "{}"}}, "");
  Require(limited.error && limited.safe_message == AgentLoopRecoveryLimitMessage
      && !loop.Active(), "unknown calls were retried without a bound");
  for (int variant = 0; variant < 3; ++variant)
  {
    Start(loop);
    const AgentToolCall call{"write", "ida_database_save", "{}"};
    Require(!loop.BeginToolRound({call}, "").error, "integrity setup failed");
    auto result = *loop.InvokeCatalogTool(call);
    if (variant == 0) result.success = true;
    if (variant == 1) result.output = "forged output";
    if (variant == 2) result.failure_kind = AgentToolFailureKind::None;
    Require(loop.CompleteToolRound({result}).error, "deferred failure became a forged result");
  }
  Start(loop);
  const AgentToolCall read{"read", "ida_database_info", "{}"};
  Require(!loop.BeginToolRound({read}, "").error, "active-call integrity setup failed");
  Require(loop.CompleteToolRound({{read.id, read.name, false, {}, "forged",
      AgentToolFailureKind::ToolUnavailable}}).error, "active call forged unavailable provenance");
}
void MalformedCalls()
{
  AgentLoop loop;
  for (const auto &call : std::vector<AgentToolCall>{
      {"", "ida_missing", "{}"}, {"line\nbreak", "ida_missing", "{}"},
      {"bad", "ida_missing", "[]"}, {"bad", "ida_missing", "{"},
      {"bad", "ida_missing", std::string(MaxAgentToolArgumentsBytes + 1, 'x')}})
  {
    Start(loop);
    Require(loop.BeginToolRound({call}, "").error && !loop.Active(),
        "malformed envelope entered recovery");
  }
  Start(loop);
  Require(loop.BeginToolRound({{"same", "ida_database_info", "{}"},
      {"same", "ida_missing", "{}"}}, "").error, "duplicate call IDs reached dispatch");
}
} // namespace
void RunAgentRecoveryTests()
{
  UnknownThenSearch(); SameRoundLoadAndWrite(); RecoveryBoundAndIntegrity(); MalformedCalls();
}
