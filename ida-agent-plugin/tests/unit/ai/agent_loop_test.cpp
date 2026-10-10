#include "ai/agent_loop.hpp"
#include "ai/agent_effect_coordinator.hpp"
#include "ai/agent_prompt.hpp"
#include "ai/agent_tool_registry.hpp"

#include <nlohmann/json.hpp>

#include <stdexcept>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

namespace
{

using namespace ida_agent::ai;
using Json = nlohmann::json;

void Require(bool condition, const char *message)
{
  if ( !condition )
    throw std::runtime_error(message);
}

ProviderProfileDraft MakeProfile()
{
  ProviderProfileDraft profile;
  profile.id = "agent-loop-test";
  profile.settings = DraftForPreset(ProviderPreset::OpenAI);
  profile.settings.base_url = "https://provider.invalid/v1";
  profile.settings.model = "agent-model";
  profile.models.push_back(
      ProviderModelDraft{"agent-model", true, "tools", 200000, 10000});
  return profile;
}

AgentToolRegistry MakeRegistry(int &exports_calls, int &string_calls)
{
  return AgentToolRegistry::ForTesting(
      [&exports_calls](std::string_view name, std::uint32_t limit)
      {
        ++exports_calls;
        return Json{
            {"items", Json::array({{{"address", "0x401000"}, {"name", name}, {"limit", limit}}})},
            {"hasMore", false},
        };
      },
      [&string_calls](std::string_view query, std::uint32_t minimum, std::uint32_t limit, bool)
      {
        ++string_calls;
        return Json{
            {"items", Json::array({{{"address", "0x402000"}, {"value", query}, {"minimum", minimum}, {"limit", limit}}})},
            {"hasMore", false},
        };
      });
}

std::vector<AgentToolDefinition> AllTools(const AgentToolRegistry &registry)
{
  std::vector<AgentToolDefinition> tools = registry.Definitions();
  const auto &effects = AgentEffectToolDefinitions();
  tools.insert(tools.end(), effects.begin(), effects.end());
  return tools;
}

bool HasTool(const ProviderChatBuildResult &build, std::string_view name)
{
  const Json body = Json::parse(build.request.body);
  const auto found = body.find("tools");
  if ( found == body.end() || !found->is_array() )
    return false;
  return std::any_of(
      found->begin(), found->end(),
      [name](const Json &tool)
      {
        return tool.is_object() && tool.value("name", std::string()) == name;
      });
}

AgentLoopStep LoadTools(
    AgentLoop &loop,
    std::string call_id,
    std::string query,
    std::uint32_t limit = 6)
{
  const AgentToolCall call{
      std::move(call_id),
      std::string(AgentToolSearchName),
      Json{{"query", std::move(query)}, {"limit", limit}}.dump(),
  };
  Require(!loop.BeginToolRound({call}, "I will load the required tools.").error,
          "tool search round did not start");
  std::optional<AgentToolResult> result = loop.InvokeCatalogTool(call);
  Require(result.has_value() && result->success, "tool search failed");
  return loop.CompleteToolRound({std::move(*result)});
}

void TestToolCatalogSearch()
{
  std::vector<AgentToolDefinition> tools = AgentToolDefinitions();
  const auto &effects = AgentEffectToolDefinitions();
  tools.insert(tools.end(), effects.begin(), effects.end());
  AgentToolCatalogSession catalog;
  catalog.Begin(std::move(tools));
  Require(catalog.ActiveDefinitions().size() == 10
              && catalog.IsActive(AgentToolSearchName)
              && !catalog.IsActive("ida_changeset_apply"),
          "catalog did not start with only the compact core set");

  const AgentToolCall invalid{
      "search-invalid",
      std::string(AgentToolSearchName),
      R"({"query":"rename","limit":6,"extra":true})",
  };
  const std::optional<AgentToolResult> invalid_result = catalog.Invoke(invalid);
  Require(invalid_result.has_value() && !invalid_result->success
              && !catalog.IsActive("ida_changeset_apply"),
          "invalid tool search changed the active catalog");

  AgentToolCall invalid_id = invalid;
  invalid_id.id = "bad\nid";
  invalid_id.arguments_json = R"({"query":"rename","limit":6})";
  const std::optional<AgentToolResult> invalid_id_result =
      catalog.Invoke(invalid_id);
  Require(invalid_id_result.has_value() && !invalid_id_result->success
              && invalid_id_result->call_id.empty()
              && !catalog.IsActive("ida_changeset_apply"),
          "invalid tool search ID escaped or changed the catalog");

  const AgentToolCall search{
      "search-rename",
      std::string(AgentToolSearchName),
      R"({"query":"rename"})",
  };
  const std::optional<AgentToolResult> result = catalog.Invoke(search);
  Require(result.has_value() && result->success
              && catalog.IsActive("ida_changeset_apply"),
          "schema capability search did not load the change tool");
  const Json output = Json::parse(result->output);
  Require(output.at("catalogTools") == 95
              && output.at("newlyLoaded").get<std::size_t>() >= 1,
          "tool search result metadata is incorrect");

  AgentToolCatalogSession oversized;
  oversized.Begin({AgentToolDefinition{
      "ida_oversized_test",
      std::string(MaxAgentToolResultBytes, 'x'),
      Json{{"type", "object"}, {"properties", Json::object()},
          {"required", Json::array()}, {"additionalProperties", false}},
  }});
  const std::size_t before = oversized.ActiveDefinitions().size();
  const std::optional<AgentToolResult> oversized_result = oversized.Invoke({
      "search-oversized",
      std::string(AgentToolSearchName),
      R"({"query":"oversized","limit":1})",
  });
  Require(oversized_result.has_value() && !oversized_result->success
              && oversized.ActiveDefinitions().size() == before
              && !oversized.IsActive("ida_oversized_test"),
          "oversized tool search changed the active catalog");
}

void TestSuccessfulRound()
{
  int exports_calls = 0;
  int string_calls = 0;
  AgentToolRegistry registry = MakeRegistry(exports_calls, string_calls);
  registry.SetAvailable(true);
  AgentLoop loop;
  AgentLoopStep first = loop.Begin(
      MakeProfile(),
      {{ProviderChatRole::User, "List exports."}},
      std::string(AgentSystemPrompt()),
      AllTools(registry));
  Require(!first.error && loop.State() == AgentLoopState::Streaming,
          "agent loop did not start");
  const Json first_body = Json::parse(first.build.request.body);
  Require(first_body.at("tools").size() == 10
              && HasTool(first.build, AgentToolSearchName)
              && !HasTool(first.build, "ida_symbol_exports"),
          "initial request did not use the compact tool catalog");
  ProviderChatAgentOptions full_options;
  full_options.system_prompt = std::string(AgentSystemPrompt());
  full_options.tools = AllTools(registry);
  const ProviderChatBuildResult full = BuildProviderAgentRequest(
      MakeProfile(), {{ProviderChatRole::User, "List exports."}}, full_options);
  Require(!full.error && first.build.estimated_input_tokens <= 4096
              && first.build.estimated_input_tokens * 2
                  < full.estimated_input_tokens,
          "compact catalog did not materially reduce fixed input tokens");

  AgentLoopStep searched = LoadTools(loop, "search-1", "symbol exports");
  Require(!searched.error && HasTool(searched.build, "ida_symbol_exports"),
          "tool search did not load symbol exports");
  const std::vector<AgentToolCall> calls{
      {"call-1", "ida_symbol_exports", R"({"name":"main","limit":2})"},
  };
  Require(!loop.BeginToolRound(calls, "I will inspect exports.").error,
          "tool round did not start");
  std::vector<AgentToolResult> results;
  results.push_back(registry.Invoke(calls.front()));
  AgentLoopStep second = loop.CompleteToolRound(std::move(results));
  Require(!second.error && exports_calls == 1 && string_calls == 0,
          "typed export tool was not invoked");
  const Json body = Json::parse(second.build.request.body);
  const std::string encoded = body.dump();
  Require(encoded.find("function_call_output") != std::string::npos,
          "tool result was not returned to provider");
  Require(encoded.find("0x401000") != std::string::npos,
          "tool output is missing");

  AgentLoopStep string_tools = LoadTools(loop, "search-2", "string search");
  Require(!string_tools.error && HasTool(string_tools.build, "ida_string_search"),
          "tool search did not load string search");

  const std::vector<AgentToolCall> next_calls{
      {"call-2", "ida_string_search",
       R"({"query":"hello","minimumLength":4,"limit":3})"},
  };
  Require(!loop.BeginToolRound(next_calls, "Now I will inspect strings.").error,
          "second tool round did not start");
  AgentLoopStep third = loop.CompleteToolRound(
      {registry.Invoke(next_calls.front())});
  Require(!third.error && exports_calls == 1 && string_calls == 1,
          "continuous tool rounds were not executed");
  const std::string third_body = Json::parse(third.build.request.body).dump();
  Require(third_body.find("0x401000") != std::string::npos
              && third_body.find("0x402000") != std::string::npos,
          "multi-round tool results were not retained");
}

void TestUnknownAndLimits()
{
  int exports_calls = 0;
  int string_calls = 0;
  AgentToolRegistry registry = MakeRegistry(exports_calls, string_calls);
  registry.SetAvailable(true);
  AgentLoop loop;
  Require(!loop.Begin(
      MakeProfile(), {{ProviderChatRole::User, "Inspect."}},
      std::string(AgentSystemPrompt()), AllTools(registry)).error,
      "agent loop setup failed");
  const std::vector<AgentToolCall> unknown_calls{
      {"call-1", "ida_database_save", "{}"}};
  Require(loop.BeginToolRound(unknown_calls, "").error
              && exports_calls == 0 && string_calls == 0,
          "unloaded side-effect tool was not rejected before execution");

  Require(!loop.Begin(
      MakeProfile(), {{ProviderChatRole::User, "Inspect."}},
      std::string(AgentSystemPrompt()), AllTools(registry)).error,
      "agent loop restart failed");
  std::vector<AgentToolCall> calls;
  for ( int index = 0; index < 5001; ++index )
    calls.push_back({"call-" + std::to_string(index), "ida_function_get", "{}"});
  AgentLoopStep unlimited = loop.BeginToolRound(std::move(calls), "");
  Require(!unlimited.error && exports_calls == 0,
          "large tool batch was rejected by a call-count limit");
}

void TestMixedBatchResultOrdering()
{
  AgentLoop loop;
  std::vector<AgentToolDefinition> tools = AgentToolDefinitions();
  const auto &effects = AgentEffectToolDefinitions();
  tools.insert(tools.end(), effects.begin(), effects.end());
  Require(!loop.Begin(
      MakeProfile(), {{ProviderChatRole::User, "Inspect and update."}},
      std::string(AgentSystemPrompt()), std::move(tools)).error,
      "mixed batch setup failed");
  AgentLoopStep loaded = LoadTools(
      loop, "search-effects", "database save debugger start", 12);
  Require(!loaded.error && HasTool(loaded.build, "ida_database_save")
              && HasTool(loaded.build, "ida_debugger_start"),
          "side-effect tools were not dynamically loaded");
  const std::vector<AgentToolCall> calls{
      {"call-read-1", "ida_database_info", "{}"},
      {"call-effect-1", "ida_database_save", "{}"},
      {"call-read-2", "ida_function_get", R"({"address":"0x401000"})"},
      {"call-effect-2", "ida_debugger_start", "{}"},
  };
  Require(!loop.BeginToolRound(calls, "I will run a mixed batch.").error,
          "mixed tool round did not start");
  const std::vector<AgentToolResult> results{
      {"call-read-1", "ida_database_info", true, "read-first", {}},
      {"call-effect-1", "ida_database_save", true, "effect-first", {}},
      {"call-read-2", "ida_function_get", false, {}, "read-second-error"},
      {"call-effect-2", "ida_debugger_start", false, {}, "effect-second-denied"},
  };
  const AgentLoopStep next = loop.CompleteToolRound(results);
  Require(!next.error, "ordered mixed results were rejected");
  const std::string body = Json::parse(next.build.request.body).dump();
  const std::size_t read_first = body.find("read-first");
  const std::size_t effect_first = body.find("effect-first");
  const std::size_t read_second = body.find("read-second-error");
  const std::size_t effect_second = body.find("effect-second-denied");
  Require(read_first < effect_first && effect_first < read_second
              && read_second < effect_second,
          "mixed results changed provider call order");

  Require(!loop.BeginToolRound(calls, "Try invalid order.").error,
          "second mixed tool round did not start");
  std::vector<AgentToolResult> reversed = results;
  std::swap(reversed[0], reversed[1]);
  Require(loop.CompleteToolRound(std::move(reversed)).error,
          "out-of-order mixed results were accepted");
}

void TestFailureOutputAndMessageShareResultBudget()
{
  AgentLoop loop;
  Require(!loop.Begin(
      MakeProfile(), {{ProviderChatRole::User, "Inspect."}},
      std::string(AgentSystemPrompt()), AgentToolDefinitions()).error,
      "dual-field budget setup failed");
  const std::vector<AgentToolCall> calls{
      {"call-dual", "ida_database_info", "{}"},
  };
  Require(!loop.BeginToolRound(calls, "Inspecting.").error,
          "dual-field tool round did not start");
  const AgentToolResult dual_field_failure{
      "call-dual",
      "ida_database_info",
      false,
      std::string(MaxAgentToolResultBytes, 'o'),
      std::string(MaxAgentToolResultBytes, 'm'),
  };
  const std::optional<std::size_t> dual_field_bytes =
      AgentToolResultContentBytes(dual_field_failure);
  Require(dual_field_bytes.has_value()
              && *dual_field_bytes == MaxProviderAgentResultBytes,
          "failure output and message were not both counted");
  Require(!loop.CompleteToolRound({dual_field_failure}).error,
          "exact dual-field result budget was rejected");

  const std::vector<AgentToolCall> next_calls{
      {"call-over", "ida_database_info", "{}"},
  };
  Require(!loop.BeginToolRound(next_calls, "Inspecting again.").error,
          "post-budget tool round did not start");
  Require(loop.CompleteToolRound({
      {"call-over", "ida_database_info", true, "x", {}}}).error,
      "result after an exact dual-field budget was accepted");
}

} // namespace

int main()
{
  try
  {
    TestToolCatalogSearch();
    TestSuccessfulRound();
    TestUnknownAndLimits();
    TestMixedBatchResultOrdering();
    TestFailureOutputAndMessageShareResultBudget();
    return 0;
  }
  catch ( const std::exception &error )
  {
    std::cerr << error.what() << '\n';
    return error.what() == nullptr ? 2 : 1;
  }
}
