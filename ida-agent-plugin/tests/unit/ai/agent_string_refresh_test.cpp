#include "ai/agent_tool_registry.hpp"

#include <stdexcept>
#include <vector>

void RunAgentStringRefreshTests()
{
  using Json = nlohmann::json;
  using ida_agent::ai::AgentToolRegistry;
  const auto page = []() { return Json{{"items", Json::array()}, {"hasMore", false}}; };
  const auto check = [](bool condition)
  {
    if ( !condition ) throw std::runtime_error("string refresh dispatch mismatch");
  };
  std::vector<bool> seen;
  auto strings = AgentToolRegistry::ForTesting(
      [](std::string_view, std::uint32_t) { return Json::object(); },
      [&seen, &page](std::string_view, std::uint32_t, std::uint32_t, bool refresh)
      { seen.push_back(refresh); return page(); });
  ida_agent::ai::AgentToolInvokers invokers;
  invokers.string_search_regex = [&seen, &page](const ida_agent::ai::AgentRegexArguments &args)
  { seen.push_back(args.refresh); return page(); };
  auto regex = AgentToolRegistry::ForTesting(std::move(invokers));
  strings.SetAvailable(true);
  regex.SetAvailable(true);
  for ( bool use_regex : {false, true} )
  {
    auto &registry = use_regex ? regex : strings;
    const std::string name = use_regex ? "ida_string_search_regex" : "ida_string_search";
    Json args{{use_regex ? "pattern" : "query", "hello"}, {"minimumLength", 4}, {"limit", 20}};
    seen.clear();
    check(registry.Invoke({"test", name, args.dump()}).success);
    for ( bool refresh : {true, false} )
    {
      args["refresh"] = refresh;
      check(registry.Invoke({"test", name, args.dump()}).success);
    }
    for ( Json invalid : {Json(nullptr), Json("true"), Json(1), Json::array(), Json::object()} )
    {
      args["refresh"] = invalid;
      check(!registry.Invoke({"test", name, args.dump()}).success);
    }
    check(seen == std::vector<bool>({false, true, false}));
  }
}
