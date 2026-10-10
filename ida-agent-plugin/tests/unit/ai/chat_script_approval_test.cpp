#include "ai/chat_script_approval.hpp"

#include <stdexcept>
#include <string>
#include <vector>

namespace
{

using namespace ida_agent::ai;

void Require(bool condition, const char *message)
{
  if ( !condition )
    throw std::runtime_error(message);
}

void TestPreviewParsingAndOrdering()
{
  const std::vector<AgentToolCall> calls{
      {"read", "ida_database_info", "{}"},
      {"python", "ida_script_execute_file",
       R"json({"path":"scripts/first.py","language":"python"})json"},
      {"save", "ida_database_save", "{}"},
      {"idc", "ida_script_execute_file",
       R"json({"path":"scripts/second.idc","language":"idc"})json"},
  };
  const auto sources = ParsePreparedScriptSources(calls);
  Require(sources.has_value() && sources->size() == 2,
          "prepared scripts were not parsed");
  Require((*sources)[0].language == "python"
              && (*sources)[0].path == "scripts/first.py",
          "first script path changed");
  Require((*sources)[1].language == "idc"
              && (*sources)[1].path == "scripts/second.idc",
          "second script path changed");

  const std::string preview = FormatChatScriptApprovalPreview(*sources);
  const std::size_t first = preview.find((*sources)[0].path);
  const std::size_t second = preview.find((*sources)[1].path);
  Require(first != std::string::npos && second != std::string::npos
              && first < second,
          "preview omitted or reordered script paths");
  Require(preview.find("print(") == std::string::npos, "preview exposed source");
  Require(preview.find("Script 1 of 2") != std::string::npos
              && preview.find("Script 2 of 2") != std::string::npos,
          "preview script labels are missing");
}

void TestSafeRouting()
{
  const auto no_scripts = ParsePreparedScriptSources({
      {"save", "ida_database_save", "{}"},
  });
  Require(RoutePreparedScriptApproval(
              AgentEffectApprovalPolicy::Ask, no_scripts)
              == ChatScriptApprovalRoute::ContinueStandardFlow,
          "ordinary Ask batch did not retain the standard flow");

  const auto scripts = ParsePreparedScriptSources({
      {"script", "ida_script_execute_file",
       R"({"path":"analysis.py","language":"python"})"},
  });
  Require(RoutePreparedScriptApproval(
              AgentEffectApprovalPolicy::Ask, scripts)
              == ChatScriptApprovalRoute::ShowDialog,
          "Ask script batch did not route to the dialog");
  Require(RoutePreparedScriptApproval(
              AgentEffectApprovalPolicy::Allow, scripts)
              == ChatScriptApprovalRoute::ContinueStandardFlow
              && RoutePreparedScriptApproval(
                     AgentEffectApprovalPolicy::Deny, scripts)
                     == ChatScriptApprovalRoute::ContinueStandardFlow,
          "settled session policy routed to a dialog");

  const auto invalid = ParsePreparedScriptSources({
      {"script", "ida_script_execute_file",
       R"({"path":7,"language":"python"})"},
  });
  Require(!invalid.has_value()
              && RoutePreparedScriptApproval(
                     AgentEffectApprovalPolicy::Ask, invalid)
                     == ChatScriptApprovalRoute::DenySession,
          "invalid prepared script did not fail closed");
  Require(ChatScriptDecisionFromAccepted(true)
              == ChatScriptApprovalDecision::AllowSessionAndExecute
              && ChatScriptDecisionFromAccepted(false)
                     == ChatScriptApprovalDecision::DenySession,
          "dialog result did not map to strict session decisions");
}

} // namespace

int main()
{
  try
  {
    TestPreviewParsingAndOrdering();
    TestSafeRouting();
    return 0;
  }
  catch ( const std::exception & )
  {
    return 1;
  }
}
