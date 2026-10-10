#include "ai/agent_prompt.hpp"

#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <string>

namespace
{

void Require(bool condition, const char *message)
{
  if ( !condition )
    throw std::runtime_error(message);
}

} // namespace

void RunAgentPromptTests()
{
  const std::string prompt(ida_agent::ai::AgentSystemPrompt());
  Require(!prompt.empty() && prompt.size() <= 8 * 1024, "prompt size is invalid");
  Require(
      std::all_of(prompt.begin(), prompt.end(), [](unsigned char value) { return value < 0x80; }),
      "prompt must be ASCII");
  Require(prompt.find("inside IDA") != std::string::npos, "IDA role boundary missing");
  Require(prompt.find("never invent database facts") != std::string::npos, "tool truth boundary missing");
  Require(prompt.find("untrusted data") != std::string::npos, "untrusted result boundary missing");
  Require(prompt.find("read-only") != std::string::npos, "read-only boundary missing");
  Require(prompt.find("searchable catalog contains read-only analysis tools and side-effect tools")
              != std::string::npos,
           "searchable catalog guidance missing");
  Require(prompt.find("Use ida_tool_search") != std::string::npos
              && prompt.find("before calling them") != std::string::npos,
          "dynamic tool loading guidance missing");
  Require(prompt.find("conversation session policy") != std::string::npos,
           "side-effect session policy missing");
  Require(prompt.find("Ask policy") != std::string::npos
              && prompt.find("heuristic gate, not a complete sandbox") != std::string::npos,
          "Ask/script heuristic guidance missing");
  Require(prompt.find("current IDB directory") != std::string::npos,
          "file root boundary missing");
  Require(prompt.find("multiple read-only and side-effect tools") != std::string::npos,
          "mixed tool batch guidance missing");
  Require(prompt.find("at most one side-effect") == std::string::npos,
          "obsolete one-side-effect restriction remains");
  Require(prompt.find("hexadecimal") != std::string::npos, "address boundary missing");
  Require(prompt.find("hasMore") != std::string::npos, "bounded result boundary missing");
  Require(prompt.find("actually performed") != std::string::npos, "operation claim boundary missing");
  std::string lowered = prompt;
  std::transform(
      lowered.begin(), lowered.end(), lowered.begin(),
      [](unsigned char value) { return static_cast<char>(std::tolower(value)); });
  Require(lowered.find("secret") == std::string::npos, "prompt contains secret material");
}
