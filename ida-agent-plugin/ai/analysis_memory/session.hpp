#pragma once
#include "ai/analysis_memory/store.hpp"
#include "ai/agent_tool_registry.hpp"
#include <map>

namespace ida_agent::ai::analysis_memory
{
struct Receipt
{
  std::string id;
  std::string tool;
  std::string result_sha256;
  std::string revision;
  std::vector<std::uint64_t> addresses;
  bool bounded = false;
  bool preview_conflict = false;
};

const std::vector<AgentToolDefinition> &ToolDefinitions();
bool IsAnalysisTool(std::string_view name);
bool IsMemoryMutation(std::string_view name);
nlohmann::json Workflow(std::string_view name);

class Session final
{
public:
  explicit Session(std::filesystem::path path = {}, bool fts = true);
  bool Bind(BinaryContext context);
  void Reset();
  void BeginTurn(BinaryContext context);
  void BeginReadBatch();
  void Observe(const std::vector<AgentToolResult> &results);
  bool SelectWorkflow(std::string_view name);
  const std::string &ActiveWorkflow() const noexcept { return workflow_; }
  std::string WorkflowPrompt() const;
  std::string Prompt(std::string_view user_text, std::size_t budget = MaxContextBytes);
  std::string Command(std::string_view command, std::string_view session);
  nlohmann::json Status() const;
  std::string CompletionNotice() const;
  AgentToolResult Invoke(const AgentToolCall &call, bool allow_write,
      std::string_view session) noexcept;
  // Validation and a concrete preview only; this never writes.
  AgentToolResult Preview(const AgentToolCall &call, std::string_view session) noexcept;
private:
  nlohmann::json Call(const AgentToolCall &call, bool allow_write,
      std::string_view session, bool preview);
  Fact ParseSave(const nlohmann::json &arguments, std::string_view session);
  nlohmann::json Report(const nlohmann::json &arguments);
  Store store_;
  BinaryContext context_;
  bool available_ = false;
  std::string workflow_;
  std::map<std::string, Receipt> receipts_;
  nlohmann::json last_report_;
  std::string observation_revision_;
  bool receipts_truncated_ = false;
};
} // namespace ida_agent::ai::analysis_memory
