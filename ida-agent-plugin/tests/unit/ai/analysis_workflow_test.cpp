#include "ai/analysis_memory/session.hpp"
#include <chrono>
#include <filesystem>
#include <iostream>
#include <stdexcept>

using namespace ida_agent::ai;
using namespace ida_agent::ai::analysis_memory;
namespace
{
using Json = nlohmann::json;
void Require(bool value, const char *message) { if (!value) throw std::runtime_error(message); }
BinaryContext Context(unsigned revision = 1)
{ return {BinaryKey(std::string(64, 'a'), "/test.i64"), DatabaseRevision("/test.i64", revision), 0x400000, 0x1234, 0x1200}; }
AgentToolCall Call(std::string name, Json arguments, std::string id = "local-tool")
{ return {std::move(id), std::move(name), arguments.dump()}; }
Json ReportArgs(const char *name = "function")
{
  return {{"name", name}, {"coverage", "Selected function and direct references only."}, {"proposedChanges", false},
      {"conclusions", Json::array({Json{{"text", "The selected function has a direct reference."},
          {"confidence", "supported"}, {"evidenceCallIds", Json::array({"xref"})}}})},
      {"uncertainties", Json::array({"Indirect calls and runtime behavior remain unknown."})}};
}
Json SaveArgs()
{
  return {{"id", 0}, {"text", "Candidate protection-check function."}, {"kind", "observation"}, {"status", "active"},
      {"address", "0x401200"}, {"evidence", Json::array({Json{{"callId", "function"}, {"address", "0x401200"}}})}};
}
void Reads(Session &session)
{
  session.BeginReadBatch();
  session.Observe({{"identity", "ida_database_info", true, "{\"database\":\"test\"}", {}},
      {"function", "ida_function_get", true, "{\"start\":\"0x401200\",\"end\":\"0x401300\"}", {}},
      {"code", "ida_decompile", true, "{\"address\":\"0x401200\",\"text\":\"return check();\"}", {}},
      {"xref", "ida_xref_query", true, "{\"items\":[{\"from\":\"0x401300\",\"to\":\"0x401200\"}]}", {}}});
}
void EvidenceAndPermissions(Session &session)
{
  session.BeginTurn(Context());
  Require(session.SelectWorkflow("function"), "workflow selection failed");
  Require(!session.SelectWorkflow("invented"), "unknown workflow selected");
  Require(session.CompletionNotice().find("incomplete") != std::string::npos, "unreported workflow appeared complete");
  auto report = Call("ida_analysis_workflow_report", ReportArgs());
  Require(!session.Invoke(report, false, "test").success, "report accepted nonexistent tool evidence");
  Reads(session);
  auto result = session.Invoke(report, false, "test");
  Require(result.success && Json::parse(result.output).at("status") == "complete", "real function workflow coverage rejected");
  Require(session.CompletionNotice().find("validated") != std::string::npos, "validated completion status missing");
  const auto save = Call("ida_analysis_memory_save", SaveArgs(), "save");
  Require(!session.Invoke(save, false, "test").success, "memory bypassed Deny/Ask without authorization");
  Require(session.Preview(save, "test").success, "valid memory mutation could not be previewed");
  auto search = Call("ida_analysis_memory_search", {{"query", ""}, {"address", ""}, {"limit", 16}, {"includeRejected", true}});
  Require(Json::parse(session.Invoke(search, false, "test").output).at("records").empty(), "preview persisted a mutation");
  result = session.Invoke(save, true, "test");
  Require(result.success, "authorized memory save failed");
  auto record = Json::parse(result.output).at("saved");
  Require(record.at("source") == "agent" && record.at("verifiedConclusion") == false, "memory fabricated analyst verification");
  Require(record.at("evidence").at(0).at("tool") == "ida_function_get", "evidence provenance missing");
  auto wrong = SaveArgs(); wrong["evidence"][0]["callId"] = "invented";
  Require(!session.Preview(Call("ida_analysis_memory_save", wrong), "test").success, "fabricated call ID accepted");
  wrong = SaveArgs(); wrong["evidence"][0]["address"] = "0x409999";
  Require(!session.Preview(Call("ida_analysis_memory_save", wrong), "test").success, "fabricated address accepted");
  wrong = SaveArgs(); wrong["address"] = "0x409999";
  Require(!session.Preview(Call("ida_analysis_memory_save", wrong), "test").success, "unobserved claim anchor accepted");
  wrong = SaveArgs(); wrong["unknown"] = true;
  Require(!session.Preview(Call("ida_analysis_memory_save", wrong), "test").success, "unknown tool field accepted");
  wrong = SaveArgs(); wrong["id"] = 0.5;
  Require(!session.Preview(Call("ida_analysis_memory_save", wrong), "test").success, "fractional ID accepted");
  const auto id = record.at("id").get<std::int64_t>();
  Require(!session.Invoke(Call("ida_analysis_memory_forget", {{"id", id}}), false, "test").success, "delete bypassed session authorization");
  Require(session.Invoke(Call("ida_analysis_memory_forget", {{"id", id}}), true, "test").success, "authorized delete failed");
  session.Bind(Context(2));
  Require(session.Status().at("lastReportStale") == true, "old report wasn't marked stale");
  Require(!session.Invoke(report, false, "test").success, "stale evidence was accepted");
  Require(!session.Preview(save, "test").success, "stale evidence was saved");
  session.BeginTurn(Context(2));
  session.BeginReadBatch(); session.Bind(Context(3));
  session.Observe({{"old", "ida_function_get", true, "{\"start\":\"0x401200\"}", {}}});
  Require(session.Status().at("receipts").at(0).at("stale") == true, "read spanning an IDB change was incorrectly refreshed");
}
void WorkflowCoverage(Session &session)
{
  session.BeginTurn(Context()); Reads(session);
  Require(session.SelectWorkflow("protection"), "protection workflow selection failed");
  Require(!session.Invoke(Call("ida_analysis_workflow_report", ReportArgs("function")), false, "test").success,
      "report changed the active workflow silently");
  auto args = ReportArgs("protection");
  auto result = session.Invoke(Call("ida_analysis_workflow_report", args), false, "test");
  Require(result.success && Json::parse(result.output).at("status") == "partial", "partial protection workflow claimed complete coverage");
  const auto gaps = Json::parse(result.output).at("missingSteps");
  Require(gaps.size() == 3, "protection report omitted segment/import/string gaps");
  session.Observe({{"segments", "ida_database_segments", true, "{\"items\":[]}", {}},
      {"imports", "ida_symbol_imports", true, "{\"items\":[]}", {}},
      {"strings", "ida_string_search", false, {}, "failed"}});
  result = session.Invoke(Call("ida_analysis_workflow_report", args), false, "test");
  Require(Json::parse(result.output).at("missingSteps") == Json::array({"strings"}), "failed read counted as evidence");
  session.Observe({{"strings", "ida_string_search", true, "{\"items\":[]}", {}}});
  result = session.Invoke(Call("ida_analysis_workflow_report", args), false, "test");
  Require(Json::parse(result.output).at("status") == "complete", "complete protection observations were not counted");
  Require(session.SelectWorkflow("types"), "type workflow selection failed");
  args = ReportArgs("types"); args["proposedChanges"] = true;
  session.Observe({{"types", "ida_type_search", true, "{\"items\":[]}", {}},
      {"locals", "ida_decompiler_locals", true, "{\"locals\":[]}", {}}});
  result = session.Invoke(Call("ida_analysis_workflow_report", args), false, "test");
  Require(Json::parse(result.output).at("missingSteps") == Json::array({"preview"}), "proposed type writes skipped ChangeSet preview");
  session.Observe({{"preview", "ida_changeset_preview", true, "{\"conflicts\":[]}", {}}});
  result = session.Invoke(Call("ida_analysis_workflow_report", args), false, "test");
  Require(Json::parse(result.output).at("status") == "complete", "type preparation could not complete after preview");
  Require(Json::parse(result.output).at("changesAppliedByReport") == false, "report claimed to apply changes");
  session.Observe({{"bounded", "ida_xref_query", true, "{\"items\":[],\"hasMore\":true}", {}},
      {"conflict", "ida_changeset_preview", true, "{\"applicable\":false,\"items\":[{\"conflict\":true}]}", {}}});
  result = session.Invoke(Call("ida_analysis_workflow_report", args), false, "test");
  Require(Json::parse(result.output).at("status") == "partial", "bounded evidence claimed complete coverage");
  Require(Json::parse(result.output).at("previewHasConflicts") == true, "type preview conflicts disappeared from report");
  Require(session.CompletionNotice().find("partial") != std::string::npos, "partial completion notice missing");
  const auto &definitions = ToolDefinitions();
  Require(definitions.size() == 5, "analysis tool catalog changed unexpectedly");
  for (const auto &tool : definitions)
  {
    Require(tool.name.find('.') == std::string::npos, "analysis tool has an incompatible dot name");
    Require(tool.parameters.at("additionalProperties") == false, "analysis tool is not strict");
    Require(tool.parameters.at("required").size() == tool.parameters.at("properties").size(), "schema omits required fields");
  }
}
void CommandsAndUnavailable(const std::filesystem::path &path)
{
  Session session(path, false); session.BeginTurn(Context());
  session.Command("add global protection note", "user");
  session.Command("add-local local note", "user");
  auto prompt = session.Prompt("protection");
  Require(prompt.find("global protection note") != std::string::npos && prompt.find("local note") != std::string::npos,
      "notes were not integrated into request context");
  session.Command("reject 1", "user");
  Require(session.Prompt("protection").find("rejected") != std::string::npos, "rejected finding wasn't retained as a warning");
  session.Command("update 2 corrected note", "user");
  Require(session.Command("search corrected", "user").find("corrected note") != std::string::npos, "user update wasn't searchable");
  session.Reset(); session.BeginTurn(Context());
  Require(session.Command("list", "user").find("corrected note") != std::string::npos, "new session lost saved analysis memory");
  session.Command("clear confirm", "user");
  Require(session.Command("list", "user").find("No matching") != std::string::npos, "clear did not remove binary memory");
  Session unavailable(path.parent_path(), false);
  unavailable.BeginTurn(Context()); unavailable.SelectWorkflow("function");
  Require(unavailable.Prompt("question").find("Active analysis workflow") != std::string::npos,
      "storage failure blocked a workflow prompt");
  Require(unavailable.Invoke(Call("ida_analysis_workflow_get", {{"name", "function"}}), false, "test").success,
      "storage failure blocked read-only workflows");
}
}
int main()
{
  const auto parent = std::filesystem::current_path();
  const auto directory = parent / ("analysis-workflow-test-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
  int status = 0;
  try
  {
    std::filesystem::create_directory(directory);
#ifndef _WIN32
    std::filesystem::permissions(directory, std::filesystem::perms::owner_all);
#endif
    { Session session(directory / "evidence.db", false); EvidenceAndPermissions(session); WorkflowCoverage(session); }
    CommandsAndUnavailable(directory / "commands.db");
    std::cout << "Analysis workflow coverage, evidence, approvals and chat commands passed.\n";
  }
  catch (const std::exception &error) { std::cerr << error.what() << '\n'; status = 1; }
  std::error_code error;
  if (directory.parent_path() == parent && directory.filename().string().rfind("analysis-workflow-test-", 0) == 0)
    std::filesystem::remove_all(directory, error);
  return status;
}
