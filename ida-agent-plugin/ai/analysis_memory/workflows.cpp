#include "ai/analysis_memory/session.hpp"
#include <algorithm>
#include <stdexcept>

namespace ida_agent::ai::analysis_memory
{
namespace
{
using Json = nlohmann::json;
Json Step(const char *id, std::initializer_list<const char *> tools, const char *purpose)
{
  return {{"id", id}, {"anyOfTools", tools}, {"purpose", purpose}};
}
Json ReceiptJson(const Receipt &receipt, const BinaryContext &context)
{
  Json addresses = Json::array();
  for (auto address : receipt.addresses) addresses.push_back(Hex(address));
  return {{"callId", receipt.id}, {"tool", receipt.tool}, {"addresses", std::move(addresses)},
      {"resultSha256", receipt.result_sha256}, {"stale", receipt.revision != context.revision},
      {"bounded", receipt.bounded}, {"previewConflict", receipt.preview_conflict}};
}
}

nlohmann::json Workflow(std::string_view name)
{
  Json steps = Json::array({Step("identity", {"ida_database_info"}, "Identify the binary, architecture and analysis scope.")});
  std::string task;
  if (name == "protection")
  {
    task = "Assess protection strength against explicit attacker goals using static evidence. "
        "Distinguish observed mechanisms, hypotheses, analysis effort, and unknown runtime behavior. "
        "Imports/strings are leads, not proof that anti-debugging, packing or licensing checks execute. "
        "Inspect representative entry/check/dispatch functions and their callers; explain bypass prerequisites, "
        "coverage and confidence without an unsupported numeric score.";
    steps.push_back(Step("structure", {"ida_database_segments"}, "Inspect segment permissions and entry points; state sampling/truncation."));
    steps.push_back(Step("imports", {"ida_symbol_imports"}, "Inspect imported protection/runtime APIs."));
    steps.push_back(Step("strings", {"ida_string_search", "ida_string_search_regex"}, "Inspect protection-related strings and follow their xrefs."));
    steps.push_back(Step("code", {"ida_decompile", "ida_function_disassemble"}, "Inspect code for the reported mechanisms; cite addresses."));
    steps.push_back(Step("references", {"ida_xref_query", "ida_function_callers"}, "Trace where candidate mechanisms are called or referenced."));
  }
  else if (name == "function")
  {
    task = "Investigate the selected function's inputs, outputs, calls and data flow. "
        "Read cursor/function boundaries before choosing a target. Corroborate pseudocode with instructions "
        "where types or control flow are uncertain. Use argument/guard tools for parameter questions; "
        "xref traversal alone is not semantic taint analysis. Record unresolved aliases, indirect calls, "
        "unsupported returns and truncated paths explicitly.";
    steps.push_back(Step("function", {"ida_function_get"}, "Confirm target function and boundaries."));
    steps.push_back(Step("code", {"ida_decompile", "ida_function_disassemble"}, "Read function behavior and check decompiler uncertainty."));
    steps.push_back(Step("references", {"ida_xref_query", "ida_function_callers", "ida_function_callees"}, "Inspect callers/callees or xrefs; label static reachability limits."));
  }
  else if (name == "types")
  {
    task = "Prepare type recovery from observed field offsets, access widths, call arguments and locals. "
        "Inspect existing type definitions and references. Separate candidate types from established declarations. "
        "If proposing IDB edits, use ida_changeset_preview first and retain its conflicts/old values. "
        "Applying a ChangeSet is a separate explicit side effect under the session policy; "
        "a preview or this report never proves that changes were applied.";
    steps.push_back(Step("function", {"ida_function_get"}, "Identify the function(s) supporting the candidate type."));
    steps.push_back(Step("code", {"ida_decompile", "ida_function_disassemble"}, "Collect accesses and call-site evidence."));
    steps.push_back(Step("existing-types", {"ida_type_get", "ida_type_search"}, "Inspect matching existing types before suggesting a new one."));
    steps.push_back(Step("candidates", {"ida_type_infer", "ida_decompiler_locals", "ida_function_stack_frame"}, "Inspect inferred types, decompiler locals or the stack layout."));
  }
  else throw std::runtime_error("Unknown analysis workflow. Choose protection, function or types.");
  return {{"name", name}, {"task", task}, {"steps", steps},
      {"reportTool", "ida_analysis_workflow_report"},
      {"reportInstructions", "Finish with the report tool using actual receipt call IDs. Describe missing/blocked work "
        "in uncertainties; the validator returns partial coverage if a required observation is absent. "
        "Tool success validates provenance only. Recheck remembered facts. Save useful findings only explicitly "
        "through analysis memory tools and the existing approval policy."}};
}

bool Session::SelectWorkflow(std::string_view name)
{
  if (name == "off") { workflow_.clear(); last_report_ = nullptr; return true; }
  try { Workflow(name); workflow_ = name; last_report_ = nullptr; return true; }
  catch (...) { return false; }
}

nlohmann::json Session::Status() const
{
  Json receipts = Json::array();
  for (const auto &entry : receipts_) receipts.push_back(ReceiptJson(entry.second, context_));
  return {{"workflow", workflow_}, {"memoryAvailable", available_},
      {"identity", context_.key}, {"identityFallback", context_.key.rfind("idb:", 0) == 0},
      {"search", store_.UsesFts() ? "fts5+literal" : "literal"},
      {"receipts", std::move(receipts)}, {"receiptsTruncated", receipts_truncated_},
      {"lastReportStale", last_report_.is_object() && last_report_.value("revision", "") != context_.revision}, {"lastReport", last_report_}};
}

std::string Session::CompletionNotice() const
{
  if (workflow_.empty()) return {};
  if (!last_report_.is_object() || last_report_.value("workflow", "") != workflow_
      || last_report_.value("revision", "") != context_.revision)
    return "Analysis workflow is incomplete: no current validated evidence report was submitted. Use /workflow status to inspect coverage.";
  if (last_report_.value("status", "") != "complete")
    return "Analysis workflow has partial coverage. Missing or bounded evidence is recorded in /workflow status.";
  return "Analysis workflow tool coverage was validated. Conclusions still require analyst judgment; inspect /workflow status for evidence and preview conflicts.";
}

nlohmann::json Session::Report(const nlohmann::json &args)
{
  if (!args.is_object() || args.size() != 5 || !args.contains("name") || !args.contains("coverage")
      || !args.contains("proposedChanges") || !args.contains("conclusions") || !args.contains("uncertainties"))
    throw std::runtime_error("Workflow report fields are invalid.");
  const auto plan = Workflow(args.at("name").get<std::string>());
  if (!workflow_.empty() && plan.at("name") != workflow_)
    throw std::runtime_error("Report workflow does not match the active workflow.");
  if (!args.at("coverage").is_string() || !ValidText(args.at("coverage").get<std::string>(), 2048)
      || !args.at("proposedChanges").is_boolean() || !args.at("conclusions").is_array()
      || args.at("conclusions").size() > 12 || !args.at("uncertainties").is_array()
      || args.at("uncertainties").size() > 12) throw std::runtime_error("Workflow report is invalid.");
  if (args.at("proposedChanges").get<bool>() && plan.at("name") != "types")
    throw std::runtime_error("Only the type-recovery preparation workflow may propose changes.");
  for (const auto &text : args.at("uncertainties"))
    if (!text.is_string() || !ValidText(text.get<std::string>(), 1024)) throw std::runtime_error("Invalid uncertainty text.");
  Json conclusions = Json::array();
  for (const auto &conclusion : args.at("conclusions"))
  {
    if (!conclusion.is_object() || conclusion.size() != 3 || !conclusion.contains("text")
        || !conclusion.contains("confidence") || !conclusion.contains("evidenceCallIds"))
      throw std::runtime_error("Conclusion fields are invalid.");
    const auto text = conclusion.at("text").get<std::string>();
    const auto confidence = conclusion.at("confidence").get<std::string>();
    const auto &ids = conclusion.at("evidenceCallIds");
    if (!ValidText(text, 2048) || (confidence != "observation" && confidence != "supported" && confidence != "hypothesis")
        || !ids.is_array() || ids.size() > 8 || (confidence != "hypothesis" && ids.empty()))
      throw std::runtime_error("A supported conclusion needs successful tool evidence.");
    Json evidence = Json::array();
    for (const auto &id : ids)
    {
      const auto entry = receipts_.find(id.get<std::string>());
      if (entry == receipts_.end() || entry->second.revision != context_.revision)
        throw std::runtime_error("Conclusion evidence is missing or stale; re-run the read tool.");
      evidence.push_back(ReceiptJson(entry->second, context_));
    }
    conclusions.push_back({{"text", text}, {"confidence", confidence}, {"evidence", std::move(evidence)}});
  }
  Json steps = plan.at("steps");
  if (args.at("proposedChanges").get<bool>())
    steps.push_back(Step("preview", {"ida_changeset_preview"}, "Preview proposed type changes and surface conflicts."));
  Json missing = Json::array();
  for (const auto &step : steps)
  {
    bool observed = false;
    for (const auto &entry : receipts_)
      if (entry.second.revision == context_.revision
          && std::find(step.at("anyOfTools").begin(), step.at("anyOfTools").end(), entry.second.tool)
              != step.at("anyOfTools").end()) observed = true;
    if (!observed) missing.push_back(step.at("id"));
  }
  Json warnings = Json::array();
  bool preview_conflict = false;
  for (const auto &entry : receipts_)
    if (entry.second.revision == context_.revision)
    {
      if (entry.second.bounded) warnings.push_back(ReceiptJson(entry.second, context_));
      if (entry.second.preview_conflict) preview_conflict = true;
    }
  const bool partial = !missing.empty() || !warnings.empty() || receipts_truncated_;
  last_report_ = {{"workflow", plan.at("name")}, {"status", partial ? "partial" : "complete"},
      {"boundedEvidence", std::move(warnings)}, {"previewHasConflicts", preview_conflict},
      {"coverage", args.at("coverage")}, {"missingSteps", std::move(missing)},
      {"conclusions", std::move(conclusions)}, {"uncertainties", args.at("uncertainties")},
      {"revision", context_.revision}, {"proposedChanges", args.at("proposedChanges")}, {"changesAppliedByReport", false},
      {"validation", "Successful current-turn tool provenance; conclusions still require analyst judgment."}};
  return last_report_;
}
} // namespace ida_agent::ai::analysis_memory
