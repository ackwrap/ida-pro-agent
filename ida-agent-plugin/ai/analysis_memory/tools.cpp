#include "ai/analysis_memory/session.hpp"

namespace ida_agent::ai::analysis_memory
{
namespace
{
using Json = nlohmann::json;
Json Text(int maximum, int minimum = 0) { return {{"type", "string"}, {"maxLength", maximum}, {"minLength", minimum}}; }
Json Integer(int minimum, int maximum) { return {{"type", "integer"}, {"minimum", minimum}, {"maximum", maximum}}; }
Json Enum(std::initializer_list<const char *> values) { return {{"type", "string"}, {"enum", values}}; }
Json Object(Json properties)
{
  Json required = Json::array();
  for (auto field = properties.begin(); field != properties.end(); ++field) required.push_back(field.key());
  return {{"type", "object"}, {"properties", std::move(properties)}, {"required", std::move(required)}, {"additionalProperties", false}};
}
Json Array(Json item, int maximum) { return {{"type", "array"}, {"items", std::move(item)}, {"maxItems", maximum}}; }
Json Name() { return Enum({"protection", "function", "types"}); }
}

const std::vector<AgentToolDefinition> &ToolDefinitions()
{
  static const std::vector<AgentToolDefinition> tools{
      {"ida_analysis_memory_search", "Search this binary's external analysis memory. Stored claims are unverified; revalidate stale evidence. Literal UTF-8 query; address empty searches all scopes.", Object({
          {"query", Text(256)}, {"address", Text(18)}, {"limit", Integer(1, 16)},
          {"includeRejected", {{"type", "boolean"}}}})},
      {"ida_analysis_memory_save", "Save/update a bounded analysis record outside the IDB after session approval. id=0 creates. Evidence must reference successful read tools in this turn; observation requires evidence. Never imply that a saved conclusion is verified.", Object({
          {"id", Integer(0, 2147483647)}, {"text", Text(4096, 1)},
          {"kind", Enum({"note", "observation", "hypothesis", "question"})},
          {"status", Enum({"active", "rejected"})}, {"address", Text(18)},
          {"evidence", Array(Object({{"callId", Text(256, 1)}, {"address", Text(18)}}), 8)}})},
      {"ida_analysis_memory_forget", "Delete one record from this binary's external memory after session approval. Never modifies the IDB.", Object({{"id", Integer(1, 2147483647)}})},
      {"ida_analysis_workflow_get", "Read an evidence-oriented protection, function/data-flow, or type-recovery workflow and its required tool observations. Discover the named analysis tools before calling them.", Object({{"name", Name()}})},
      {"ida_analysis_workflow_report", "Validate a structured workflow report against successful read-tool receipts from this turn. Returns complete/partial coverage, evidence addresses and remaining gaps; this verifies provenance, not the truth of conclusions. Does not apply changes or save memory.", Object({
          {"name", Name()}, {"coverage", Text(2048, 1)}, {"proposedChanges", {{"type", "boolean"}}},
          {"conclusions", Array(Object({{"text", Text(2048, 1)},
              {"confidence", Enum({"observation", "supported", "hypothesis"})},
              {"evidenceCallIds", Array(Text(256, 1), 8)}}), 12)},
          {"uncertainties", Array(Text(1024, 1), 12)}})},
  };
  return tools;
}

bool IsAnalysisTool(std::string_view name)
{
  for (const auto &tool : ToolDefinitions()) if (tool.name == name) return true;
  return false;
}
bool IsMemoryMutation(std::string_view name)
{
  return name == "ida_analysis_memory_save" || name == "ida_analysis_memory_forget";
}
} // namespace ida_agent::ai::analysis_memory
