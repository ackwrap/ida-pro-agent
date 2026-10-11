#include "ai/analysis_memory/session.hpp"
#include "ai/agent_effect_digest.hpp"
#include <algorithm>
#include <charconv>
#include <cctype>
#include <limits>
#include <set>
#include <stdexcept>

namespace ida_agent::ai::analysis_memory
{
namespace
{
using Json = nlohmann::json;
void Require(bool condition, const char *message)
{ if (!condition) throw std::runtime_error(message); }
void Fields(const Json &value, std::initializer_list<const char *> fields)
{
  Require(value.is_object() && value.size() == fields.size(), "Analysis tool fields are invalid.");
  for (const char *field : fields) Require(value.contains(field), "Analysis tool field is missing.");
}
std::int64_t Id(const Json &value, std::int64_t minimum)
{
  Require(value.is_number_integer(), "Memory ID must be an integer.");
  if (value.is_number_unsigned()) Require(value.get<std::uint64_t>() <= 2147483647, "Memory ID is too large.");
  const auto id = value.get<std::int64_t>();
  Require(id >= minimum && id <= 2147483647, "Memory ID is invalid.");
  return id;
}
std::optional<std::uint64_t> Rva(const Json &value, const BinaryContext &context)
{
  const auto address = value.get<std::string>();
  if (address.empty()) return {};
  const auto parsed = ParseHex(address);
  Require(parsed && *parsed >= context.image_base, "Memory address must be a hexadecimal address at or above the image base.");
  return *parsed - context.image_base;
}
std::string_view Trim(std::string_view text)
{
  while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) text.remove_prefix(1);
  while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back()))) text.remove_suffix(1);
  return text;
}
std::pair<std::string_view, std::string_view> Split(std::string_view text)
{
  text = Trim(text);
  const auto separator = text.find_first_of(" \t\r\n");
  if (separator == std::string_view::npos) return {text, {}};
  return {text.substr(0, separator), Trim(text.substr(separator + 1))};
}
std::int64_t CommandId(std::string_view text)
{
  std::int64_t id = 0;
  const auto parsed = std::from_chars(text.data(), text.data() + text.size(), id);
  Require(!text.empty() && parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size()
      && id > 0 && id <= 2147483647, "Provide a valid memory record ID.");
  return id;
}
bool ReadTool(std::string_view name)
{
  static const std::set<std::string_view> names{
      "ida_database_info", "ida_database_segments", "ida_database_entry_points",
      "ida_symbol_imports", "ida_symbol_exports", "ida_symbol_search", "ida_string_search", "ida_string_search_regex",
      "ida_function_get", "ida_function_search", "ida_function_disassemble", "ida_function_basic_blocks",
      "ida_function_callers", "ida_function_callees", "ida_function_chunks", "ida_function_call_graph",
      "ida_decompile", "ida_xref_query", "ida_instruction_get", "ida_memory_read", "ida_memory_search_bytes",
      "ida_type_get", "ida_type_search", "ida_type_infer", "ida_type_xrefs", "ida_type_read_struct",
      "ida_type_read_value", "ida_xref_struct_field", "ida_function_stack_frame", "ida_decompiler_locals",
      "ida_decompiler_ctree", "ida_decompiler_local_xrefs", "ida_changeset_preview", "ida_comment_get",
      "ida_analysis_trace_argument", "ida_analysis_trace_argument_callers", "ida_analysis_guard_evidence",
      "ida_analysis_status", "ida_analysis_problems"};
  return names.count(name) != 0;
}
void Signals(const Json &value, Receipt &receipt, std::size_t &budget, unsigned depth = 0)
{
  if (budget == 0 || depth > 16) return;
  --budget;
  if (value.is_object())
    for (auto field = value.begin(); field != value.end() && budget; ++field)
    {
      if ((field.key() == "hasMore" || field.key() == "truncated") && field.value().is_boolean()
          && field.value().get<bool>()) receipt.bounded = true;
      if (receipt.tool == "ida_changeset_preview"
          && ((field.key() == "conflict" && field.value() == true)
              || (field.key() == "applicable" && field.value() == false))) receipt.preview_conflict = true;
      Signals(field.value(), receipt, budget, depth + 1);
    }
  else if (value.is_array()) for (const auto &item : value) Signals(item, receipt, budget, depth + 1);
}
void Addresses(const Json &value, std::vector<std::uint64_t> &addresses, std::size_t &budget, unsigned depth = 0)
{
  if (budget == 0 || depth > 16 || addresses.size() >= 32) return;
  --budget;
  if (value.is_object())
    for (auto field = value.begin(); field != value.end() && budget; ++field)
    {
      static const std::set<std::string_view> keys{"address", "start", "end", "from", "to", "caller", "callee", "target", "entry", "functionAddress"};
      if (field.value().is_string() && keys.count(field.key()))
      {
        const auto address = ParseHex(field.value().get<std::string>());
        if (address && addresses.size() < 32
            && std::find(addresses.begin(), addresses.end(), *address) == addresses.end()) addresses.push_back(*address);
      }
      Addresses(field.value(), addresses, budget, depth + 1);
    }
  else if (value.is_array()) for (const auto &item : value) Addresses(item, addresses, budget, depth + 1);
}
Json Arguments(const AgentToolCall &call)
{
  Require(ValidText(call.id, MaxAgentToolCallIdBytes) && IsAnalysisTool(call.name)
      && call.arguments_json.size() <= MaxAgentToolArgumentsBytes, "Analysis tool call is invalid.");
  return Json::parse(call.arguments_json, [](int depth, Json::parse_event_t, Json &) {
    Require(depth <= 16, "Analysis tool arguments are too deeply nested."); return true; });
}
}

Session::Session(std::filesystem::path path, bool fts) : store_(std::move(path), fts) {}
bool Session::Bind(BinaryContext context)
{
  if (context.key != context_.key)
  {
    receipts_.clear(); receipts_truncated_ = false; last_report_ = nullptr;
  }
  context_ = std::move(context);
  available_ = store_.Open(context_);
  return available_;
}
void Session::Reset()
{
  store_.Close(); context_ = {}; available_ = false; workflow_.clear(); receipts_.clear();
  receipts_truncated_ = false; observation_revision_.clear(); last_report_ = nullptr;
}
void Session::BeginTurn(BinaryContext context)
{
  Bind(std::move(context)); receipts_.clear(); receipts_truncated_ = false; last_report_ = nullptr;
  observation_revision_ = context_.revision;
}
void Session::BeginReadBatch() { observation_revision_ = context_.revision; }
void Session::Observe(const std::vector<AgentToolResult> &results)
{
  if (!ValidContext(context_)) return;
  for (const auto &result : results)
  {
    if (!result.success || !ReadTool(result.name) || !ValidText(result.call_id, 256)
        || result.output.empty() || result.output.size() > MaxAgentToolResultBytes) continue;
    if (receipts_.size() >= 128 && !receipts_.count(result.call_id)) { receipts_truncated_ = true; continue; }
    try
    {
      const auto output = Json::parse(result.output, [](int depth, Json::parse_event_t, Json &) {
        Require(depth <= 32, "Tool result nesting exceeds the evidence budget."); return true; });
      if (!output.is_object() && !output.is_array()) continue;
      Receipt receipt{result.call_id, result.name, AgentEffectSha256(result.output), observation_revision_, {}};
      std::size_t budget = 2048;
      Addresses(output, receipt.addresses, budget);
      budget = 2048; Signals(output, receipt, budget);
      receipts_[result.call_id] = std::move(receipt);
    }
    catch (...) {}
  }
}

std::string Session::Prompt(std::string_view user_text)
{
  std::string prompt;
  if (!workflow_.empty()) prompt = "\nActive analysis workflow:\n" + Workflow(workflow_).dump();
  if (!available_) return prompt;
  try
  {
    std::vector<Fact> facts;
    std::set<std::int64_t> seen;
    const auto append = [&](const std::vector<Fact> &rows) {
      for (const auto &fact : rows) if (seen.insert(fact.id).second) facts.push_back(fact); };
    // Current-function and cursor records get priority, followed by relevant
    // terms and global notes. Address-scoped records never become global.
    for (const auto anchor : {context_.function_rva, context_.cursor_rva})
      if (anchor)
      {
        auto local = store_.Find({"", 12, anchor, true, false});
        local.erase(std::remove_if(local.begin(), local.end(), [&](const Fact &fact) {
          return fact.anchor_rva != anchor; }), local.end());
        append(local);
      }
    if (ValidText(user_text, 256)) append(store_.Find({std::string(user_text), 6, {}, true, false}));
    std::string term;
    std::size_t queries = 0;
    const auto flush = [&]() {
      if (term.size() >= 4 && term.size() <= 64 && queries++ < 4)
        append(store_.Find({term, 3, {}, true, false}));
      term.clear(); };
    for (unsigned char c : user_text)
    {
      if (c < 128 && std::isalnum(c)) term.push_back(static_cast<char>(c)); else flush();
      if (queries >= 4) break;
    }
    flush();
    append(store_.Find({"", 6, {}, true, true}));
    prompt += BuildMemoryContext(facts, context_);
  }
  catch (...) { /* Storage failure must not prevent ordinary chat. */ }
  return prompt;
}

Fact Session::ParseSave(const Json &args, std::string_view session)
{
  Fields(args, {"id", "text", "kind", "status", "address", "evidence"});
  Fact fact;
  fact.id = Id(args.at("id"), 0); fact.text = args.at("text").get<std::string>();
  fact.kind = args.at("kind").get<std::string>(); fact.status = args.at("status").get<std::string>();
  fact.anchor_rva = Rva(args.at("address"), context_);
  fact.source = "agent"; fact.session = session; fact.revision = context_.revision;
  Require(args.at("evidence").is_array() && args.at("evidence").size() <= MaxEvidence, "Memory evidence is invalid.");
  bool anchor_observed = !fact.anchor_rva.has_value();
  for (const auto &item : args.at("evidence"))
  {
    Fields(item, {"callId", "address"});
    const auto id = item.at("callId").get<std::string>();
    const auto receipt = receipts_.find(id);
    Require(receipt != receipts_.end() && receipt->second.revision == context_.revision,
        "Memory evidence must reference a successful, current-turn read tool; re-run stale evidence.");
    auto rva = Rva(item.at("address"), context_);
    if (rva)
    {
      const auto ea = context_.image_base + *rva;
      Require(std::find(receipt->second.addresses.begin(), receipt->second.addresses.end(), ea)
          != receipt->second.addresses.end(), "Memory evidence address was not returned by this tool.");
    }
    if (fact.anchor_rva)
      anchor_observed = anchor_observed || std::find(receipt->second.addresses.begin(), receipt->second.addresses.end(),
          context_.image_base + *fact.anchor_rva) != receipt->second.addresses.end();
    fact.evidence.push_back({rva, receipt->second.tool, id, receipt->second.result_sha256, receipt->second.revision});
  }
  Require(fact.kind != "observation" || anchor_observed, "Observation anchor was not returned by its evidence tools.");
  Require(ValidFact(fact), "Analysis memory record is invalid; observations require evidence.");
  return fact;
}

Json Session::Call(const AgentToolCall &call, bool allow_write, std::string_view session, bool preview)
{
  const auto args = Arguments(call);
  if (call.name == "ida_analysis_workflow_get")
  { Fields(args, {"name"}); return Workflow(args.at("name").get<std::string>()); }
  if (call.name == "ida_analysis_workflow_report") return Report(args);
  Require(available_, "Analysis memory storage is unavailable; analysis can continue without it.");
  if (call.name == "ida_analysis_memory_search")
  {
    Fields(args, {"query", "address", "limit", "includeRejected"});
    Require(args.at("includeRejected").is_boolean(), "includeRejected must be boolean.");
    const auto limit = Id(args.at("limit"), 1);
    Require(limit <= 16, "Memory result limit exceeds 16.");
    Search query{args.at("query").get<std::string>(), static_cast<std::uint32_t>(limit + 1),
        Rva(args.at("address"), context_), args.at("includeRejected").get<bool>(), false};
    const auto found = store_.Find(query);
    Json rows = Json::array();
    bool more = false;
    for (const auto &fact : found)
    {
      auto record = PresentFact(fact, context_);
      if (rows.size() == static_cast<std::size_t>(limit)
          || rows.dump().size() + record.dump().size() > 192 * 1024) { more = true; break; }
      rows.push_back(std::move(record));
    }
    return {{"records", std::move(rows)}, {"hasMore", more}, {"search", store_.UsesFts() ? "fts5+literal" : "literal"}};
  }
  Require(preview || allow_write, "The conversation session side-effect policy denied memory writes.");
  if (call.name == "ida_analysis_memory_save")
  {
    auto fact = ParseSave(args, session);
    const auto previous = fact.id ? store_.Get(fact.id) : std::nullopt;
    if (fact.id) Require(previous.has_value(), "Memory record was not found in this binary.");
    if (preview) return {{"operation", "save external analysis memory"}, {"record", PresentFact(fact, context_)},
        {"previous", previous ? PresentFact(*previous, context_) : Json(nullptr)}};
    return {{"saved", PresentFact(store_.Save(std::move(fact)), context_)}};
  }
  Fields(args, {"id"});
  const auto id = Id(args.at("id"), 1);
  const auto fact = store_.Get(id);
  Require(fact.has_value(), "Memory record was not found in this binary.");
  if (preview) return {{"operation", "delete external analysis memory"}, {"record", PresentFact(*fact, context_)}};
  return {{"deleted", store_.Forget(id)}, {"id", id}};
}

AgentToolResult Session::Invoke(const AgentToolCall &call, bool allow_write, std::string_view session) noexcept
{
  try
  {
    auto output = Call(call, allow_write, session, false).dump();
    Require(output.size() <= MaxAgentToolResultBytes, "Analysis tool result exceeded its output budget.");
    return {call.id, call.name, true, std::move(output), {}};
  }
  catch (const std::exception &error)
  {
    // Parsing libraries may include untrusted input in exception messages.
    const auto *safe = dynamic_cast<const std::runtime_error *>(&error);
    return {call.id, call.name, false, {}, safe ? std::string(safe->what()) : "Analysis tool arguments are invalid."};
  }
  catch (...) { return {call.id, call.name, false, {}, "Analysis tool failed."}; }
}
AgentToolResult Session::Preview(const AgentToolCall &call, std::string_view session) noexcept
{
  try
  {
    Require(IsMemoryMutation(call.name), "Only memory mutations can be prepared.");
    return {call.id, call.name, true, Call(call, false, session, true).dump(), {}};
  }
  catch (const std::exception &error)
  {
    const auto *safe = dynamic_cast<const std::runtime_error *>(&error);
    return {call.id, call.name, false, {}, safe ? std::string(safe->what()) : "Memory mutation arguments are invalid."};
  }
  catch (...) { return {call.id, call.name, false, {}, "Memory mutation could not be prepared."}; }
}

std::string Session::Command(std::string_view line, std::string_view session)
{
  Require(available_, "Analysis memory storage is unavailable.");
  const auto [command, argument] = Split(line);
  if (command.empty() || command == "list" || command == "search")
  {
    const auto rows = store_.Find({command == "search" ? std::string(argument) : "", 20, {}, true, false});
    if (rows.empty()) return "No matching analysis memory records.";
    std::string output = "Analysis memory (unverified; /memory help for commands):";
    for (const auto &fact : rows)
      output += "\n" + std::to_string(fact.id) + " [" + fact.kind + ", " + fact.status
          + (fact.revision == context_.revision ? "" : ", stale") + "] " + fact.text;
    if (rows.size() == 20) output += "\nShowing the first 20 records; narrow the search for more.";
    return output;
  }
  if (command == "help")
    return "/memory [list|search <text>|add <note>|add-local <note>|update <id> <note>|reject <id>|forget <id>|clear confirm]. "
        "Notes are stored outside the IDB for this binary. Clearing chat history keeps analysis memory.";
  if (command == "clear")
  {
    Require(argument == "confirm", "Use /memory clear confirm to delete this binary's analysis memory.");
    store_.Clear(); return "This binary's external analysis memory was cleared.";
  }
  if (command == "add" || command == "add-local")
  {
    Fact fact; fact.text = argument; fact.session = session; fact.revision = context_.revision;
    if (command == "add-local")
    {
      fact.anchor_rva = context_.function_rva ? context_.function_rva : context_.cursor_rva;
      Require(fact.anchor_rva.has_value(), "Select a database address before adding a local note.");
    }
    return "Saved analysis note " + std::to_string(store_.Save(std::move(fact)).id) + ".";
  }
  const auto [id_text, text] = Split(argument);
  const auto id = CommandId(id_text);
  auto fact = store_.Get(id);
  Require(fact.has_value(), "Memory record was not found in this binary.");
  if (command == "forget")
  { Require(text.empty(), "Unexpected text after memory ID."); store_.Forget(id); return "Deleted analysis memory " + std::to_string(id) + "."; }
  if (command == "reject")
  { Require(text.empty(), "Unexpected text after memory ID."); fact->status = "rejected"; }
  else if (command == "update")
  {
    fact->text = text; fact->kind = "note"; fact->source = "user"; fact->session = session;
    fact->revision = context_.revision; fact->evidence.clear();
  }
  else throw std::runtime_error("Unknown memory command. Use /memory help.");
  store_.Save(std::move(*fact));
  return "Updated analysis memory " + std::to_string(id) + ".";
}
} // namespace ida_agent::ai::analysis_memory
