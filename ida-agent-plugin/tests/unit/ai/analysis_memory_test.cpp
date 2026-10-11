#include "ai/analysis_memory/store.hpp"
#include <chrono>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#ifdef _WIN32
#include <winsqlite/winsqlite3.h>
#else
#include <sqlite3.h>
#endif

using namespace ida_agent::ai::analysis_memory;
namespace
{
void Require(bool value, const char *message) { if (!value) throw std::runtime_error(message); }
template <class Action> void Reject(Action action, const char *message)
{
  bool rejected = false;
  try { action(); } catch (const std::exception &) { rejected = true; }
  Require(rejected, message);
}
BinaryContext Context(char digest, std::uint32_t revision = 1, std::uint64_t base = 0x400000)
{
  return {BinaryKey(std::string(64, digest), "/sample/test.i64"),
      DatabaseRevision("/sample/test.i64", revision), base, 0x1234, 0x1200};
}
Fact Note(const BinaryContext &context, std::string text)
{
  Fact fact; fact.text = std::move(text); fact.revision = context.revision; fact.session = "test-session";
  return fact;
}
struct Sandbox
{
  std::filesystem::path parent = std::filesystem::current_path();
  std::filesystem::path path = parent / ("analysis-memory-test-" + std::to_string(
      std::chrono::steady_clock::now().time_since_epoch().count()));
  Sandbox()
  {
    Require(!std::filesystem::exists(path), "sandbox collision");
    std::filesystem::create_directory(path);
#ifndef _WIN32
    std::filesystem::permissions(path, std::filesystem::perms::owner_all);
#endif
  }
  ~Sandbox()
  {
    std::error_code error;
    if (path.parent_path() == parent && path.filename().string().rfind("analysis-memory-test-", 0) == 0)
      std::filesystem::remove_all(path, error);
  }
};

void FixtureSql(const std::filesystem::path &path, const std::string &sql)
{
  sqlite3 *raw = nullptr;
  const auto result = sqlite3_open_v2(path.u8string().c_str(), &raw, SQLITE_OPEN_READWRITE, nullptr);
  std::unique_ptr<sqlite3, decltype(&sqlite3_close_v2)> db(raw, sqlite3_close_v2);
  Require(result == SQLITE_OK, "fixture database open failed");
  Require(sqlite3_exec(raw, sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK, "fixture SQL failed");
}

void CorruptionAndFutureSchema(const std::filesystem::path &directory)
{
  const auto context = Context('f');
  const auto corrupt = directory / "corrupt.db";
  { Store store(corrupt, false); Require(store.Open(context), "corruption fixture open failed"); store.Save(Note(context, "original note")); }
  FixtureSql(corrupt, "UPDATE analysis_facts SET payload='{' WHERE id=1");
  {
    Store store(corrupt, false); Require(store.Open(context), "corrupt payload prevented opening storage");
    Reject([&] { store.Find({"", 20}); }, "malformed stored JSON was accepted");
  }
  const auto deep = std::string(100, '[') + "0" + std::string(100, ']');
  FixtureSql(corrupt, "UPDATE analysis_facts SET payload='" + deep + "' WHERE id=1");
  {
    Store store(corrupt, false); Require(store.Open(context), "deep payload fixture open failed");
    Reject([&] { store.Get(1); }, "deep persisted JSON escaped the decoder budget");
    store.Clear();
    Require(store.Find({"", 20}).empty(), "explicit clearing could not recover corrupted records");
  }
  const auto future = directory / "future.db";
  { Store store(future, false); Require(store.Open(context), "future schema fixture open failed"); store.Save(Note(context, "future note")); }
  FixtureSql(future, "PRAGMA user_version=2");
  Store unsupported(future, false);
  Require(!unsupported.Open(context), "unsupported future schema was silently downgraded");
  sqlite3 *raw = nullptr;
  Require(sqlite3_open_v2(future.u8string().c_str(), &raw, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK, "future schema check open failed");
  std::unique_ptr<sqlite3, decltype(&sqlite3_close_v2)> db(raw, sqlite3_close_v2);
  sqlite3_stmt *statement = nullptr;
  Require(sqlite3_prepare_v2(raw, "PRAGMA user_version", -1, &statement, nullptr) == SQLITE_OK, "future schema query failed");
  std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> row(statement, sqlite3_finalize);
  Require(sqlite3_step(statement) == SQLITE_ROW && sqlite3_column_int(statement, 0) == 2, "future schema was modified");
}

void StoreAndIsolation(const std::filesystem::path &path)
{
  const auto first = Context('a');
  const auto other = Context('b');
  std::int64_t id = 0;
  {
    Store store(path, false);
    Require(store.Open(first), "memory store failed to open");
    Require(!store.UsesFts(), "literal fallback did not remain enabled");
    auto note = Note(first, "Anti-debug authentication check at dispatch; 100%_ literal.");
    note.anchor_rva = 0x1200;
    const auto saved = store.Save(note); id = saved.id;
    Require(id > 0 && saved.created_at > 0, "saved record metadata missing");
    Require(store.Find({"AUTHENTICATION", 20}).size() == 1, "literal ASCII search failed");
    Require(store.Find({"100%_", 20}).size() == 1, "literal wildcard search changed meaning");
    Require(store.Find({"' OR 1=1 --", 20}).empty(), "query escaped SQL binding");
    Require(store.Open(other), "second binary could not open");
    Require(store.Find({"", 20}).empty() && !store.Get(id), "binary isolation leaked a record");
    Require(!store.Forget(id), "other binary deleted a record");
    auto overwrite = Note(other, "overwrite"); overwrite.id = id;
    Reject([&] { store.Save(overwrite); }, "other binary overwrote a record");
    store.Clear();
    Require(store.Open(first) && store.Get(id).has_value(), "other binary clearing affected this binary");
  }
  {
    Store restarted(path, false);
    auto rebased = Context('a', 2, 0x800000);
    Require(restarted.Open(rebased), "restart could not read existing memory");
    auto saved = restarted.Get(id);
    Require(saved && saved->text.find("authentication") != std::string::npos, "saved memory did not persist");
    const auto presented = PresentFact(*saved, rebased);
    Require(presented.at("address") == "0x801200", "RVA did not survive rebase");
    Require(presented.at("stale") == true && presented.at("verifiedConclusion") == false, "stale/unverified boundary missing");
    saved->text = "revised observation lead";
    saved->status = "rejected";
    restarted.Save(*saved);
    Require(restarted.Find({"revised", 20}).empty(), "rejected claim appears as active");
    Require(restarted.Find({"revised", 20, {}, true}).size() == 1, "rejected claim cannot be retrieved explicitly");
    Require(restarted.Forget(id) && !restarted.Get(id), "delete did not persist");
  }
}

void SearchAndScope(const std::filesystem::path &path)
{
  auto context = Context('c');
  Store fallback(path, false); Require(fallback.Open(context), "fallback open failed");
  fallback.Save(Note(context, "\xE4\xBF\x9D\xE6\x8A\xA4\xE5\xBC\xBA\xE5\xBA\xA6 \"quoted\" anti-debug"));
  auto local = Note(context, "local dispatch note"); local.anchor_rva = 0x1200; fallback.Save(local);
  auto elsewhere = Note(context, "another function"); elsewhere.anchor_rva = 0x2400; fallback.Save(elsewhere);
  Require(fallback.Find({"\xE4\xBF\x9D\xE6\x8A\xA4", 20}).size() == 1, "UTF-8 literal retrieval failed");
  Require(fallback.Find({"\"quoted\"", 20}).size() == 1, "quoted literal retrieval failed");
  const auto scoped = fallback.Find({"", 20, 0x1200});
  Require(scoped.size() == 2 && scoped.front().anchor_rva == 0x1200, "local scope includes another function or loses priority");
  Require(fallback.Find({"", 20, {}, false, true}).size() == 1, "global retrieval includes local facts");
  {
    Store indexed(path, true); Require(indexed.Open(context), "optional FTS store failed to open");
    Require(indexed.Find({"\"quoted\"", 20}).size() == 1, "FTS/literal quote fallback failed");
    if (indexed.UsesFts())
      Require(indexed.Find({"anti debug", 20}).size() == 1, "FTS phrase index was not populated");
    indexed.Clear();
  }
  fallback.Save(Note(context, "newly added anti-debug record after fallback change"));
  Store reindexed(path, true); Require(reindexed.Open(context), "index reopen failed");
  if (reindexed.UsesFts()) Require(reindexed.Find({"anti debug", 20}).size() == 1, "FTS was not rebuilt after fallback writes/clear");
  Require(reindexed.Find({"local", 20}).empty(), "deleted records remained in search");
}

void BoundsAndCodec(const std::filesystem::path &path)
{
  const auto context = Context('d');
  Require(BinaryKey("", "/sample/test.i64").rfind("idb:", 0) == 0, "missing digest fallback is not explicit");
  Require(BinaryKey("", "").empty(), "empty identity accepted");
  Require(BinaryKey(std::string(64, 'a'), "/other.i64") == Context('a').key, "same input digest changed identity after IDB move");
  Require(DatabaseRevision("/other.i64", 1) != context.revision, "copied IDB did not invalidate evidence revision");
  Require(!ParseHex("0x10000000000000000") && !ParseHex("1234"), "invalid address accepted");
  Store store(path, false); Require(store.Open(context), "bounds store open failed");
  Reject([&] { store.Find({"", 0}); }, "zero search bound accepted");
  Reject([&] { store.Find({std::string(257, 'x'), 1}); }, "oversized query accepted");
  auto invalid = Note(context, std::string(MaxFactBytes + 1, 'x'));
  Reject([&] { store.Save(invalid); }, "oversized fact accepted");
  invalid = Note(context, std::string("bad\0text", 8));
  Reject([&] { store.Save(invalid); }, "NUL fact accepted");
  invalid = Note(context, std::string("\xC0\xAF", 2));
  Reject([&] { store.Save(invalid); }, "invalid UTF-8 accepted");
  invalid = Note(context, "unsupported observed claim"); invalid.kind = "observation";
  Reject([&] { store.Save(invalid); }, "observation without evidence accepted");
  auto fact = Note(context, "hypothesis"); fact.kind = "hypothesis";
  auto encoded = EncodeFact(fact);
  Require(DecodeFact(encoded).has_value(), "fact codec failed round trip");
  encoded["unknown"] = true;
  Require(!DecodeFact(encoded), "unknown persisted field accepted");
  fact.anchor_rva = 0xffffffffffffffffULL;
  Require(PresentFact(fact, context).at("address").is_null(), "rebasing overflow returned a false address");
  std::vector<Fact> facts;
  for (unsigned index = 0; index != 12; ++index) facts.push_back(Note(context, std::string(1500, 'x')));
  const auto prompt = BuildMemoryContext(facts, context);
  Require(!prompt.empty() && prompt.size() <= MaxContextBytes, "memory prompt exceeded budget");
  Require(prompt.find("untrusted") != std::string::npos && prompt.find("verifiedConclusion") != std::string::npos,
      "context lost provenance/verification boundary");
  Require(BuildMemoryContext(facts, context, 50).empty(), "too-small budget emitted incomplete JSON");
  for (unsigned index = 0; index != 512; ++index) store.Save(Note(context, "bounded note " + std::to_string(index)));
  Reject([&] { store.Save(Note(context, "over capacity")); }, "per-binary quota not enforced");
  Require(store.Open(Context('e')), "second quota scope could not open");
  store.Save(Note(Context('e'), "another binary still has capacity"));
}
}

int main()
{
  try
  {
    Sandbox sandbox;
    StoreAndIsolation(sandbox.path / "isolation.db");
    SearchAndScope(sandbox.path / "search.db");
    BoundsAndCodec(sandbox.path / "bounds.db");
    CorruptionAndFutureSchema(sandbox.path);
    std::cout << "Analysis memory persistence, isolation, search and bounds passed.\n";
    return 0;
  }
  catch (const std::exception &error) { std::cerr << error.what() << '\n'; return 1; }
}
