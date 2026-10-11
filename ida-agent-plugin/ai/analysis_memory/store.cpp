#include "ai/analysis_memory/store.hpp"
#include "ai/application_paths.hpp"
#include "instance/secure_file.hpp"
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <knownfolders.h>
#include <shlobj.h>
#include <winsqlite/winsqlite3.h>
#else
#include <sqlite3.h>
#include "ai/application_paths_linux.hpp"
#include "instance/private_file_linux.hpp"
#endif
#include <chrono>
#include <limits>
#include <stdexcept>
#include <utility>

namespace ida_agent::ai::analysis_memory
{
namespace
{
constexpr const char *Unavailable = "Analysis memory storage is unavailable.";
void Check(int code)
{
  if (code != SQLITE_OK) throw std::runtime_error(Unavailable);
}
void Exec(sqlite3 *db, const char *sql) { Check(sqlite3_exec(db, sql, nullptr, nullptr, nullptr)); }
class Statement
{
public:
  Statement(sqlite3 *db, const char *sql) { Check(sqlite3_prepare_v2(db, sql, -1, &value_, nullptr)); }
  ~Statement() { sqlite3_finalize(value_); }
  Statement(const Statement &) = delete;
  Statement &operator=(const Statement &) = delete;
  sqlite3_stmt *Get() const { return value_; }
  void Text(int index, const std::string &text)
  { Check(sqlite3_bind_text(value_, index, text.c_str(), static_cast<int>(text.size()), SQLITE_TRANSIENT)); }
  void Integer(int index, std::int64_t value) { Check(sqlite3_bind_int64(value_, index, value)); }
  bool Row()
  {
    const int code = sqlite3_step(value_);
    if (code != SQLITE_ROW && code != SQLITE_DONE) throw std::runtime_error(Unavailable);
    return code == SQLITE_ROW;
  }
private:
  sqlite3_stmt *value_ = nullptr;
};
class Transaction
{
public:
  explicit Transaction(sqlite3 *db) : db_(db) { Exec(db_, "BEGIN IMMEDIATE"); }
  ~Transaction() { if (!committed_) sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr); }
  void Commit() { Exec(db_, "COMMIT"); committed_ = true; }
private:
  sqlite3 *db_;
  bool committed_ = false;
};
std::filesystem::path DefaultPath()
{
#ifdef _WIN32
  PWSTR raw = nullptr;
  if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_CREATE, nullptr, &raw))) return {};
  std::unique_ptr<wchar_t, decltype(&CoTaskMemFree)> directory(raw, CoTaskMemFree);
  return ResolveAiDataPath(directory.get(), L"analysis-memory.db");
#else
  return LinuxAiPath("XDG_STATE_HOME", ".local/state", "analysis-memory.db");
#endif
}
std::int64_t Now()
{
  return std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
}
Fact ReadFact(sqlite3_stmt *row)
{
  const auto *text = reinterpret_cast<const char *>(sqlite3_column_text(row, 1));
  const int size = sqlite3_column_bytes(row, 1);
  if (!text || size <= 0 || size > 32 * 1024) throw std::runtime_error("Stored analysis memory is invalid.");
  const auto payload = nlohmann::json::parse(text, text + size,
      [](int depth, nlohmann::json::parse_event_t, nlohmann::json &) {
        if (depth > 16) throw std::runtime_error("Stored analysis memory is invalid."); return true; }, false);
  auto fact = DecodeFact(payload);
  if (!fact) throw std::runtime_error("Stored analysis memory is invalid.");
  fact->id = sqlite3_column_int64(row, 0);
  fact->created_at = sqlite3_column_int64(row, 2);
  fact->updated_at = sqlite3_column_int64(row, 3);
  if (!ValidFact(*fact)) throw std::runtime_error("Stored analysis memory is invalid.");
  return std::move(*fact);
}
std::string LiteralPhrase(std::string_view text)
{
  std::string result = "\"";
  for (char c : text) { result.push_back(c); if (c == '"') result.push_back(c); }
  return result + "\"";
}
}

struct Store::Impl
{
  sqlite3 *db = nullptr;
  bool fts = false;
  ~Impl() { if (db) sqlite3_close_v2(db); }
  void Dirty() { Exec(db, "UPDATE analysis_memory_meta SET dirty=1 WHERE singleton=1"); }
  bool SyncFts()
  {
    if (!fts) return false;
    try
    {
      Transaction transaction(db);
      Statement dirty(db, "SELECT dirty FROM analysis_memory_meta WHERE singleton=1");
      if (!dirty.Row()) return false;
      if (sqlite3_column_int(dirty.Get(), 0))
      {
        Exec(db, "INSERT INTO analysis_facts_fts(analysis_facts_fts) VALUES('rebuild')");
        Exec(db, "UPDATE analysis_memory_meta SET dirty=0 WHERE singleton=1");
      }
      transaction.Commit();
      return true;
    }
    catch (...) { return false; }
  }
};

Store::Store(std::filesystem::path path, bool fts) : path_(std::move(path)), enable_fts_(fts) {}
Store::~Store() = default;
void Store::Close() noexcept { context_ = {}; impl_.reset(); }
bool Store::UsesFts() const noexcept { return impl_ && impl_->fts; }

bool Store::Open(BinaryContext context) noexcept
{
  context_ = {};
  if (!ValidContext(context)) return false;
  try
  {
    if (!impl_)
    {
      if (path_.empty()) path_ = DefaultPath();
      if (path_.empty() || !path_.is_absolute()) return false;
      bridge::EnsureCurrentUserOnlyDirectory(path_.parent_path());
      if (std::filesystem::is_symlink(std::filesystem::symlink_status(path_))) return false;
#ifndef _WIN32
      bridge::PreparePrivateFile(path_);
      for (const char *suffix : {"-wal", "-shm", "-journal"})
      {
        const auto sidecar = std::filesystem::path(path_.string() + suffix);
        if (std::filesystem::exists(std::filesystem::symlink_status(sidecar)))
          bridge::ApplyCurrentUserOnlyFileAcl(sidecar);
      }
#endif
      auto connection = std::make_unique<Impl>();
      Check(sqlite3_open_v2(path_.u8string().c_str(), &connection->db,
          SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
#ifndef _WIN32
          | SQLITE_OPEN_NOFOLLOW
#endif
          , nullptr));
      bridge::ApplyCurrentUserOnlyFileAcl(path_);
      Check(sqlite3_busy_timeout(connection->db, 50));
      sqlite3_limit(connection->db, SQLITE_LIMIT_LENGTH, 128 * 1024);
      {
        Statement version(connection->db, "PRAGMA user_version");
        if (!version.Row() || sqlite3_column_int(version.Get(), 0) > 1) return false;
      }
      Exec(connection->db, "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA temp_store=MEMORY;");
      Exec(connection->db,
          "CREATE TABLE IF NOT EXISTS analysis_facts (id INTEGER PRIMARY KEY AUTOINCREMENT,"
          "binary_key TEXT NOT NULL, text TEXT NOT NULL, anchor TEXT NOT NULL, status TEXT NOT NULL,"
          "payload TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);"
          "CREATE INDEX IF NOT EXISTS analysis_facts_binary ON analysis_facts(binary_key,updated_at DESC);"
          "CREATE TABLE IF NOT EXISTS analysis_memory_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1), dirty INTEGER NOT NULL);"
          "INSERT OR IGNORE INTO analysis_memory_meta VALUES(1,1); PRAGMA user_version=1;");
      if (enable_fts_ && sqlite3_exec(connection->db,
          "CREATE VIRTUAL TABLE temp.analysis_memory_fts_probe USING fts5(text); DROP TABLE temp.analysis_memory_fts_probe",
          nullptr, nullptr, nullptr) == SQLITE_OK)
        connection->fts = sqlite3_exec(connection->db,
            "CREATE VIRTUAL TABLE IF NOT EXISTS analysis_facts_fts USING fts5(text,content='analysis_facts',content_rowid='id')",
            nullptr, nullptr, nullptr) == SQLITE_OK;
      impl_ = std::move(connection);
    }
    context_ = std::move(context);
    return true;
  }
  catch (...) { Close(); return false; }
}

std::vector<Fact> Store::Find(const Search &query)
{
  if (!impl_ || !ValidContext(context_)) throw std::runtime_error(Unavailable);
  if (!ValidText(query.text, 256, true) || query.limit == 0 || query.limit > 32)
    throw std::runtime_error("Analysis memory search is invalid.");
  const bool fts = !query.text.empty() && impl_->SyncFts();
  const auto search = [&](bool use_fts)
  {
    const std::string sql =
        "SELECT id,payload,created_at,updated_at FROM analysis_facts WHERE binary_key=?1 "
        "AND (?2 OR status='active') AND (?3='' OR anchor='' OR anchor=?3) "
        "AND (NOT ?4 OR anchor='') AND (?5='' OR instr(lower(text),lower(?5))>0 "
        + std::string(use_fts ? "OR id IN (SELECT rowid FROM analysis_facts_fts WHERE analysis_facts_fts MATCH ?7) " : "")
        + ") ORDER BY (anchor=?3 AND anchor<>'') DESC,updated_at DESC,id DESC LIMIT ?6";
    Statement rows(impl_->db, sql.c_str());
    rows.Text(1, context_.key);
    rows.Integer(2, query.include_rejected ? 1 : 0);
    rows.Text(3, query.anchor_rva ? Hex(*query.anchor_rva) : "");
    rows.Integer(4, query.global_only ? 1 : 0);
    rows.Text(5, query.text);
    rows.Integer(6, query.limit);
    if (use_fts) rows.Text(7, LiteralPhrase(query.text));
    std::vector<Fact> result;
    while (rows.Row()) result.push_back(ReadFact(rows.Get()));
    return result;
  };
  if (fts) { try { return search(true); } catch (...) {} }
  return search(false);
}

std::optional<Fact> Store::Get(std::int64_t id)
{
  if (!impl_ || !ValidContext(context_)) throw std::runtime_error(Unavailable);
  if (id <= 0) return {};
  Statement row(impl_->db, "SELECT id,payload,created_at,updated_at FROM analysis_facts WHERE binary_key=?1 AND id=?2");
  row.Text(1, context_.key); row.Integer(2, id);
  return row.Row() ? std::optional<Fact>(ReadFact(row.Get())) : std::nullopt;
}

Fact Store::Save(Fact fact)
{
  if (!impl_ || !ValidContext(context_)) throw std::runtime_error(Unavailable);
  if (!ValidFact(fact)) throw std::runtime_error("Analysis memory record is invalid.");
  Transaction transaction(impl_->db);
  const auto existing = fact.id ? Get(fact.id) : std::nullopt;
  if (fact.id && !existing) throw std::runtime_error("Analysis memory record was not found in this binary.");
  if (!fact.id)
  {
    Statement counts(impl_->db,
        "SELECT count(*),sum(CASE WHEN binary_key=?1 THEN 1 ELSE 0 END) FROM analysis_facts");
    counts.Text(1, context_.key);
    if (!counts.Row() || sqlite3_column_int(counts.Get(), 0) >= 8192 || sqlite3_column_int(counts.Get(), 1) >= 512)
      throw std::runtime_error("Analysis memory capacity reached; remove obsolete records first.");
  }
  fact.created_at = existing ? existing->created_at : Now();
  fact.updated_at = Now();
  const std::string payload = EncodeFact(fact).dump();
  if (payload.size() > 32 * 1024) throw std::runtime_error("Analysis memory record exceeds its storage budget.");
  Statement write(impl_->db, fact.id
      ? "UPDATE analysis_facts SET text=?2,anchor=?3,status=?4,payload=?5,updated_at=?7 WHERE binary_key=?1 AND id=?8"
      : "INSERT INTO analysis_facts(binary_key,text,anchor,status,payload,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7)");
  write.Text(1, context_.key); write.Text(2, fact.text);
  write.Text(3, fact.anchor_rva ? Hex(*fact.anchor_rva) : "");
  write.Text(4, fact.status); write.Text(5, payload);
  if (!fact.id) write.Integer(6, fact.created_at);
  write.Integer(7, fact.updated_at);
  if (fact.id) write.Integer(8, fact.id);
  write.Row();
  if (!fact.id) fact.id = sqlite3_last_insert_rowid(impl_->db);
  impl_->Dirty(); transaction.Commit();
  return fact;
}

bool Store::Forget(std::int64_t id)
{
  if (!impl_ || !ValidContext(context_)) throw std::runtime_error(Unavailable);
  if (id <= 0) return false;
  Transaction transaction(impl_->db);
  Statement remove(impl_->db, "DELETE FROM analysis_facts WHERE binary_key=?1 AND id=?2");
  remove.Text(1, context_.key); remove.Integer(2, id); remove.Row();
  const bool found = sqlite3_changes(impl_->db) == 1;
  impl_->Dirty(); transaction.Commit();
  return found;
}

void Store::Clear()
{
  if (!impl_ || !ValidContext(context_)) throw std::runtime_error(Unavailable);
  Transaction transaction(impl_->db);
  Statement remove(impl_->db, "DELETE FROM analysis_facts WHERE binary_key=?1");
  remove.Text(1, context_.key); remove.Row();
  impl_->Dirty(); transaction.Commit();
}
} // namespace ida_agent::ai::analysis_memory
