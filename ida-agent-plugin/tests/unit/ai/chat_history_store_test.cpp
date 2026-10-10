#include "ai/chat_history_store.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winsqlite/winsqlite3.h>
#else
#include <unistd.h>
#include <fstream>
#include <sqlite3.h>
inline unsigned long GetCurrentProcessId() { return static_cast<unsigned long>(getpid()); }
#endif

#include <algorithm>
#include <chrono>
#include <cwctype>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

#include "sqlite_sleep_probe.hpp"

namespace
{

void Require(bool condition, const char *message)
{
  if ( !condition )
    throw std::runtime_error(message);
}

std::string SessionId(std::size_t index)
{
  constexpr char Hex[] = "0123456789abcdef";
  std::string id(31, '0');
  id.push_back(Hex[index]);
  return id;
}

void SeedSessions(
    const std::filesystem::path &database_path,
    const std::string &database_key,
    std::size_t count)
{
  sqlite3 *database = nullptr;
  const std::string encoded_path = database_path.u8string();
  Require(
      sqlite3_open_v2(
          encoded_path.c_str(),
          &database,
          SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX,
          nullptr) == SQLITE_OK,
      "session seed database did not open");
  sqlite3_stmt *insert = nullptr;
  Require(
      sqlite3_prepare_v2(
          database,
          "INSERT INTO chat_sessions(database_key,session_id,title,history_json,"
          "entry_count,created_at,updated_at) VALUES(?1,?2,'seed',"
          "'{\"version\":1,\"entries\":[]}',0,?3,?3)",
          -1,
          &insert,
          nullptr) == SQLITE_OK,
      "session seed statement was not prepared");
  for ( std::size_t index = 0; index < count; ++index )
  {
    const std::string id = SessionId(index);
    Require(
        sqlite3_bind_text(
            insert,
            1,
            database_key.data(),
            static_cast<int>(database_key.size()),
            SQLITE_TRANSIENT) == SQLITE_OK
            && sqlite3_bind_text(
                insert,
                2,
                id.data(),
                static_cast<int>(id.size()),
                SQLITE_TRANSIENT) == SQLITE_OK
            && sqlite3_bind_int64(
                insert, 3, static_cast<sqlite3_int64>(index + 1)) == SQLITE_OK
            && sqlite3_step(insert) == SQLITE_DONE,
        "session seed row was not inserted");
    Require(sqlite3_reset(insert) == SQLITE_OK, "session seed statement did not reset");
    Require(
        sqlite3_clear_bindings(insert) == SQLITE_OK,
        "session seed bindings did not clear");
  }
  Require(sqlite3_finalize(insert) == SQLITE_OK, "session seed statement did not finalize");
  Require(sqlite3_close_v2(database) == SQLITE_OK, "session seed database did not close");
}

} // namespace

int main()
{
  using namespace ida_agent::ai;

  const std::filesystem::path root = std::filesystem::canonical(std::filesystem::temp_directory_path())
      / (L"ida-agent-chat-store-" + std::to_wstring(GetCurrentProcessId()));
  std::filesystem::remove_all(root);
  const std::filesystem::path database_path = root / L"chat.db";
  const std::filesystem::path idb_path = root / L"Sample.i64";
  std::filesystem::create_directories(root);
#ifndef _WIN32
  std::filesystem::permissions(root, std::filesystem::perms::owner_all);
#endif
#ifdef _WIN32
  {
    HANDLE file = CreateFileW(
        idb_path.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    Require(file != INVALID_HANDLE_VALUE, "test IDB was not created");
    CloseHandle(file);
  }
  std::wstring aliased_text = idb_path.wstring();
  std::transform(aliased_text.begin(), aliased_text.end(), aliased_text.begin(), towupper);
  const auto canonical_key = NormalizeDatabaseKey(idb_path);
  const auto aliased_key = NormalizeDatabaseKey(std::filesystem::path(aliased_text));
#else
  std::ofstream(idb_path).put('x');
  const auto alias = root / "alias.i64";
  std::filesystem::create_symlink(idb_path, alias);
  const auto canonical_key = NormalizeDatabaseKey(idb_path);
  const auto aliased_key = NormalizeDatabaseKey(alias);
  const auto lower = root / "sample.i64";
  std::ofstream(lower).put('y');
#ifdef __APPLE__
  Require((NormalizeDatabaseKey(lower) == canonical_key) == std::filesystem::equivalent(lower, idb_path),
      "database identity does not match volume case sensitivity");
#else
  Require(NormalizeDatabaseKey(lower) != canonical_key, "case-sensitive paths merged");
#endif
  const auto unpacked = root / "Unpacked.i64";
  const auto before_pack = NormalizeDatabaseKey(unpacked);
#ifdef __APPLE__
  Require(before_pack.has_value(), "unpacked IDB identity missing");
#else
  Require(before_pack && *before_pack == unpacked.u8string(), "unpacked IDB identity missing");
#endif
  std::ofstream(unpacked).put('z');
  Require(NormalizeDatabaseKey(unpacked) == before_pack, "packing changed IDB identity");
  const auto parent_alias = root / "directory-alias";
  std::filesystem::create_directory_symlink(root, parent_alias);
  Require(NormalizeDatabaseKey(parent_alias / "NotPacked.i64") == NormalizeDatabaseKey(root / "NotPacked.i64"),
      "unpacked IDB parent alias split history");
  std::filesystem::create_symlink(root / "missing", root / "dangling.i64");
  Require(!NormalizeDatabaseKey(root / "dangling.i64") && !NormalizeDatabaseKey(root)
      && !NormalizeDatabaseKey(root / "missing/sample.i64"), "invalid IDB identity accepted");
#endif
  Require(canonical_key.has_value(), "canonical database key was not created");
  Require(aliased_key == canonical_key, "path alias split the database key");

  ChatHistoryStore first(database_path);
  Require(first.Open(*canonical_key), "first store did not open");
  Require(first.Load().status == ChatHistoryLoadStatus::Missing, "new key was not missing");
  const std::vector<ChatEntry> entries{
      {ChatSpeaker::User, "question"},
      {ChatSpeaker::Assistant, "answer"},
  };
  Require(first.Save(entries), "first history was not saved");
  const ChatHistoryLoadResult first_loaded = first.Load();
  Require(first_loaded.status == ChatHistoryLoadStatus::Loaded, "first history was not loaded");
  Require(first_loaded.entries.size() == 2, "first history entry count mismatch");
  Require(first_loaded.entries[0].text == "question", "first history content mismatch");
  const std::string first_session = first.ActiveSessionId();
  Require(first_session.size() == 32, "first session id mismatch");
  ChatSessionListResult sessions = first.ListSessions();
  Require(sessions.status == ChatHistoryLoadStatus::Loaded
              && sessions.sessions.size() == 1,
          "first session was not listed");
  Require(sessions.sessions[0].title == "question"
              && sessions.sessions[0].entry_count == 2,
          "first session metadata mismatch");

  Require(first.StartNew(), "new session was not created");
  const std::string second_session = first.ActiveSessionId();
  Require(second_session != first_session, "new session reused an id");
  Require(first.Load().entries.empty(), "new session was not empty");
  Require(first.Save({{ChatSpeaker::User, "another question"}}),
          "new session was not saved");
  sessions = first.ListSessions();
  Require(sessions.sessions.size() == 2
              && sessions.active_session_id == second_session,
          "multiple sessions were not listed");
  const ChatHistoryLoadResult selected = first.SelectSession(first_session);
  Require(selected.status == ChatHistoryLoadStatus::Loaded
              && selected.entries[0].text == "question",
          "stored session was not selected");
  Require(first.SelectSession("missing").status == ChatHistoryLoadStatus::Missing,
          "invalid session selection was accepted");

  ChatHistoryStore reopened(database_path);
  Require(reopened.Open(*canonical_key), "reopened store did not open");
  Require(reopened.ActiveSessionId() == first_session,
          "active session selection was not restored");
  Require(reopened.Load().entries[0].text == "question",
          "reopened active session content mismatch");

  ChatHistoryStore second(database_path);
  Require(second.Open("C:/samples/second.i64"), "second store did not open");
  Require(second.Load().status == ChatHistoryLoadStatus::Missing, "database keys were not isolated");
  Require(second.Save({{ChatSpeaker::System, "second"}}), "second history was not saved");
  Require(second.Load().entries[0].text == "second", "second history content mismatch");
  Require(first.Load().entries[0].text == "question", "second save overwrote first history");

  SeedSessions(database_path, "limit-key", 9);
  ChatHistoryStore limited(database_path);
  Require(limited.Open("limit-key"), "limited store did not open");
  Require(limited.ListSessions().sessions.size() == 8,
          "opening an existing store did not enforce the session limit");
  Require(limited.SelectSession(SessionId(0)).status == ChatHistoryLoadStatus::Missing,
          "opening an existing store did not delete the oldest session");
  Require(limited.StartNew(), "limited store did not create a new session");
  Require(limited.ListSessions().sessions.size() == 8,
          "new session exceeded the per-database limit");
  Require(limited.SelectSession(SessionId(1)).status == ChatHistoryLoadStatus::Missing,
          "new session did not delete the next oldest session");
  Require(second.ListSessions().sessions.size() == 1,
          "session pruning crossed database keys");

  sqlite3 *locking_database = nullptr;
  const std::string encoded_database_path = database_path.u8string();
  Require(
      sqlite3_open_v2(
          encoded_database_path.c_str(),
          &locking_database,
          SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX,
          nullptr) == SQLITE_OK,
      "locking database did not open");
  const std::string corrupt_session =
      "UPDATE chat_sessions SET history_json='invalid' WHERE session_id='"
      + second_session + "'";
  Require(
      sqlite3_exec(
          locking_database,
          corrupt_session.c_str(),
          nullptr,
          nullptr,
          nullptr) == SQLITE_OK,
      "session was not corrupted for selection test");
  Require(
      first.SelectSession(second_session).status == ChatHistoryLoadStatus::Invalid,
      "corrupt session selection was accepted");
  Require(first.ActiveSessionId() == first_session,
          "corrupt selection changed the active session");
  Require(
      sqlite3_exec(locking_database, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) == SQLITE_OK,
      "write lock was not acquired");
  {
    SqliteSleepProbe sleep;
    const auto locked_started = std::chrono::steady_clock::now();
    Require(!first.Save(entries), "save unexpectedly succeeded while write-locked");
    Require(sleep.RequestedMicroseconds() > 0 && sleep.RequestedMicroseconds() <= 1000000,
        "write lock exceeded the one-second SQLite backoff budget");
    // A shared runner may resume sleeps late. Verify the exact requested budget
    // above, while retaining a generous wall-clock guard against a hung save.
    Require(std::chrono::steady_clock::now() - locked_started < std::chrono::seconds(10),
        "write lock caused an unbounded wait");
  }
  Require(
      sqlite3_exec(locking_database, "ROLLBACK", nullptr, nullptr, nullptr) == SQLITE_OK,
      "write lock was not released");
  Require(sqlite3_close_v2(locking_database) == SQLITE_OK, "locking database did not close");
  Require(first.Save(entries), "save did not recover after write lock release");

  Require(first.Clear(), "first history was not cleared");
  const ChatHistoryLoadResult cleared = first.Load();
  Require(cleared.status == ChatHistoryLoadStatus::Loaded, "clear did not leave canonical history");
  Require(cleared.entries.empty(), "clear did not remove history entries");
  Require(first.ListSessions().sessions.size() == 2,
          "clear removed the session itself");

  sqlite3 *legacy_database = nullptr;
  Require(
      sqlite3_open_v2(
          encoded_database_path.c_str(),
          &legacy_database,
          SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX,
          nullptr) == SQLITE_OK,
      "legacy database did not open");
  Require(
      sqlite3_exec(
          legacy_database,
          "INSERT OR REPLACE INTO chat_history(database_key,history_json,updated_at) "
          "VALUES('legacy-key','{\"version\":1,\"entries\":[{\"speaker\":\"user\","
          "\"text\":\"legacy\"}]}',123)",
          nullptr,
          nullptr,
          nullptr) == SQLITE_OK,
      "legacy history was not inserted");
  Require(sqlite3_close_v2(legacy_database) == SQLITE_OK,
          "legacy database did not close");
  ChatHistoryStore legacy(database_path);
  Require(legacy.Open("legacy-key"), "legacy store did not open");
  Require(legacy.Load().entries[0].text == "legacy",
          "legacy history was not migrated");
  Require(legacy.ListSessions().sessions.size() == 1,
          "legacy history did not become a session");

  Require(first.ClearAll(), "all history was not cleared");
  Require(first.ActiveSessionId().empty(), "clear all retained the active session");
  Require(first.ListSessions().sessions.empty(), "clear all retained first-key sessions");
  Require(second.ListSessions().sessions.empty(), "clear all retained second-key sessions");
  Require(limited.ListSessions().sessions.empty(), "clear all retained limited-key sessions");
  ChatHistoryStore cleared_legacy(database_path);
  Require(cleared_legacy.Open("legacy-key"), "cleared legacy store did not open");
  Require(cleared_legacy.Load().status == ChatHistoryLoadStatus::Missing,
          "clear all retained legacy history");
  second.ResetActiveSession();
  Require(second.Save({{ChatSpeaker::User, "after clear"}}),
          "save did not create a session after clear all");
  Require(second.ListSessions().sessions.size() == 1,
          "save after clear all created the wrong session count");

  ChatHistoryStore invalid_key(database_path);
  Require(!invalid_key.Open(""), "empty database key was accepted");
  Require(
      invalid_key.Load().status == ChatHistoryLoadStatus::Unavailable,
      "unopened store did not report unavailable");

  std::filesystem::remove_all(root);
  return 0;
}
