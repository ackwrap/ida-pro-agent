#include "ai/chat_history_store.hpp"
#include "ai/application_paths.hpp"

#include "ai/chat_history_codec.hpp"
#include "instance/secure_file.hpp"

#include "crypto/secure_random.hpp"
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

#include <array>
#include <chrono>
#include <climits>
#include <cwctype>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace ida_agent::ai
{
namespace
{

constexpr int BusyTimeoutMs = 1000;
constexpr std::size_t MaxDatabaseKeyBytes = 32 * 1024;
constexpr std::size_t MaxSessionIdBytes = 64;
constexpr std::size_t MaxSessionTitleBytes = 80;
constexpr std::size_t MaxStoredSessions = 8;

class Database final
{
public:
  Database() = default;
  ~Database()
  {
    if ( value_ != nullptr )
      sqlite3_close_v2(value_);
  }
  Database(const Database &) = delete;
  Database &operator=(const Database &) = delete;

  bool Open(const std::filesystem::path &path)
  {
#ifndef _WIN32
    try
    {
      ida_agent::bridge::PreparePrivateFile(path);
      for (const char *suffix : {"-wal", "-shm", "-journal"})
      {
        const std::filesystem::path sidecar(path.string() + suffix);
        const auto status = std::filesystem::symlink_status(sidecar);
        if (std::filesystem::exists(status))
          ida_agent::bridge::ApplyCurrentUserOnlyFileAcl(sidecar);
      }
    }
    catch (const std::exception &) { return false; }
#endif
    const std::string encoded_path = path.u8string();
    if ( sqlite3_open_v2(
             encoded_path.c_str(),
             &value_,
             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
#ifndef _WIN32
                 | SQLITE_OPEN_NOFOLLOW
#endif
                 ,
             nullptr) != SQLITE_OK )
    {
      return false;
    }
    return sqlite3_busy_timeout(value_, BusyTimeoutMs) == SQLITE_OK;
  }

  sqlite3 *Get() const noexcept { return value_; }

private:
  sqlite3 *value_ = nullptr;
};

class Statement final
{
public:
  Statement(sqlite3 *database, const char *sql)
  {
    if ( sqlite3_prepare_v2(database, sql, -1, &value_, nullptr) != SQLITE_OK )
      value_ = nullptr;
  }
  ~Statement()
  {
    if ( value_ != nullptr )
      sqlite3_finalize(value_);
  }
  Statement(const Statement &) = delete;
  Statement &operator=(const Statement &) = delete;

  sqlite3_stmt *Get() const noexcept { return value_; }
  explicit operator bool() const noexcept { return value_ != nullptr; }

private:
  sqlite3_stmt *value_ = nullptr;
};

std::filesystem::path ResolveDefaultDatabasePath()
{
#ifdef _WIN32
  PWSTR raw_path = nullptr;
  if ( FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_CREATE, nullptr, &raw_path)) )
    return {};
  std::unique_ptr<wchar_t, decltype(&CoTaskMemFree)> local_app_data(raw_path, CoTaskMemFree);
  return ResolveAiDataPath(local_app_data.get(), L"chat.db");
#else
  return LinuxAiPath("XDG_STATE_HOME", ".local/state", "chat.db");
#endif
}

bool Execute(sqlite3 *database, const char *sql)
{
  return sqlite3_exec(database, sql, nullptr, nullptr, nullptr) == SQLITE_OK;
}

bool Configure(sqlite3 *database)
{
  return Execute(database, "PRAGMA journal_mode=WAL")
      && Execute(database, "PRAGMA synchronous=NORMAL")
      && Execute(database, "PRAGMA temp_store=MEMORY")
      && Execute(
          database,
          "CREATE TABLE IF NOT EXISTS chat_history ("
          "database_key TEXT PRIMARY KEY NOT NULL,"
          "history_json TEXT NOT NULL,"
          "updated_at INTEGER NOT NULL"
          ") WITHOUT ROWID")
      && Execute(
          database,
          "CREATE TABLE IF NOT EXISTS chat_sessions ("
          "database_key TEXT NOT NULL,"
          "session_id TEXT NOT NULL,"
          "title TEXT NOT NULL,"
          "history_json TEXT NOT NULL,"
          "entry_count INTEGER NOT NULL,"
          "created_at INTEGER NOT NULL,"
          "updated_at INTEGER NOT NULL,"
          "PRIMARY KEY(database_key,session_id)"
          ") WITHOUT ROWID")
      && Execute(
          database,
          "CREATE INDEX IF NOT EXISTS chat_sessions_recent "
          "ON chat_sessions(database_key,updated_at DESC)")
      && Execute(
          database,
          "CREATE TABLE IF NOT EXISTS chat_session_state ("
          "database_key TEXT PRIMARY KEY NOT NULL,"
          "active_session_id TEXT NOT NULL,"
          "updated_at INTEGER NOT NULL"
          ") WITHOUT ROWID");
}

bool BindText(sqlite3_stmt *statement, int index, std::string_view value)
{
  if ( value.size() > static_cast<std::size_t>(INT_MAX) )
    return false;
  return sqlite3_bind_text(
             statement,
             index,
             value.data(),
             static_cast<int>(value.size()),
             SQLITE_TRANSIENT) == SQLITE_OK;
}

std::int64_t UnixTimeSeconds()
{
  return std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
}

std::optional<std::string> NewSessionId()
{
  std::array<unsigned char, 16> bytes{};
  try { ida_agent::bridge::FillSecureRandom(bytes.data(), bytes.size()); }
  catch (const std::exception &) { return std::nullopt; }
  static constexpr char Hex[] = "0123456789abcdef";
  std::string id;
  id.reserve(bytes.size() * 2);
  for ( unsigned char byte : bytes )
  {
    id.push_back(Hex[byte >> 4]);
    id.push_back(Hex[byte & 0x0F]);
  }
  return id;
}

bool ValidSessionId(std::string_view id)
{
  if ( id.empty() || id.size() > MaxSessionIdBytes )
    return false;
  for ( char character : id )
  {
    if ( !((character >= '0' && character <= '9')
        || (character >= 'a' && character <= 'f')) )
    {
      return false;
    }
  }
  return true;
}

std::string SessionTitle(const std::vector<ChatEntry> &entries)
{
  std::string title = "New conversation";
  for ( const ChatEntry &entry : entries )
  {
    if ( entry.speaker == ChatSpeaker::User && !entry.text.empty() )
    {
      title = entry.text;
      break;
    }
  }
  for ( char &character : title )
  {
    if ( character == '\r' || character == '\n' || character == '\t' )
      character = ' ';
  }
  if ( title.size() > MaxSessionTitleBytes )
  {
    std::size_t size = MaxSessionTitleBytes;
    while ( size > 0
        && (static_cast<unsigned char>(title[size]) & 0xC0) == 0x80 )
    {
      --size;
    }
    title.resize(size);
  }
  return title;
}

bool SetActiveSession(
    sqlite3 *database,
    std::string_view database_key,
    std::string_view session_id)
{
  Statement save(
      database,
      "INSERT OR REPLACE INTO chat_session_state("
      "database_key,active_session_id,updated_at) VALUES(?1,?2,?3)");
  if ( !save
      || !BindText(save.Get(), 1, database_key)
      || !BindText(save.Get(), 2, session_id)
      || sqlite3_bind_int64(save.Get(), 3, UnixTimeSeconds()) != SQLITE_OK )
  {
    return false;
  }
  return sqlite3_step(save.Get()) == SQLITE_DONE;
}

bool RetainNewestSessions(
    sqlite3 *database,
    std::string_view database_key,
    std::size_t maximum)
{
  Statement prune(
      database,
      "DELETE FROM chat_sessions WHERE database_key=?1 AND session_id NOT IN ("
      "SELECT session_id FROM chat_sessions WHERE database_key=?1 "
      "ORDER BY created_at DESC,session_id DESC LIMIT ?2)");
  if ( !prune
      || !BindText(prune.Get(), 1, database_key)
      || sqlite3_bind_int64(
          prune.Get(), 2, static_cast<sqlite3_int64>(maximum)) != SQLITE_OK )
  {
    return false;
  }
  return sqlite3_step(prune.Get()) == SQLITE_DONE;
}

} // namespace

ChatHistoryStore::ChatHistoryStore(std::filesystem::path database_path)
    : database_path_(std::move(database_path))
{
}

bool ChatHistoryStore::Open(std::string database_key)
{
  ready_ = false;
  database_key_.clear();
  active_session_id_.clear();
  if ( database_key.empty() || database_key.size() > MaxDatabaseKeyBytes )
    return false;
  if ( database_path_.empty() )
    database_path_ = ResolveDefaultDatabasePath();
  if ( database_path_.empty() )
    return false;

  try
  {
    ida_agent::bridge::EnsureCurrentUserOnlyDirectory(database_path_.parent_path());
    Database database;
    if ( !database.Open(database_path_) || !Configure(database.Get()) )
      return false;
    ida_agent::bridge::ApplyCurrentUserOnlyFileAcl(database_path_);
    if ( !RetainNewestSessions(database.Get(), database_key, MaxStoredSessions) )
      return false;

    Statement selected(
        database.Get(),
        "SELECT s.session_id FROM chat_session_state st "
        "JOIN chat_sessions s ON s.database_key=st.database_key "
        "AND s.session_id=st.active_session_id WHERE st.database_key=?1");
    if ( !selected || !BindText(selected.Get(), 1, database_key) )
      return false;
    const int selected_result = sqlite3_step(selected.Get());
    if ( selected_result == SQLITE_ROW )
    {
      const auto *value = reinterpret_cast<const char *>(
          sqlite3_column_text(selected.Get(), 0));
      const int size = sqlite3_column_bytes(selected.Get(), 0);
      if ( value != nullptr && size > 0 )
        active_session_id_.assign(value, static_cast<std::size_t>(size));
    }
    else if ( selected_result != SQLITE_DONE )
    {
      return false;
    }
    if ( !active_session_id_.empty() && !ValidSessionId(active_session_id_) )
      return false;
    if ( active_session_id_.empty() )
    {
      Statement recent(
          database.Get(),
          "SELECT session_id FROM chat_sessions WHERE database_key=?1 "
          "ORDER BY updated_at DESC,session_id LIMIT 1");
      if ( !recent || !BindText(recent.Get(), 1, database_key) )
        return false;
      const int recent_result = sqlite3_step(recent.Get());
      if ( recent_result == SQLITE_ROW )
      {
        const auto *value = reinterpret_cast<const char *>(
            sqlite3_column_text(recent.Get(), 0));
        const int size = sqlite3_column_bytes(recent.Get(), 0);
        if ( value != nullptr && size > 0 )
          active_session_id_.assign(value, static_cast<std::size_t>(size));
      }
      else if ( recent_result != SQLITE_DONE )
      {
        return false;
      }
    }
    if ( active_session_id_.empty() )
    {
      Statement legacy(
          database.Get(),
          "SELECT history_json,updated_at FROM chat_history WHERE database_key=?1");
      if ( !legacy || !BindText(legacy.Get(), 1, database_key) )
        return false;
      if ( sqlite3_step(legacy.Get()) == SQLITE_ROW )
      {
        const auto *value = reinterpret_cast<const char *>(
            sqlite3_column_text(legacy.Get(), 0));
        const int size = sqlite3_column_bytes(legacy.Get(), 0);
        const auto entries = value != nullptr && size > 0
                && static_cast<std::size_t>(size) <= MaxChatHistoryBytes
            ? DecodeChatHistory(
                std::string_view(value, static_cast<std::size_t>(size)))
            : std::nullopt;
        const auto id = entries ? NewSessionId() : std::nullopt;
        if ( id )
        {
          const std::int64_t updated_at = sqlite3_column_int64(legacy.Get(), 1);
          Statement migrate(
              database.Get(),
              "INSERT INTO chat_sessions(database_key,session_id,title,"
              "history_json,entry_count,created_at,updated_at) "
              "VALUES(?1,?2,?3,?4,?5,?6,?6)");
          if ( !migrate
              || !BindText(migrate.Get(), 1, database_key)
              || !BindText(migrate.Get(), 2, *id)
              || !BindText(migrate.Get(), 3, SessionTitle(*entries))
              || !BindText(
                  migrate.Get(),
                  4,
                  std::string_view(value, static_cast<std::size_t>(size)))
              || sqlite3_bind_int64(
                  migrate.Get(), 5, static_cast<sqlite3_int64>(entries->size()))
                  != SQLITE_OK
              || sqlite3_bind_int64(migrate.Get(), 6, updated_at) != SQLITE_OK
              || sqlite3_step(migrate.Get()) != SQLITE_DONE )
          {
            return false;
          }
          active_session_id_ = *id;
        }
      }
    }
    if ( !active_session_id_.empty()
        && !SetActiveSession(database.Get(), database_key, active_session_id_) )
    {
      return false;
    }
  }
  catch ( const std::exception & )
  {
    return false;
  }

  database_key_ = std::move(database_key);
  ready_ = true;
  return true;
}

ChatHistoryLoadResult ChatHistoryStore::Load() const
{
  if ( !ready_ )
    return {ChatHistoryLoadStatus::Unavailable, {}};
  Database database;
  if ( !database.Open(database_path_) || !Configure(database.Get()) )
    return {ChatHistoryLoadStatus::Unavailable, {}};

  Statement query(
      database.Get(),
      active_session_id_.empty()
          ? "SELECT history_json FROM chat_history WHERE database_key=?1"
          : "SELECT history_json FROM chat_sessions "
            "WHERE database_key=?1 AND session_id=?2");
  if ( !query || !BindText(query.Get(), 1, database_key_)
      || (!active_session_id_.empty()
          && !BindText(query.Get(), 2, active_session_id_)) )
    return {ChatHistoryLoadStatus::Unavailable, {}};
  const int result = sqlite3_step(query.Get());
  if ( result == SQLITE_DONE )
    return {ChatHistoryLoadStatus::Missing, {}};
  if ( result != SQLITE_ROW )
    return {ChatHistoryLoadStatus::Unavailable, {}};

  const int size = sqlite3_column_bytes(query.Get(), 0);
  const auto *value = reinterpret_cast<const char *>(sqlite3_column_text(query.Get(), 0));
  if ( value == nullptr || size <= 0 || static_cast<std::size_t>(size) > MaxChatHistoryBytes )
    return {ChatHistoryLoadStatus::Invalid, {}};
  const auto entries = DecodeChatHistory(std::string_view(value, static_cast<std::size_t>(size)));
  if ( !entries )
    return {ChatHistoryLoadStatus::Invalid, {}};
  return {ChatHistoryLoadStatus::Loaded, *entries};
}

bool ChatHistoryStore::Save(const std::vector<ChatEntry> &entries)
{
  if ( !ready_ )
    return false;
  if ( active_session_id_.empty() && !StartNew() )
    return false;
  const std::optional<std::string> encoded = EncodeChatHistory(entries);
  if ( !encoded )
    return false;

  Database database;
  if ( !database.Open(database_path_) || !Configure(database.Get()) )
    return false;
  Statement save(
      database.Get(),
      "UPDATE chat_sessions SET title=?3,history_json=?4,entry_count=?5,"
      "updated_at=?6 WHERE database_key=?1 AND session_id=?2");
  if ( !save
      || !BindText(save.Get(), 1, database_key_)
      || !BindText(save.Get(), 2, active_session_id_)
      || !BindText(save.Get(), 3, SessionTitle(entries))
      || !BindText(save.Get(), 4, *encoded)
      || sqlite3_bind_int64(
          save.Get(), 5, static_cast<sqlite3_int64>(entries.size())) != SQLITE_OK
      || sqlite3_bind_int64(save.Get(), 6, UnixTimeSeconds()) != SQLITE_OK )
  {
    return false;
  }
  return sqlite3_step(save.Get()) == SQLITE_DONE
      && sqlite3_changes(database.Get()) == 1;
}

bool ChatHistoryStore::Clear()
{
  return Save({});
}

bool ChatHistoryStore::ClearAll()
{
  if ( database_path_.empty() )
    database_path_ = ResolveDefaultDatabasePath();
  if ( database_path_.empty() )
    return false;
  std::error_code error;
  if ( !std::filesystem::exists(database_path_, error) )
  {
    if ( error )
      return false;
    active_session_id_.clear();
    return true;
  }

  Database database;
  if ( !database.Open(database_path_) || !Configure(database.Get())
      || !Execute(database.Get(), "BEGIN IMMEDIATE") )
  {
    return false;
  }
  const bool cleared = Execute(database.Get(), "DELETE FROM chat_session_state")
      && Execute(database.Get(), "DELETE FROM chat_sessions")
      && Execute(database.Get(), "DELETE FROM chat_history");
  if ( !cleared || !Execute(database.Get(), "COMMIT") )
  {
    Execute(database.Get(), "ROLLBACK");
    return false;
  }
  active_session_id_.clear();
  return true;
}

void ChatHistoryStore::ResetActiveSession() noexcept
{
  active_session_id_.clear();
}

bool ChatHistoryStore::StartNew()
{
  if ( !ready_ )
    return false;
  const auto id = NewSessionId();
  const auto encoded = EncodeChatHistory({});
  if ( !id || !encoded )
    return false;
  Database database;
  if ( !database.Open(database_path_) || !Configure(database.Get())
      || !Execute(database.Get(), "BEGIN IMMEDIATE") )
  {
    return false;
  }
  const bool pruned = RetainNewestSessions(
      database.Get(), database_key_, MaxStoredSessions - 1);
  const std::int64_t now = UnixTimeSeconds();
  Statement insert(
      database.Get(),
      "INSERT INTO chat_sessions(database_key,session_id,title,history_json,"
      "entry_count,created_at,updated_at) VALUES(?1,?2,?3,?4,0,?5,?5)");
  const bool inserted = pruned && insert
      && BindText(insert.Get(), 1, database_key_)
      && BindText(insert.Get(), 2, *id)
      && BindText(insert.Get(), 3, "New conversation")
      && BindText(insert.Get(), 4, *encoded)
      && sqlite3_bind_int64(insert.Get(), 5, now) == SQLITE_OK
      && sqlite3_step(insert.Get()) == SQLITE_DONE;
  const bool active = inserted
      && SetActiveSession(database.Get(), database_key_, *id);
  if ( !active || !Execute(database.Get(), "COMMIT") )
  {
    Execute(database.Get(), "ROLLBACK");
    return false;
  }
  active_session_id_ = *id;
  return true;
}

ChatSessionListResult ChatHistoryStore::ListSessions() const
{
  if ( !ready_ )
    return {ChatHistoryLoadStatus::Unavailable, {}, {}};
  Database database;
  if ( !database.Open(database_path_) || !Configure(database.Get()) )
    return {ChatHistoryLoadStatus::Unavailable, {}, {}};
  Statement query(
      database.Get(),
      "SELECT session_id,title,entry_count,created_at,updated_at "
      "FROM chat_sessions WHERE database_key=?1 "
      "ORDER BY updated_at DESC,session_id LIMIT ?2");
  if ( !query
      || !BindText(query.Get(), 1, database_key_)
      || sqlite3_bind_int64(query.Get(), 2, MaxStoredSessions) != SQLITE_OK )
  {
    return {ChatHistoryLoadStatus::Unavailable, {}, {}};
  }
  std::vector<ChatSessionSummary> sessions;
  int result = SQLITE_OK;
  while ( (result = sqlite3_step(query.Get())) == SQLITE_ROW )
  {
    const auto *id = reinterpret_cast<const char *>(sqlite3_column_text(query.Get(), 0));
    const auto *title = reinterpret_cast<const char *>(sqlite3_column_text(query.Get(), 1));
    const int id_size = sqlite3_column_bytes(query.Get(), 0);
    const int title_size = sqlite3_column_bytes(query.Get(), 1);
    if ( id == nullptr || title == nullptr || id_size <= 0 || title_size <= 0
        || id_size > static_cast<int>(MaxSessionIdBytes)
        || title_size > static_cast<int>(MaxSessionTitleBytes) )
    {
      return {ChatHistoryLoadStatus::Invalid, {}, {}};
    }
    const sqlite3_int64 entry_count = sqlite3_column_int64(query.Get(), 2);
    if ( entry_count < 0
        || entry_count > static_cast<sqlite3_int64>(MaxChatHistoryEntries) )
    {
      return {ChatHistoryLoadStatus::Invalid, {}, {}};
    }
    sessions.push_back({
        std::string(id, static_cast<std::size_t>(id_size)),
        std::string(title, static_cast<std::size_t>(title_size)),
        static_cast<std::size_t>(entry_count),
        sqlite3_column_int64(query.Get(), 3),
        sqlite3_column_int64(query.Get(), 4),
    });
  }
  if ( result != SQLITE_DONE )
    return {ChatHistoryLoadStatus::Unavailable, {}, {}};
  return {
      sessions.empty() ? ChatHistoryLoadStatus::Missing
                       : ChatHistoryLoadStatus::Loaded,
      std::move(sessions),
      active_session_id_,
  };
}

ChatHistoryLoadResult ChatHistoryStore::SelectSession(
    std::string_view session_id)
{
  if ( !ready_ || !ValidSessionId(session_id) )
    return {ChatHistoryLoadStatus::Missing, {}};
  Database database;
  if ( !database.Open(database_path_) || !Configure(database.Get()) )
    return {ChatHistoryLoadStatus::Unavailable, {}};
  Statement query(
      database.Get(),
      "SELECT history_json FROM chat_sessions "
      "WHERE database_key=?1 AND session_id=?2");
  if ( !query
      || !BindText(query.Get(), 1, database_key_)
      || !BindText(query.Get(), 2, session_id) )
  {
    return {ChatHistoryLoadStatus::Unavailable, {}};
  }
  const int result = sqlite3_step(query.Get());
  if ( result == SQLITE_DONE )
    return {ChatHistoryLoadStatus::Missing, {}};
  if ( result != SQLITE_ROW )
    return {ChatHistoryLoadStatus::Unavailable, {}};
  const int size = sqlite3_column_bytes(query.Get(), 0);
  const auto *value = reinterpret_cast<const char *>(
      sqlite3_column_text(query.Get(), 0));
  if ( value == nullptr || size <= 0
      || static_cast<std::size_t>(size) > MaxChatHistoryBytes )
  {
    return {ChatHistoryLoadStatus::Invalid, {}};
  }
  const auto entries = DecodeChatHistory(
      std::string_view(value, static_cast<std::size_t>(size)));
  if ( !entries )
    return {ChatHistoryLoadStatus::Invalid, {}};
  if ( !SetActiveSession(database.Get(), database_key_, session_id) )
    return {ChatHistoryLoadStatus::Unavailable, {}};
  active_session_id_ = std::string(session_id);
  return {ChatHistoryLoadStatus::Loaded, *entries};
}

const std::string &ChatHistoryStore::ActiveSessionId() const noexcept
{
  return active_session_id_;
}

} // namespace ida_agent::ai
