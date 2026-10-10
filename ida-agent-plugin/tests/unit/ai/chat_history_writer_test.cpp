#include "ai/chat_history_writer.hpp"

#include <chrono>
#include <filesystem>
#include <stdexcept>
#include <string>

#ifdef _WIN32
#include <winsqlite/winsqlite3.h>
#else
#include <sqlite3.h>
#endif

using namespace ida_agent::ai;

namespace
{
void Require(bool condition, const char *message)
{
  if ( !condition ) throw std::runtime_error(message);
}
}

int main()
{
  const auto root = std::filesystem::temp_directory_path()
      / ("ida-history-writer-" + std::to_string(
          std::chrono::steady_clock::now().time_since_epoch().count()));
  const auto path = root / "chat.db";
  {
    ChatHistoryStore store(path);
    Require(store.Open("writer-test") && store.StartNew(), "store initialization failed");
    const auto first = store.ActiveSessionId();
    ChatHistoryWriter writer;
    sqlite3 *locked = nullptr;
    Require(sqlite3_open(path.u8string().c_str(), &locked) == SQLITE_OK, "lock connection failed");
    Require(sqlite3_exec(locked, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) == SQLITE_OK, "lock failed");
    const auto started = std::chrono::steady_clock::now();
    for ( int index = 0; index < 50; ++index )
      Require(writer.Submit(store.ForBackgroundSave(), {{ChatSpeaker::User, std::to_string(index)}}), "enqueue failed");
    Require(std::chrono::steady_clock::now() - started < std::chrono::milliseconds(500), "enqueue waited for SQLite lock");
    // Let a write fail while the caller remains responsive. The failure is
    // observable, and a later snapshot can recover after the lock is released.
    writer.Drain();
    Require(writer.TakeFailure(), "background write failure was lost");
    sqlite3_exec(locked, "ROLLBACK", nullptr, nullptr, nullptr);
    sqlite3_close(locked);
    Require(writer.Submit(store.ForBackgroundSave(), {{ChatSpeaker::User, "latest"}}), "retry enqueue failed");
    writer.Drain();
    Require(!writer.TakeFailure(), "write did not recover");
    Require(store.Load().entries.at(0).text == "latest", "latest snapshot was not persisted");
    Require(store.StartNew(), "new session failed");
    const auto second = store.ActiveSessionId();
    Require(writer.Submit(store.ForBackgroundSave(), {{ChatSpeaker::User, "second"}}), "second enqueue failed");
    writer.Drain();
    Require(store.SelectSession(first).entries.at(0).text == "latest", "write crossed session boundary");
    Require(store.SelectSession(second).entries.at(0).text == "second", "second session was not saved");
    Require(store.ClearAll(), "clear failed");
    Require(store.Load().status == ChatHistoryLoadStatus::Missing, "clear resurrected a pending snapshot");
    store.ResetActiveSession();
    Require(store.StartNew(), "post-clear session failed");
    Require(writer.Submit(store.ForBackgroundSave(), {{ChatSpeaker::User, "shutdown"}}), "shutdown enqueue failed");
    // The destructor flushes the final queued snapshot before closing SQLite.
  }
  {
    ChatHistoryStore store(path);
    Require(store.Open("writer-test"), "reopen failed");
    Require(store.Load().entries.at(0).text == "shutdown", "shutdown discarded pending history");
  }
  std::filesystem::remove_all(root);
}
