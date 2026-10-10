#include "ai/application_paths_linux.hpp"
#include "ai/plugin_settings.hpp"
#include "ai/provider_settings_store.hpp"
#include "ai/chat_history_store.hpp"
#include "ai/provider_url.hpp"
#include "ai/utf8.hpp"
#include "instance/secure_file.hpp"
#include "instance/private_file_linux.hpp"
#include <sqlite3.h>
#include <sys/stat.h>
#include <unistd.h>
#include <atomic>
#include <fstream>
#include <stdexcept>
#include <thread>
#include <vector>

namespace
{
void Require(bool condition, const char *message)
{
  if (!condition) throw std::runtime_error(message);
}
void Mode(const std::filesystem::path &path, mode_t expected)
{
  struct stat info{};
  Require(lstat(path.c_str(), &info) == 0 && (info.st_mode & 0777) == expected,
      "private path permissions mismatch");
}
struct TemporaryDirectory
{
  std::filesystem::path path;
  TemporaryDirectory()
  {
    char pattern[] = "/tmp/ida-ai-storage-XXXXXX";
    const auto value = mkdtemp(pattern);
    Require(value != nullptr, "temporary directory creation failed");
    path = std::filesystem::canonical(value);
  }
  ~TemporaryDirectory() { std::error_code error; std::filesystem::remove_all(path, error); }
};
}

int main()
{
  using namespace ida_agent::ai;
  using namespace ida_agent::bridge;
  TemporaryDirectory temporary;
  const auto root = temporary.path;
  Require(ValidUtf8("中文✓") && !ValidUtf8("\xc0\x80") && !ValidUtf8("\xed\xa0\x80")
      && !ValidUtf8("\xf4\x90\x80\x80") && !ValidUtf8("\xf0\x9f"), "UTF-8 validation mismatch");
  Require(provider_detail::IsValidBaseUrl("http://[::1]:8080/路径"), "IPv6/UTF-8 URL rejected");
  for (const auto *url : {"file:///etc/passwd", "https://user:secret@example.test", "https://example.test/#x",
      "https://example.test/?x", "https://example.test/\xed\xa0\x80", "https://example.test\\evil"})
    Require(!provider_detail::IsValidBaseUrl(url), "unsafe provider URL accepted");
  umask(0); // Only this test process; creation must still be private.
  setenv("XDG_CONFIG_HOME", (root / "配置 with spaces").c_str(), 1);
  setenv("XDG_STATE_HOME", (root / "状态").c_str(), 1);
  const auto config = LinuxAiPath("XDG_CONFIG_HOME", ".config", "settings.json");
  const auto state = LinuxAiPath("XDG_STATE_HOME", ".local/state", "chat.db");
  Require(config == root / "配置 with spaces/ida-agent/ai/settings.json", "XDG config path mismatch");
  Require(state == root / "状态/ida-agent/ai/chat.db", "XDG state path mismatch");

  PluginSettingsStore settings;
  Require(settings.Load().status == PluginSettingsLoadStatus::Missing, "missing defaults status");
  Require(!std::filesystem::exists(config.parent_path()), "read unexpectedly created directories");
  Require(settings.Save({}), "default settings save failed");
  Mode(config.parent_path(), 0700);
  Mode(config, 0600);
  Require(settings.Load().status == PluginSettingsLoadStatus::Loaded, "default settings load failed");
  ProviderSettingsStore providers;
  auto manager = CreateProviderManagerDraft();
  manager.profiles.front().settings.api_key = "test-only-secret";
  Require(providers.Save(manager), "provider round trip save failed");
  Require(providers.Load().manager.profiles.front().settings.api_key == "test-only-secret",
      "provider secret was not persisted");
  Mode(config.parent_path() / "providers.json", 0600);
  ChatHistoryStore history;
  Require(history.Open("/tmp/CaseSensitive.i64") && history.Save({{ChatSpeaker::User, "中文 history"}}),
      "default history save failed");
  Mode(state.parent_path(), 0700);
  Mode(state, 0600);
  sqlite3 *database = nullptr;
  Require(sqlite3_open_v2(state.c_str(), &database, SQLITE_OPEN_READWRITE, nullptr) == SQLITE_OK,
      "WAL observer failed to open");
  Require(sqlite3_exec(database, "SELECT * FROM chat_sessions", nullptr, nullptr, nullptr) == SQLITE_OK,
      "WAL observer failed to read");
  Require(history.Save({{ChatSpeaker::User, "persisted again"}}), "WAL save failed");
  Mode(state.string() + "-wal", 0600);
  Mode(state.string() + "-shm", 0600);
  sqlite3_close(database);

#ifdef __APPLE__
  const auto fallback = "Library/Application Support/ida-agent/ai/settings.json";
#else
  const auto fallback = ".config/ida-agent/ai/settings.json";
#endif
  // Relative/empty XDG values are ignored without writing to the real home.
  setenv("XDG_CONFIG_HOME", "relative/location", 1);
  Require(LinuxAiPath("XDG_CONFIG_HOME", ".config", "settings.json")
      == LinuxHomeDirectory() / fallback, "relative XDG was accepted");
  setenv("XDG_CONFIG_HOME", "", 1);
  Require(LinuxAiPath("XDG_CONFIG_HOME", ".config", "settings.json")
      == LinuxHomeDirectory() / fallback, "empty XDG was accepted");

  const auto victim = root / "victim";
  AtomicWriteCurrentUserOnlyFile(victim, "unchanged");
  const auto linked = root / "linked.json";
  std::filesystem::create_symlink(victim, linked);
  PluginSettingsStore symlink(linked);
  Require(!symlink.Save({}) && symlink.Load().status == PluginSettingsLoadStatus::Unavailable,
      "settings symlink followed");
  ChatHistoryStore linked_db(linked);
  Require(!linked_db.Open("sample"), "SQLite followed a symlink");
  std::filesystem::remove(linked);
  std::filesystem::create_hard_link(victim, linked);
  Require(!symlink.Save({}) && symlink.Load().status == PluginSettingsLoadStatus::Unavailable,
      "settings hard link accepted");
  Require(!linked_db.Open("sample"), "SQLite accepted a hard link");
  std::filesystem::remove(linked);
  Require(ReadPrivateFile(victim, 100).contents == "unchanged", "linked target changed");
  std::filesystem::create_directory_symlink(config.parent_path(), root / "alias");
  PluginSettingsStore parent_link(root / "alias/settings.json");
  Require(!parent_link.Save({}) && parent_link.Load().status == PluginSettingsLoadStatus::Unavailable,
      "ancestor symlink followed");
  Require(mkfifo(linked.c_str(), 0600) == 0, "FIFO fixture failed");
  Require(symlink.Load().status == PluginSettingsLoadStatus::Unavailable && !symlink.Save({}),
      "FIFO settings accepted");
  std::filesystem::remove(linked);

  const auto public_file = root / "public.json";
  AtomicWriteCurrentUserOnlyFile(public_file, "unchanged");
  chmod(public_file.c_str(), 0644);
  PluginSettingsStore public_settings(public_file);
  Require(!public_settings.Save({}) && public_settings.Load().status == PluginSettingsLoadStatus::Unavailable,
      "public settings accepted");
  Mode(public_file, 0644); // Rejection must not silently alter someone else's setup.
  const auto public_dir = root / "public";
  std::filesystem::create_directory(public_dir);
  chmod(public_dir.c_str(), 0755);
  Require(!PluginSettingsStore(public_dir / "settings.json").Save({}), "public directory accepted");

  const auto sidecar_db = root / "sidecar.db";
  std::filesystem::create_symlink(victim, sidecar_db.string() + "-wal");
  Require(!ChatHistoryStore(sidecar_db).Open("sample"), "SQLite followed a WAL symlink");
  Require(ReadPrivateFile(victim, 100).contents == "unchanged", "WAL symlink target changed");

  const auto concurrent_path = root / "concurrent.json";
  Require(PluginSettingsStore(concurrent_path).Save({}), "concurrent fixture failed");
  std::atomic<unsigned> save_failures{0}, unavailable_reads{0}, invalid_reads{0};
  std::vector<std::thread> workers;
  for (int index = 0; index < 4; ++index)
    workers.emplace_back([&, index]
    {
      PluginSettingsStore store(concurrent_path);
      PluginSettings value;
      value.debug_logging = (index % 2) != 0;
      for (int write = 0; write < 20; ++write)
      {
        if (!store.Save(value)) ++save_failures;
        const auto status = store.Load().status;
        if (status == PluginSettingsLoadStatus::Unavailable) ++unavailable_reads;
        else if (status != PluginSettingsLoadStatus::Loaded) ++invalid_reads;
      }
    });
  for (auto &worker : workers) worker.join();
  Require(save_failures == 0, "concurrent atomic save failed");
  Require(unavailable_reads == 0, "concurrent atomic read was unavailable");
  Require(invalid_reads == 0, "concurrent atomic writes exposed partial JSON");
  Mode(concurrent_path, 0600);
  for (const auto &entry : std::filesystem::directory_iterator(root))
    Require(entry.path().filename().string().find(".tmp-") == std::string::npos, "temporary file leaked");
}
