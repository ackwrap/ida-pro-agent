#pragma once

#include "ai/chat_transcript.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ida_agent::ai
{

enum class ChatHistoryLoadStatus
{
  Missing,
  Loaded,
  Invalid,
  Unavailable,
};

struct ChatHistoryLoadResult
{
  ChatHistoryLoadStatus status;
  std::vector<ChatEntry> entries;
};

struct ChatSessionSummary
{
  std::string id;
  std::string title;
  std::size_t entry_count = 0;
  std::int64_t created_at = 0;
  std::int64_t updated_at = 0;
};

struct ChatSessionListResult
{
  ChatHistoryLoadStatus status;
  std::vector<ChatSessionSummary> sessions;
  std::string active_session_id;
};

std::optional<std::string> NormalizeDatabaseKey(const std::filesystem::path &idb_path);

class ChatHistoryStore
{
public:
  explicit ChatHistoryStore(std::filesystem::path database_path = {});

  bool Open(std::string database_key);
  ChatHistoryLoadResult Load() const;
  bool Save(const std::vector<ChatEntry> &entries);
  bool Clear();
  bool ClearAll();
  void ResetActiveSession() noexcept;
  bool StartNew();
  ChatSessionListResult ListSessions() const;
  ChatHistoryLoadResult SelectSession(std::string_view session_id);
  const std::string &ActiveSessionId() const noexcept;

private:
  std::filesystem::path database_path_;
  std::string database_key_;
  std::string active_session_id_;
  bool ready_ = false;
};

} // namespace ida_agent::ai
