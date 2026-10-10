#pragma once

#include "ai/chat_history_store.hpp"

#include <condition_variable>
#include <mutex>
#include <optional>
#include <thread>

namespace ida_agent::ai
{

// A single worker serializes writes. Only the newest pending snapshot is kept;
// callers drain before switching or clearing a conversation.
class ChatHistoryWriter final
{
public:
  ChatHistoryWriter() = default;
  ~ChatHistoryWriter();
  bool Submit(ChatHistoryStore target, std::vector<ChatEntry> entries);
  void Drain();
  bool TakeFailure();

private:
  struct Request { ChatHistoryStore target; std::vector<ChatEntry> entries; };
  void Run();
  std::mutex mutex_;
  std::condition_variable ready_;
  std::optional<Request> pending_;
  std::thread worker_;
  bool writing_ = false;
  bool draining_ = false;
  bool stopping_ = false;
  bool failed_ = false;
};

} // namespace ida_agent::ai
