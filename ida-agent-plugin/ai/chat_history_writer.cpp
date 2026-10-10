#include "ai/chat_history_writer.hpp"

#include <chrono>
#include <utility>

namespace ida_agent::ai
{

ChatHistoryWriter::~ChatHistoryWriter()
{
  {
    std::lock_guard<std::mutex> lock(mutex_);
    stopping_ = true;
  }
  ready_.notify_all();
  if ( worker_.joinable() ) worker_.join();
}

bool ChatHistoryWriter::Submit(ChatHistoryStore target, std::vector<ChatEntry> entries)
{
  std::lock_guard<std::mutex> lock(mutex_);
  if ( stopping_ || draining_ || target.ActiveSessionId().empty()
      || (pending_ && !pending_->target.SameSaveTarget(target)) )
    return false;
  if ( !worker_.joinable() )
  {
    try { worker_ = std::thread([this] { Run(); }); }
    catch ( ... ) { return false; }
  }
  pending_ = Request{std::move(target), std::move(entries)};
  ready_.notify_all();
  return true;
}

void ChatHistoryWriter::Drain()
{
  std::unique_lock<std::mutex> lock(mutex_);
  draining_ = true;
  ready_.notify_all();
  ready_.wait(lock, [this] { return !pending_ && !writing_; });
  draining_ = false;
}

bool ChatHistoryWriter::TakeFailure()
{
  std::lock_guard<std::mutex> lock(mutex_);
  return std::exchange(failed_, false);
}

void ChatHistoryWriter::Run()
{
  std::optional<ChatHistoryStore> current;
  std::unique_lock<std::mutex> lock(mutex_);
  for ( ;; )
  {
    ready_.wait(lock, [this] { return pending_ || stopping_; });
    if ( !pending_ ) return;
    // Fixed coalescing window, so continuously arriving saves cannot starve IO.
    ready_.wait_for(lock, std::chrono::milliseconds(100),
        [this] { return draining_ || stopping_; });
    Request request = std::move(*pending_);
    pending_.reset();
    writing_ = true;
    lock.unlock();
    bool saved = false;
    try
    {
      if ( !current || !current->SameSaveTarget(request.target) )
        current = std::move(request.target);
      saved = current->Save(request.entries);
    }
    catch ( ... ) {}
    lock.lock();
    failed_ = failed_ || !saved;
    writing_ = false;
    ready_.notify_all();
  }
}

} // namespace ida_agent::ai
