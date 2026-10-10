#pragma once

#include <cstdint>
#include <stdexcept>

// Include the platform's SQLite header before this test-only helper.
// Observe SQLite's requested backoff independently of scheduler oversleep.
class SqliteSleepProbe final
{
public:
  SqliteSleepProbe() : original_(sqlite3_vfs_find(nullptr)), wrapper_(*original_)
  {
    wrapper_.zName = "ida-history-test-sleep";
    wrapper_.pNext = nullptr;
    wrapper_.xSleep = Sleep;
    if (sqlite3_vfs_register(&wrapper_, 1) != SQLITE_OK)
      throw std::runtime_error("SQLite sleep probe registration failed");
    active_ = this;
  }

  ~SqliteSleepProbe()
  {
    sqlite3_vfs_register(original_, 1);
    sqlite3_vfs_unregister(&wrapper_);
    active_ = nullptr;
  }

  SqliteSleepProbe(const SqliteSleepProbe &) = delete;
  SqliteSleepProbe &operator=(const SqliteSleepProbe &) = delete;
  std::int64_t RequestedMicroseconds() const { return requested_; }

private:
  static int Sleep(sqlite3_vfs *, int microseconds)
  {
    active_->requested_ += microseconds;
    return active_->original_->xSleep(active_->original_, microseconds);
  }

  inline static SqliteSleepProbe *active_ = nullptr;
  sqlite3_vfs *original_;
  sqlite3_vfs wrapper_;
  std::int64_t requested_ = 0;
};
