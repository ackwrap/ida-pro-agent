#pragma once

#include <exception>
#include <chrono>
#include <functional>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <unordered_set>
#include <utility>

#include <ida.hpp>
#include <kernwin.hpp>

namespace ida_agent::bridge
{

class IdaBusyError final : public std::runtime_error
{
public:
  IdaBusyError() : std::runtime_error("IDA rejected the execution request") {}
};

class IdaTimeoutError final : public std::runtime_error
{
public:
  IdaTimeoutError() : std::runtime_error("IDA execution exceeded its deadline") {}
};

namespace detail
{

class FunctionRequest final : public exec_request_t
{
public:
  explicit FunctionRequest(std::function<void()> callback)
      : callback_(std::move(callback))
  {
  }

  ssize_t idaapi execute() override
  {
    callback_();
    return 1;
  }

private:
  std::function<void()> callback_;
};

} // namespace detail

class IdaExecutor
{
public:
  void Start() noexcept
  {
    std::lock_guard<std::mutex> lock(mutex_);
    stopping_ = false;
  }

  void Shutdown() noexcept
  {
    std::lock_guard<std::mutex> lock(mutex_);
    stopping_ = true;
    for ( qthread_t thread : active_threads_ )
      set_execute_sync_availability(thread, esa_unavailable);
  }

  template <typename Callback>
  auto Read(Callback &&callback) const -> std::invoke_result_t<Callback>
  {
    return Invoke(MFF_READ, std::nullopt, true, std::forward<Callback>(callback));
  }

  template <typename Callback>
  auto ReadFor(
      std::chrono::milliseconds timeout,
      Callback &&callback) const -> std::invoke_result_t<Callback>
  {
    if ( timeout.count() <= 0 )
      throw IdaTimeoutError();
    return Invoke(
        MFF_READ,
        std::chrono::steady_clock::now() + timeout,
        true,
        std::forward<Callback>(callback));
  }

  template <typename Callback>
  auto Write(Callback &&callback) const -> std::invoke_result_t<Callback>
  {
    return Invoke(MFF_WRITE, std::nullopt, false, std::forward<Callback>(callback));
  }

  template <typename Callback>
  auto WriteFor(
      std::chrono::milliseconds timeout,
      Callback &&callback) const -> std::invoke_result_t<Callback>
  {
    if ( timeout.count() <= 0 )
      throw IdaTimeoutError();
    return Invoke(
        MFF_WRITE,
        std::chrono::steady_clock::now() + timeout,
        false,
        std::forward<Callback>(callback));
  }

  template <typename Callback>
  auto Ui(Callback &&callback) const -> std::invoke_result_t<Callback>
  {
    return Invoke(MFF_FAST, std::nullopt, true, std::forward<Callback>(callback));
  }

  template <typename Callback>
  auto UiFor(std::chrono::milliseconds timeout, Callback &&callback) const -> std::invoke_result_t<Callback>
  {
    if ( timeout.count() <= 0 ) throw IdaTimeoutError();
    return Invoke(MFF_FAST, std::chrono::steady_clock::now() + timeout,
        true, std::forward<Callback>(callback));
  }

  // Debugger/UI commands that must run while the debuggee is executing.
  // Do not use for IDB reads/writes. Once a command starts, preserve its receipt.
  template <typename Callback>
  auto DebuggerFor(std::chrono::milliseconds timeout, Callback &&callback) const -> std::invoke_result_t<Callback>
  {
    if ( timeout.count() <= 0 ) throw IdaTimeoutError();
    return Invoke(MFF_FAST, std::chrono::steady_clock::now() + timeout,
        false, std::forward<Callback>(callback));
  }

private:
  template <typename Callback>
  auto Invoke(
      int flags,
      std::optional<std::chrono::steady_clock::time_point> deadline,
      bool check_deadline_after_callback,
      Callback &&callback) const -> std::invoke_result_t<Callback>
  {
    using Result = std::invoke_result_t<Callback>;
    static_assert(!std::is_reference_v<Result>, "IdaExecutor callbacks must return values");
    if ( is_main_thread() )
    {
      if ( deadline && std::chrono::steady_clock::now() >= *deadline )
        throw IdaTimeoutError();
      if constexpr ( std::is_void_v<Result> )
      {
        std::invoke(std::forward<Callback>(callback));
        if ( check_deadline_after_callback && deadline
          && std::chrono::steady_clock::now() >= *deadline )
          throw IdaTimeoutError();
        return;
      }
      else
      {
        Result result = std::invoke(std::forward<Callback>(callback));
        if ( check_deadline_after_callback && deadline
          && std::chrono::steady_clock::now() >= *deadline )
          throw IdaTimeoutError();
        return result;
      }
    }

    const qthread_t thread = RegisterThread();
    try
    {
      if constexpr ( std::is_void_v<Result> )
      {
        InvokeQueued(
            flags,
            deadline,
            check_deadline_after_callback,
            std::forward<Callback>(callback));
        UnregisterThread(thread);
      }
      else
      {
        Result result = InvokeQueued(
            flags,
            deadline,
            check_deadline_after_callback,
            std::forward<Callback>(callback));
        UnregisterThread(thread);
        return result;
      }
    }
    catch ( ... )
    {
      UnregisterThread(thread);
      throw;
    }
  }

  template <typename Callback>
  static auto InvokeQueued(
      int flags,
      std::optional<std::chrono::steady_clock::time_point> deadline,
      bool check_deadline_after_callback,
      Callback &&callback) -> std::invoke_result_t<Callback>
  {
    using Result = std::invoke_result_t<Callback>;

    std::exception_ptr failure;
    bool timed_out = false;

    if constexpr ( std::is_void_v<Result> )
    {
      detail::FunctionRequest request(
          [&callback, &deadline, &failure, &timed_out, check_deadline_after_callback]()
      {
        try
        {
          if ( deadline && std::chrono::steady_clock::now() >= *deadline )
          {
            timed_out = true;
            return;
          }
          std::invoke(std::forward<Callback>(callback));
          timed_out = check_deadline_after_callback && deadline
              && std::chrono::steady_clock::now() >= *deadline;
        }
        catch ( ... )
        {
          failure = std::current_exception();
        }
      });
      if ( execute_sync(request, flags) != 1 && !failure )
        throw IdaBusyError();
      if ( failure )
        std::rethrow_exception(failure);
      if ( timed_out )
        throw IdaTimeoutError();
    }
    else
    {
      std::optional<Result> result;
      detail::FunctionRequest request(
          [&callback, &deadline, &failure, &result, &timed_out, check_deadline_after_callback]()
      {
        try
        {
          if ( deadline && std::chrono::steady_clock::now() >= *deadline )
          {
            timed_out = true;
            return;
          }
          result.emplace(std::invoke(std::forward<Callback>(callback)));
          timed_out = check_deadline_after_callback && deadline
              && std::chrono::steady_clock::now() >= *deadline;
        }
        catch ( ... )
        {
          failure = std::current_exception();
        }
      });
      if ( execute_sync(request, flags) != 1 && !failure )
        throw IdaBusyError();
      if ( failure )
        std::rethrow_exception(failure);
      if ( timed_out )
        throw IdaTimeoutError();
      if ( !result )
        throw std::runtime_error("IDA execution did not produce a result");
      return std::move(*result);
    }
  }

  qthread_t RegisterThread() const
  {
    qthread_t thread = qthread_self();
    if ( thread == nullptr )
      throw std::runtime_error("failed to identify the IDA execution thread");
    std::lock_guard<std::mutex> lock(mutex_);
    if ( stopping_ )
    {
      qthread_free(thread);
      throw IdaBusyError();
    }
    active_threads_.insert(thread);
    return thread;
  }

  void UnregisterThread(qthread_t thread) const noexcept
  {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      active_threads_.erase(thread);
    }
    set_execute_sync_availability(thread, esa_release);
    qthread_free(thread);
  }

  mutable std::mutex mutex_;
  mutable std::unordered_set<qthread_t> active_threads_;
  bool stopping_ = false;
};

} // namespace ida_agent::bridge
