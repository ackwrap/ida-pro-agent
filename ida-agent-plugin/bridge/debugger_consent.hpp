#pragma once

#include "rpc/dispatcher.hpp"

namespace ida_agent::bridge
{
class IdaExecutor;

// Main-thread-only state. Pending also blocks reentrant calls from modal UI.
class DebuggerConsent
{
public:
  enum class Decision { New, Pending, Allowed, Denied };
  Decision Begin()
  {
    const auto previous = decision_;
    if ( previous == Decision::New ) decision_ = Decision::Pending;
    return previous;
  }
  void Complete(bool allowed)
  {
    if ( decision_ == Decision::Pending )
      decision_ = allowed ? Decision::Allowed : Decision::Denied;
  }
private:
  Decision decision_ = Decision::New;
};

void AddDebuggerConsent(Dispatcher::MethodHandlers &handlers, IdaExecutor &executor);
} // namespace ida_agent::bridge
