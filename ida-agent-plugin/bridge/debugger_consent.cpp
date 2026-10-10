#include "debugger_consent.hpp"
#include "ida_executor.hpp"

#include <chrono>
#include <memory>
#include <utility>

namespace ida_agent::bridge
{
void AddDebuggerConsent(Dispatcher::MethodHandlers &handlers, IdaExecutor &executor)
{
  // All debugger handlers share one in-memory decision for this Pipe instance.
  const auto consent = std::make_shared<DebuggerConsent>();
  for ( auto &[name, handler] : handlers )
  {
    if ( name.compare(0, 9, "debugger.") != 0 ) continue;
    handler = [&executor, consent, invoke = std::move(handler)](const rpc::Request &request) -> Dispatcher::MethodResult
    {
      using Clock = std::chrono::steady_clock;
      const auto deadline = Clock::now() + std::chrono::milliseconds(request.timeout_ms);
      try
      {
        const auto decision = executor.UiFor(std::chrono::milliseconds(request.timeout_ms), [consent, deadline]()
        {
          const auto existing = consent->Begin();
          if ( existing != DebuggerConsent::Decision::New ) return existing;
          bool allowed = false;
          if ( is_idaq() )
          {
            allowed = ask_yn(ASKBTN_NO,
                "HIDECANCEL\nAllow MCP debugger access for this IDA instance?\n\n"
                "This allows all MCP clients connected to this Pipe to read debugger\n"
                "state and memory, control execution, change breakpoints, and write\n"
                "process memory.\n\n"
                "Allow once for this Pipe. Later debugger requests will not ask again.\n"
                "The decision is temporary and resets when the Pipe is recreated\n"
                "or this IDA database is closed.") == ASKBTN_YES;
          }
          allowed = allowed && Clock::now() < deadline;
          consent->Complete(allowed);
          return allowed ? DebuggerConsent::Decision::Allowed : DebuggerConsent::Decision::Denied;
        });
        if ( decision == DebuggerConsent::Decision::Pending )
          return rpc::RpcError{rpc::ErrorCode::IdaBusy, "Debugger approval is already pending in IDA.", true};
        if ( decision != DebuggerConsent::Decision::Allowed )
          return rpc::RpcError{rpc::ErrorCode::PermissionDenied,
              "MCP debugger access was not allowed for this Pipe. Reopen the IDA database to request permission again.", false};
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
        if ( remaining <= 0 ) throw IdaTimeoutError();
        rpc::Request approved = request;
        approved.timeout_ms = static_cast<std::uint32_t>(remaining);
        return invoke(approved);
      }
      catch ( const IdaTimeoutError & )
      {
        return rpc::RpcError{rpc::ErrorCode::Timeout, "Debugger permission or request timed out.", false};
      }
      catch ( const IdaBusyError & )
      {
        return rpc::RpcError{rpc::ErrorCode::IdaBusy, "IDA cannot display debugger permission now.", true};
      }
    };
  }
}
} // namespace ida_agent::bridge
