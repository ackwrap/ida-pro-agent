#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winhttp.h>

#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace ida_agent::ai::stream_client_win_internal
{

// The callback retains the buffers until HANDLE_CLOSING, including when a
// pending send/read is abandoned by cancellation or the overall deadline.
class WinHttpAsyncRequest final
{
public:
  using AbortReason = std::function<std::optional<std::string>()>;

  WinHttpAsyncRequest();
  ~WinHttpAsyncRequest();
  WinHttpAsyncRequest(const WinHttpAsyncRequest &) = delete;
  WinHttpAsyncRequest &operator=(const WinHttpAsyncRequest &) = delete;

  bool Attach(HINTERNET request, std::string body, std::string &error);
  bool Send(HINTERNET request, const AbortReason &abort, std::string &error);
  bool Receive(HINTERNET request, const AbortReason &abort, std::string &error);
  bool Read(
      HINTERNET request, const AbortReason &abort,
      std::string_view &bytes, std::string &error);
  DWORD LastError() const noexcept;
  std::string_view LastOperation() const noexcept;

private:
  struct State;
  enum class Completion;
  static void CALLBACK StatusCallback(HINTERNET, DWORD_PTR, DWORD, void *, DWORD);
  bool Perform(
      Completion expected, std::string_view operation,
      const std::function<BOOL()> &start, const AbortReason &abort, std::string &error);

  State *state_;
  DWORD last_error_ = ERROR_SUCCESS;
  std::string_view last_operation_;
};

} // namespace ida_agent::ai::stream_client_win_internal
