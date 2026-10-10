#include "ai/stream_client_win_async.hpp"
#include "ai/stream_client_win_internal.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <utility>

namespace ida_agent::ai::stream_client_win_internal
{

enum class WinHttpAsyncRequest::Completion
{
  None, Sent, Headers, Available, Read, Error,
};

struct WinHttpAsyncRequest::State final
{
  State() : event(CreateEventW(nullptr, FALSE, FALSE, nullptr)) {}
  ~State() { if ( event != nullptr ) CloseHandle(event); }

  void AddRef() noexcept { references.fetch_add(1, std::memory_order_relaxed); }
  void Release() noexcept
  {
    if ( references.fetch_sub(1, std::memory_order_acq_rel) == 1 )
      delete this;
  }

  std::atomic<unsigned long> references{1};
  HANDLE event;
  std::atomic<Completion> completion{Completion::None};
  std::atomic<DWORD> error{ERROR_SUCCESS};
  std::atomic<DWORD> read_bytes{0};
  std::string body;
  std::array<char, 16 * 1024> buffer{};
};

WinHttpAsyncRequest::WinHttpAsyncRequest() : state_(new State) {}
WinHttpAsyncRequest::~WinHttpAsyncRequest() { state_->Release(); }
DWORD WinHttpAsyncRequest::LastError() const noexcept { return last_error_; }
std::string_view WinHttpAsyncRequest::LastOperation() const noexcept { return last_operation_; }

void CALLBACK WinHttpAsyncRequest::StatusCallback(
    HINTERNET, DWORD_PTR context, DWORD status, void *information, DWORD size)
{
  auto *state = reinterpret_cast<State *>(context);
  if ( state == nullptr )
    return;
  Completion completion = Completion::None;
  switch ( status )
  {
    case WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE:
      completion = Completion::Sent;
      break;
    case WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE:
      completion = Completion::Headers;
      break;
    case WINHTTP_CALLBACK_STATUS_READ_COMPLETE:
      state->read_bytes.store(size, std::memory_order_relaxed);
      completion = Completion::Read;
      break;
    case WINHTTP_CALLBACK_STATUS_DATA_AVAILABLE:
      if ( information != nullptr && size == sizeof(DWORD) )
        state->read_bytes.store(*static_cast<const DWORD *>(information), std::memory_order_relaxed);
      completion = Completion::Available;
      break;
    case WINHTTP_CALLBACK_STATUS_REQUEST_ERROR:
      state->error.store(
          information != nullptr && size == sizeof(WINHTTP_ASYNC_RESULT)
              ? static_cast<const WINHTTP_ASYNC_RESULT *>(information)->dwError
              : ERROR_WINHTTP_INTERNAL_ERROR,
          std::memory_order_relaxed);
      completion = Completion::Error;
      break;
    case WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING:
      state->Release();
      return;
    default:
      return;
  }
  state->completion.store(completion, std::memory_order_release);
  SetEvent(state->event);
}

bool WinHttpAsyncRequest::Attach(HINTERNET request, std::string body, std::string &error)
{
  state_->body = std::move(body);
  DWORD_PTR context = reinterpret_cast<DWORD_PTR>(state_);
  if ( state_->event == nullptr
      || !WinHttpSetOption(request, WINHTTP_OPTION_CONTEXT_VALUE, &context, sizeof(context)) )
  {
    error = "Stream request callback setup failed.";
    return false;
  }
  state_->AddRef();
  if ( WinHttpSetStatusCallback(
           request, StatusCallback,
           WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE
               | WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE
               | WINHTTP_CALLBACK_STATUS_DATA_AVAILABLE
               | WINHTTP_CALLBACK_STATUS_READ_COMPLETE
               | WINHTTP_CALLBACK_STATUS_REQUEST_ERROR
               | WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING,
           0) == WINHTTP_INVALID_STATUS_CALLBACK )
  {
    state_->Release();
    error = "Stream request callback setup failed.";
    return false;
  }
  return true;
}

bool WinHttpAsyncRequest::Perform(
    Completion expected, std::string_view operation,
    const std::function<BOOL()> &start, const AbortReason &abort, std::string &error)
{
  last_error_ = ERROR_SUCCESS;
  last_operation_ = operation;
  if ( const auto reason = abort() )
  {
    error = *reason;
    return false;
  }
  ResetEvent(state_->event);
  state_->completion.store(Completion::None, std::memory_order_release);
  state_->error.store(ERROR_SUCCESS, std::memory_order_relaxed);
  state_->read_bytes.store(0, std::memory_order_relaxed);
  if ( !start() )
  {
    const DWORD start_error = GetLastError();
    if ( start_error != ERROR_IO_PENDING )
    {
      last_error_ = start_error;
      error = FormatWinHttpSseError(operation, last_error_);
      return false;
    }
  }
  while ( true )
  {
    if ( const auto reason = abort() )
    {
      error = *reason;
      return false;
    }
    // Poll our completion event, never a WinHTTP receive timeout. A WinHTTP
    // timeout cancels the request and that handle cannot be read again.
    const DWORD wait = WaitForSingleObject(state_->event, 25);
    if ( wait == WAIT_TIMEOUT )
      continue;
    if ( wait != WAIT_OBJECT_0 )
      last_error_ = GetLastError();
    else
    {
      const Completion completion = state_->completion.load(std::memory_order_acquire);
      if ( completion == expected )
        return true;
      if ( completion != Completion::Error )
        continue;
      last_error_ = state_->error.load(std::memory_order_relaxed);
    }
    error = FormatWinHttpSseError(operation, last_error_);
    return false;
  }
}

bool WinHttpAsyncRequest::Send(HINTERNET request, const AbortReason &abort, std::string &error)
{
  return Perform(Completion::Sent, "WinHttpSendRequest", [&]
  {
    const DWORD size = static_cast<DWORD>(state_->body.size());
    return WinHttpSendRequest(
        request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        state_->body.empty() ? WINHTTP_NO_REQUEST_DATA : state_->body.data(),
        size, size, reinterpret_cast<DWORD_PTR>(state_));
  }, abort, error);
}

bool WinHttpAsyncRequest::Receive(HINTERNET request, const AbortReason &abort, std::string &error)
{
  return Perform(Completion::Headers, "WinHttpReceiveResponse", [&]
  {
    return WinHttpReceiveResponse(request, nullptr);
  }, abort, error);
}

bool WinHttpAsyncRequest::Read(
    HINTERNET request, const AbortReason &abort, std::string_view &bytes, std::string &error)
{
  bytes = {};
  if ( !Perform(Completion::Available, "WinHttpQueryDataAvailable", [&]
       {
         return WinHttpQueryDataAvailable(request, nullptr);
       }, abort, error) )
    return false;
  const DWORD available = state_->read_bytes.load(std::memory_order_relaxed);
  if ( available == 0 )
    return true;
  const DWORD requested = (std::min)(available, static_cast<DWORD>(state_->buffer.size()));
  if ( !Perform(Completion::Read, "WinHttpReadData", [&]
       {
         return WinHttpReadData(request, state_->buffer.data(), requested, nullptr);
       }, abort, error) )
    return false;
  const DWORD read = state_->read_bytes.load(std::memory_order_relaxed);
  if ( read == 0 )
  {
    error = "WinHttpReadData returned zero bytes while data was available.";
    return false;
  }
  bytes = std::string_view(state_->buffer.data(), read);
  return true;
}

} // namespace ida_agent::ai::stream_client_win_internal
