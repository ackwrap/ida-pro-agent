#include "transport/named_pipe_server.hpp"

#include "envelope.hpp"
#include "framing.hpp"
#include "validation.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <sddl.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace ida_agent::bridge
{
namespace
{

constexpr DWORD ClientInputTimeoutMs = 5000;
constexpr DWORD ResponseGraceMs = 2000;
constexpr std::size_t MaxRpcResponseBytes = 256 * 1024;
constexpr std::size_t IoWorkerCount = 4;
constexpr std::size_t MaxPendingClients = 8;

void TraceShutdown(
    const std::function<void(const char *)> &trace,
    const char *phase) noexcept
{
  if ( !trace )
    return;
  try
  {
    trace(phase);
  }
  catch ( ... )
  {
  }
}

class Handle
{
public:
  explicit Handle(HANDLE value = INVALID_HANDLE_VALUE) : value_(value) {}
  ~Handle() { Close(); }
  Handle(const Handle &) = delete;
  Handle &operator=(const Handle &) = delete;
  Handle(Handle &&other) noexcept : value_(other.Release()) {}
  Handle &operator=(Handle &&other) noexcept
  {
    if ( this != &other )
    {
      Close();
      value_ = other.Release();
    }
    return *this;
  }
  HANDLE Get() const noexcept { return value_; }
  HANDLE Release() noexcept
  {
    const HANDLE value = value_;
    value_ = INVALID_HANDLE_VALUE;
    return value;
  }
  void Close() noexcept
  {
    if ( value_ != INVALID_HANDLE_VALUE && value_ != nullptr )
    {
      CloseHandle(value_);
      value_ = INVALID_HANDLE_VALUE;
    }
  }

private:
  HANDLE value_;
};

class ClientConnection
{
public:
  explicit ClientConnection(HANDLE value) : value_(value) {}
  ~ClientConnection() { Close(); }
  HANDLE Get() const noexcept { return value_.load(); }
  void Cancel() noexcept
  {
    const HANDLE value = value_.load();
    if ( value != INVALID_HANDLE_VALUE )
      CancelIoEx(value, nullptr);
  }
  void Close() noexcept
  {
    const HANDLE value = value_.exchange(INVALID_HANDLE_VALUE);
    if ( value != INVALID_HANDLE_VALUE )
    {
      CancelIoEx(value, nullptr);
      DisconnectNamedPipe(value);
      CloseHandle(value);
    }
  }

private:
  std::atomic<HANDLE> value_;
};

class PipeSecurity
{
public:
  PipeSecurity()
  {
    HANDLE raw_token = nullptr;
    if ( !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token) )
      throw std::runtime_error("failed to query current process token");
    Handle token(raw_token);
    DWORD size = 0;
    GetTokenInformation(token.Get(), TokenUser, nullptr, 0, &size);
    if ( size == 0 )
      throw std::runtime_error("failed to size current user token");
    std::vector<std::uint8_t> information(size);
    if ( !GetTokenInformation(token.Get(), TokenUser, information.data(), size, &size) )
      throw std::runtime_error("failed to read current user token");
    const auto *token_user = reinterpret_cast<const TOKEN_USER *>(information.data());

    LPWSTR raw_sid = nullptr;
    if ( !ConvertSidToStringSidW(token_user->User.Sid, &raw_sid) )
      throw std::runtime_error("failed to encode current user SID");
    std::unique_ptr<wchar_t, decltype(&LocalFree)> sid(raw_sid, LocalFree);
    const std::wstring sddl = L"D:P(A;;GA;;;" + std::wstring(sid.get()) + L")";
    if ( !ConvertStringSecurityDescriptorToSecurityDescriptorW(
             sddl.c_str(), SDDL_REVISION_1, &descriptor_, nullptr) )
    {
      throw std::runtime_error("failed to build named pipe security descriptor");
    }
    attributes_.nLength = sizeof(attributes_);
    attributes_.lpSecurityDescriptor = descriptor_;
    attributes_.bInheritHandle = FALSE;
  }

  ~PipeSecurity()
  {
    if ( descriptor_ != nullptr )
      LocalFree(descriptor_);
  }
  SECURITY_ATTRIBUTES *Attributes() noexcept { return &attributes_; }

private:
  PSECURITY_DESCRIPTOR descriptor_ = nullptr;
  SECURITY_ATTRIBUTES attributes_{};
};

DWORD RemainingTimeout(std::chrono::steady_clock::time_point deadline)
{
  const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
      deadline - std::chrono::steady_clock::now());
  if ( remaining.count() <= 0 )
    throw std::runtime_error("RPC pipe deadline exceeded");
  return static_cast<DWORD>((std::min)(remaining.count(), static_cast<long long>(MAXDWORD)));
}

DWORD CompleteOverlapped(
    HANDLE pipe,
    OVERLAPPED &operation,
    HANDLE stop_event,
    std::chrono::steady_clock::time_point deadline)
{
  const HANDLE events[] = {stop_event, operation.hEvent};
  const DWORD selected = WaitForMultipleObjects(2, events, FALSE, RemainingTimeout(deadline));
  if ( selected != WAIT_OBJECT_0 + 1 )
  {
    CancelIoEx(pipe, &operation);
    WaitForSingleObject(operation.hEvent, INFINITE);
    if ( selected == WAIT_OBJECT_0 )
      throw std::runtime_error("RPC pipe is stopping");
    throw std::runtime_error("RPC pipe deadline exceeded");
  }
  DWORD transferred = 0;
  if ( !GetOverlappedResult(pipe, &operation, &transferred, FALSE) )
    throw std::runtime_error("RPC pipe operation failed");
  return transferred;
}

DWORD ReadChunk(
    HANDLE pipe,
    std::uint8_t *output,
    DWORD size,
    HANDLE stop_event,
    std::chrono::steady_clock::time_point deadline)
{
  Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  if ( event.Get() == nullptr )
    throw std::runtime_error("failed to create RPC read event");
  OVERLAPPED operation{};
  operation.hEvent = event.Get();
  DWORD transferred = 0;
  if ( ReadFile(pipe, output, size, &transferred, &operation) )
    return transferred;
  if ( GetLastError() != ERROR_IO_PENDING )
    throw std::runtime_error("RPC pipe read failed");
  return CompleteOverlapped(pipe, operation, stop_event, deadline);
}

void ReadExact(
    HANDLE pipe,
    std::uint8_t *output,
    std::size_t size,
    HANDLE stop_event,
    std::chrono::steady_clock::time_point deadline)
{
  std::size_t offset = 0;
  while ( offset < size )
  {
    const DWORD chunk = static_cast<DWORD>((std::min)(
        size - offset, static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
    const DWORD received = ReadChunk(pipe, output + offset, chunk, stop_event, deadline);
    if ( received == 0 )
      throw std::runtime_error("RPC pipe client disconnected");
    offset += received;
  }
}

DWORD WriteChunk(
    HANDLE pipe,
    const std::uint8_t *data,
    DWORD size,
    HANDLE stop_event,
    std::chrono::steady_clock::time_point deadline)
{
  Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  if ( event.Get() == nullptr )
    throw std::runtime_error("failed to create RPC write event");
  OVERLAPPED operation{};
  operation.hEvent = event.Get();
  DWORD transferred = 0;
  if ( WriteFile(pipe, data, size, &transferred, &operation) )
    return transferred;
  if ( GetLastError() != ERROR_IO_PENDING )
    throw std::runtime_error("RPC pipe write failed");
  return CompleteOverlapped(pipe, operation, stop_event, deadline);
}

void WriteExact(
    HANDLE pipe,
    const std::uint8_t *data,
    std::size_t size,
    HANDLE stop_event,
    std::chrono::steady_clock::time_point deadline)
{
  std::size_t offset = 0;
  while ( offset < size )
  {
    const DWORD chunk = static_cast<DWORD>((std::min)(
        size - offset, static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
    const DWORD written = WriteChunk(pipe, data + offset, chunk, stop_event, deadline);
    if ( written == 0 )
      throw std::runtime_error("RPC pipe response write failed");
    offset += written;
  }
}

std::string ReadPayload(
    HANDLE pipe,
    HANDLE stop_event,
    std::chrono::steady_clock::time_point deadline)
{
  std::array<std::uint8_t, rpc::RequestHeaderBytes> encoded_header{};
  ReadExact(pipe, encoded_header.data(), encoded_header.size(), stop_event, deadline);
  const rpc::RequestFrameHeader header = rpc::ParseRequestFrameHeader(encoded_header);
  std::string payload(header.payload_size, '\0');
  ReadExact(
      pipe,
      reinterpret_cast<std::uint8_t *>(payload.data()),
      payload.size(),
      stop_event,
      deadline);
  return payload;
}

void SendPayload(
    HANDLE pipe,
    std::string_view payload,
    HANDLE stop_event,
    std::chrono::steady_clock::time_point deadline)
{
  const auto header = rpc::BuildResponseFrameHeader(static_cast<std::uint32_t>(payload.size()));
  WriteExact(pipe, header.data(), header.size(), stop_event, deadline);
  WriteExact(
      pipe,
      reinterpret_cast<const std::uint8_t *>(payload.data()),
      payload.size(),
      stop_event,
      deadline);
}

void WaitForClientClose(
    HANDLE pipe,
    HANDLE stop_event,
    std::chrono::steady_clock::time_point deadline)
{
  Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  if ( event.Get() == nullptr )
    throw std::runtime_error("failed to create RPC close event");
  OVERLAPPED operation{};
  operation.hEvent = event.Get();
  std::uint8_t ignored = 0;
  DWORD transferred = 0;
  if ( ReadFile(pipe, &ignored, 1, &transferred, &operation) )
    return;

  const DWORD read_error = GetLastError();
  if ( read_error == ERROR_BROKEN_PIPE || read_error == ERROR_NO_DATA )
    return;
  if ( read_error != ERROR_IO_PENDING )
    throw std::runtime_error("failed to wait for RPC client close");

  const HANDLE events[] = {stop_event, event.Get()};
  DWORD selected = WAIT_TIMEOUT;
  try
  {
    selected = WaitForMultipleObjects(2, events, FALSE, RemainingTimeout(deadline));
  }
  catch ( const std::exception & )
  {
    CancelIoEx(pipe, &operation);
    WaitForSingleObject(event.Get(), INFINITE);
    return;
  }
  if ( selected == WAIT_OBJECT_0 )
  {
    CancelIoEx(pipe, &operation);
    WaitForSingleObject(event.Get(), INFINITE);
    return;
  }
  if ( selected != WAIT_OBJECT_0 + 1 )
  {
    CancelIoEx(pipe, &operation);
    WaitForSingleObject(event.Get(), INFINITE);
    throw std::runtime_error("failed while waiting for RPC client close");
  }

  if ( !GetOverlappedResult(pipe, &operation, &transferred, FALSE) )
  {
    const DWORD result_error = GetLastError();
    if ( result_error != ERROR_BROKEN_PIPE
        && result_error != ERROR_NO_DATA
        && result_error != ERROR_OPERATION_ABORTED )
    {
      throw std::runtime_error("RPC client close wait failed");
    }
  }
}

} // namespace

class NamedPipeServer::Impl
{
public:
  ~Impl() { Stop({}); }

  void Start(
      std::wstring pipe_name,
      std::string instance_id,
      std::uint32_t pid,
      Dispatcher::MethodHandlers handlers,
      std::function<void()> unavailable)
  {
    if ( running_ )
      throw std::logic_error("RPC server is already running");
    pipe_name_ = std::move(pipe_name);
    instance_id_ = std::move(instance_id);
    pid_ = pid;
    unavailable_ = std::move(unavailable);
    dispatcher_ = std::make_unique<Dispatcher>(instance_id_, std::move(handlers));
    security_ = std::make_unique<PipeSecurity>();
    stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if ( stop_event_ == nullptr )
      throw std::runtime_error("failed to create RPC stop event");

    Handle first = CreatePipeInstance();
    {
      std::lock_guard<std::mutex> lock(clients_mutex_);
      stopping_ = false;
    }
    running_ = true;
    try
    {
      for ( std::size_t index = 0; index < IoWorkerCount; ++index )
        io_workers_.emplace_back([this]() { ProcessClients(); });
      listener_thread_ = std::thread([this, first = std::move(first)]() mutable
      {
        Run(std::move(first));
      });
    }
    catch ( ... )
    {
      Stop({});
      throw;
    }
  }

  void Stop(const std::function<void(const char *)> &trace) noexcept
  {
    TraceShutdown(trace, "pipe.stop.signal.begin");
    if ( stop_event_ != nullptr )
      SetEvent(stop_event_);
    {
      std::lock_guard<std::mutex> lock(clients_mutex_);
      stopping_ = true;
      for ( const auto &client : pending_clients_ )
        client->Close();
      pending_clients_.clear();
      for ( const auto &client : active_clients_ )
        client->Cancel();
    }
    clients_ready_.notify_all();
    TraceShutdown(trace, "pipe.stop.signal.end");
    TraceShutdown(trace, "pipe.stop.listener_join.begin");
    if ( listener_thread_.joinable() )
      listener_thread_.join();
    TraceShutdown(trace, "pipe.stop.listener_join.end");
    TraceShutdown(trace, "pipe.stop.workers_join.begin");
    for ( std::thread &worker : io_workers_ )
    {
      if ( worker.joinable() )
        worker.join();
    }
    io_workers_.clear();
    TraceShutdown(trace, "pipe.stop.workers_join.end");
    if ( stop_event_ != nullptr )
    {
      CloseHandle(stop_event_);
      stop_event_ = nullptr;
    }
    running_ = false;
    dispatcher_.reset();
    security_.reset();
    unavailable_ = {};
    pipe_name_.clear();
    instance_id_.clear();
    pid_ = 0;
    TraceShutdown(trace, "pipe.stop.end");
  }

  const std::wstring &PipeName() const noexcept { return pipe_name_; }

private:
  Handle CreatePipeInstance()
  {
    Handle pipe(CreateNamedPipeW(
        pipe_name_.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        static_cast<DWORD>(MaxPendingClients + IoWorkerCount),
        static_cast<DWORD>(rpc::MaxMessageBytes),
        static_cast<DWORD>(rpc::MaxMessageBytes),
        0,
        security_->Attributes()));
    if ( pipe.Get() == INVALID_HANDLE_VALUE )
      throw std::runtime_error("failed to create RPC named pipe");
    return pipe;
  }

  bool ConnectClient(HANDLE pipe)
  {
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if ( event.Get() == nullptr )
      throw std::runtime_error("failed to create pipe connection event");
    OVERLAPPED operation{};
    operation.hEvent = event.Get();
    if ( ConnectNamedPipe(pipe, &operation) )
      return true;
    const DWORD error = GetLastError();
    if ( error == ERROR_PIPE_CONNECTED )
      return true;
    if ( error != ERROR_IO_PENDING )
      throw std::runtime_error("failed to accept RPC pipe client");
    const HANDLE events[] = {stop_event_, event.Get()};
    const DWORD selected = WaitForMultipleObjects(2, events, FALSE, INFINITE);
    if ( selected == WAIT_OBJECT_0 )
    {
      CancelIoEx(pipe, &operation);
      WaitForSingleObject(event.Get(), INFINITE);
      return false;
    }
    if ( selected != WAIT_OBJECT_0 + 1 )
      throw std::runtime_error("failed while accepting RPC pipe client");
    DWORD ignored = 0;
    if ( !GetOverlappedResult(pipe, &operation, &ignored, FALSE)
      && GetLastError() != ERROR_PIPE_CONNECTED )
    {
      throw std::runtime_error("failed to complete RPC pipe connection");
    }
    return true;
  }

  void Run(Handle pipe) noexcept
  {
    bool unavailable = false;
    try
    {
      while ( WaitForSingleObject(stop_event_, 0) != WAIT_OBJECT_0 )
      {
        if ( !ConnectClient(pipe.Get()) )
          break;
        auto client = std::make_shared<ClientConnection>(pipe.Release());
        {
          std::lock_guard<std::mutex> lock(clients_mutex_);
          if ( stopping_ || pending_clients_.size() >= MaxPendingClients )
          {
            client->Close();
          }
          else
          {
            pending_clients_.push_back(std::move(client));
            clients_ready_.notify_one();
          }
        }
        pipe = CreatePipeInstance();
      }
    }
    catch ( const std::exception & )
    {
      unavailable = WaitForSingleObject(stop_event_, 0) != WAIT_OBJECT_0;
    }
    if ( unavailable && unavailable_ )
      unavailable_();
  }

  void ProcessClients() noexcept
  {
    while ( true )
    {
      std::shared_ptr<ClientConnection> client;
      {
        std::unique_lock<std::mutex> lock(clients_mutex_);
        clients_ready_.wait(lock, [this]() { return stopping_ || !pending_clients_.empty(); });
        if ( stopping_ && pending_clients_.empty() )
          return;
        client = std::move(pending_clients_.front());
        pending_clients_.pop_front();
        active_clients_.push_back(client);
      }
      try
      {
        HandleClient(client->Get());
      }
      catch ( const std::exception & )
      {
        // Invalid handshakes and framing errors close without exposing details.
      }
      {
        std::lock_guard<std::mutex> lock(clients_mutex_);
        active_clients_.erase(
            std::remove(active_clients_.begin(), active_clients_.end(), client),
            active_clients_.end());
      }
      client->Close();
    }
  }

  void HandleClient(HANDLE pipe)
  {
    const auto input_deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(ClientInputTimeoutMs);
    const rpc::Json hello = rpc::ParseRootObject(ReadPayload(pipe, stop_event_, input_deadline));
    rpc::RequireExactFields(hello, {"method", "params"});
    if ( rpc::ReadString(hello, "method") != "hello" )
      throw std::invalid_argument("hello handshake is required");
    const rpc::Json &params = rpc::ReadObject(hello, "params");
    rpc::RequireExactFields(params, {"protocol", "client"});
    if ( rpc::ReadUnsigned(params, "protocol") != 1
      || rpc::ReadString(params, "client") != "ida-mcp" )
    {
      throw std::invalid_argument("hello handshake is incompatible");
    }
    SendPayload(
        pipe,
        rpc::Json{
            {"product", "ida-agent-plugin"},
            {"protocol", 1},
            {"instance_id", instance_id_},
            {"pid", pid_},
        }.dump(),
        stop_event_,
        input_deadline);

    const std::string payload = ReadPayload(pipe, stop_event_, input_deadline);
    rpc::Request request;
    try
    {
      request = rpc::ParseRequest(payload);
    }
    catch ( const std::exception & )
    {
      const rpc::RequestCorrelation correlation = rpc::ParseRequestCorrelation(payload);
      SendResponse(pipe, rpc::Response{
          std::string(rpc::ProtocolVersion),
          correlation.request_id,
          correlation.session_id,
          std::nullopt,
          rpc::RpcError{rpc::ErrorCode::InvalidArgument, "RPC request is invalid", false},
      }, input_deadline);
      return;
    }

    const auto operation_deadline = std::chrono::steady_clock::now()
        + std::chrono::milliseconds(request.timeout_ms);
    rpc::Response response;
    try
    {
      response = dispatcher_->Dispatch(request);
    }
    catch ( const std::exception & )
    {
      response = rpc::Response{
          std::string(rpc::ProtocolVersion),
          request.request_id,
          request.session_id,
          std::nullopt,
          rpc::RpcError{rpc::ErrorCode::InternalError, "RPC dispatch failed", false},
      };
    }
    const auto completed_at = std::chrono::steady_clock::now();
    if ( completed_at > operation_deadline )
    {
      response = rpc::Response{
          std::string(rpc::ProtocolVersion),
          request.request_id,
          request.session_id,
          std::nullopt,
          rpc::RpcError{rpc::ErrorCode::Timeout, "RPC request timed out", true},
      };
    }
    const auto response_deadline = (std::max)(operation_deadline, completed_at)
        + std::chrono::milliseconds(ResponseGraceMs);
    SendResponse(pipe, response, response_deadline);
  }

  void SendResponse(
      HANDLE pipe,
      const rpc::Response &response,
      std::chrono::steady_clock::time_point deadline)
  {
    std::string payload = rpc::SerializeResponse(response);
    if ( payload.size() > MaxRpcResponseBytes )
    {
      payload = rpc::SerializeResponse(rpc::Response{
          std::string(rpc::ProtocolVersion),
          response.request_id,
          response.session_id,
          std::nullopt,
          rpc::RpcError{
              rpc::ErrorCode::OutputLimit,
              "RPC response exceeds the configured limit",
              false,
          },
      });
    }
    SendPayload(pipe, payload, stop_event_, deadline);
    WaitForClientClose(pipe, stop_event_, deadline);
  }

  bool running_ = false;
  HANDLE stop_event_ = nullptr;
  std::wstring pipe_name_;
  std::string instance_id_;
  std::uint32_t pid_ = 0;
  std::unique_ptr<PipeSecurity> security_;
  std::unique_ptr<Dispatcher> dispatcher_;
  std::function<void()> unavailable_;
  std::thread listener_thread_;
  std::vector<std::thread> io_workers_;
  std::mutex clients_mutex_;
  std::condition_variable clients_ready_;
  std::deque<std::shared_ptr<ClientConnection>> pending_clients_;
  std::vector<std::shared_ptr<ClientConnection>> active_clients_;
  bool stopping_ = false;
};

NamedPipeServer::NamedPipeServer() : impl_(std::make_unique<Impl>()) {}
NamedPipeServer::~NamedPipeServer() = default;

void NamedPipeServer::Start(
    std::wstring pipe_name,
    std::string instance_id,
    std::uint32_t pid,
    Dispatcher::MethodHandlers handlers,
    std::function<void()> unavailable)
{
  impl_->Start(
      std::move(pipe_name),
      std::move(instance_id),
      pid,
      std::move(handlers),
      std::move(unavailable));
}

void NamedPipeServer::Stop(const std::function<void(const char *)> &trace) noexcept
{
  impl_->Stop(trace);
}

const std::wstring &NamedPipeServer::PipeName() const noexcept
{
  return impl_->PipeName();
}

} // namespace ida_agent::bridge
