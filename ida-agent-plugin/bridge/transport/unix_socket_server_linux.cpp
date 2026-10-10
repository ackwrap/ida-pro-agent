#include "unix_socket_server.hpp"
#include "unix_socket_platform.hpp"
#include "framing.hpp"
#include "validation.hpp"
#include "instance/runtime_linux.hpp"

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <poll.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <mutex>
#include <set>
#include <stdexcept>
#include <thread>
#include <vector>

namespace ida_agent::bridge
{
namespace
{
using Clock = std::chrono::steady_clock;
constexpr std::size_t WorkerCount = 4;
constexpr std::size_t MaxPending = 8;
constexpr std::size_t MaxResponse = 256 * 1024;
}

class UnixSocketServer::Impl
{
public:
  ~Impl() { Stop(); }

  void Start(std::string path, std::string id, std::uint32_t pid,
      Dispatcher::MethodHandlers handlers, std::function<void()> unavailable)
  {
    if ( listener_ != -1 ) throw std::logic_error("Unix server already started");
    sockaddr_un address{};
    if ( path.empty() || path.size() >= sizeof(address.sun_path) )
      throw std::invalid_argument("Unix socket path is too long");
    EnsurePrivateDirectory(std::filesystem::path(path).parent_path());
    path_ = std::move(path);
    id_ = std::move(id);
    pid_ = pid;
    unavailable_ = std::move(unavailable);
    dispatcher_ = std::make_unique<Dispatcher>(id_, std::move(handlers));
    stopping_ = false;
    listener_ = socket_platform::Create();
    if ( listener_ < 0 ) throw std::runtime_error("cannot create Unix socket");
    try
    {
      address.sun_family = AF_UNIX;
      std::memcpy(address.sun_path, path_.c_str(), path_.size() + 1);
      // Never unlink an existing socket: the path belongs to a unique instance.
      if ( bind(listener_, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0 )
        throw std::runtime_error("cannot bind Unix socket");
      bound_ = true;
      if ( lstat(path_.c_str(), &owned_socket_) != 0 || chmod(path_.c_str(), 0600) != 0
        || listen(listener_, static_cast<int>(MaxPending)) != 0 )
        throw std::runtime_error("cannot initialize private Unix socket");
      for ( std::size_t i = 0; i < WorkerCount; ++i )
        workers_.emplace_back([this]() { Worker(); });
      acceptor_ = std::thread([this]() { Accept(); });
    }
    catch ( ... ) { Stop(); throw; }
  }

  void Stop() noexcept
  {
    stopping_ = true;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      for ( int fd : active_ ) shutdown(fd, SHUT_RDWR);
      for ( int fd : pending_ ) close(fd);
      pending_.clear();
    }
    ready_.notify_all();
    if ( acceptor_.joinable() ) acceptor_.join();
    for ( auto &worker : workers_ ) if ( worker.joinable() ) worker.join();
    workers_.clear();
    if ( listener_ != -1 ) { close(listener_); listener_ = -1; }
    if ( bound_ )
    {
      struct stat current{};
      if ( lstat(path_.c_str(), &current) == 0 && current.st_dev == owned_socket_.st_dev
        && current.st_ino == owned_socket_.st_ino ) unlink(path_.c_str());
      bound_ = false;
    }
    dispatcher_.reset();
  }

  const std::string &Path() const noexcept { return path_; }

private:
  void Await(int fd, short events, Clock::time_point deadline)
  {
    while ( !stopping_ )
    {
      const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
      if ( remaining <= 0 ) throw std::runtime_error("socket timeout");
      pollfd item{fd, events, 0};
      const int result = poll(&item, 1, static_cast<int>((std::min)(remaining, decltype(remaining)(100))));
      if ( result < 0 && errno == EINTR ) continue;
      if ( result < 0 ) throw std::runtime_error("socket poll failed");
      if ( result == 0 ) continue;
      if ( (item.revents & events) != 0 ) return;
      throw std::runtime_error("socket disconnected");
    }
    throw std::runtime_error("server stopped");
  }

  void Read(int fd, void *buffer, std::size_t size, Clock::time_point deadline)
  {
    auto *out = static_cast<char *>(buffer);
    while ( size != 0 )
    {
      Await(fd, POLLIN, deadline);
      const auto count = recv(fd, out, size, 0);
      if ( count < 0 && (errno == EINTR || errno == EAGAIN) ) continue;
      if ( count <= 0 ) throw std::runtime_error("socket read failed");
      out += count;
      size -= static_cast<std::size_t>(count);
    }
  }

  void Write(int fd, const void *buffer, std::size_t size, Clock::time_point deadline)
  {
    const auto *data = static_cast<const char *>(buffer);
    while ( size != 0 )
    {
      Await(fd, POLLOUT, deadline);
      const auto count = send(fd, data, size, socket_platform::SendFlags);
      if ( count < 0 && (errno == EINTR || errno == EAGAIN) ) continue;
      if ( count <= 0 ) throw std::runtime_error("socket write failed");
      data += count;
      size -= static_cast<std::size_t>(count);
    }
  }

  std::string ReadPayload(int fd, Clock::time_point deadline)
  {
    std::array<std::uint8_t, rpc::RequestHeaderBytes> encoded{};
    Read(fd, encoded.data(), encoded.size(), deadline);
    const auto header = rpc::ParseRequestFrameHeader(encoded);
    std::string payload(header.payload_size, '\0');
    Read(fd, payload.data(), payload.size(), deadline);
    return payload;
  }

  void SendPayload(int fd, const std::string &payload, Clock::time_point deadline)
  {
    const auto header = rpc::BuildResponseFrameHeader(static_cast<std::uint32_t>(payload.size()));
    Write(fd, header.data(), header.size(), deadline);
    Write(fd, payload.data(), payload.size(), deadline);
  }

  void Handle(int fd)
  {
    const auto input_deadline = Clock::now() + std::chrono::seconds(5);
    const auto hello = rpc::ParseRootObject(ReadPayload(fd, input_deadline));
    rpc::RequireExactFields(hello, {"method", "params"});
    const auto &params = rpc::ReadObject(hello, "params");
    rpc::RequireExactFields(params, {"protocol", "client"});
    if ( rpc::ReadString(hello, "method") != "hello" || rpc::ReadUnsigned(params, "protocol") != 1
      || rpc::ReadString(params, "client") != "ida-mcp" )
      throw std::invalid_argument("incompatible hello");
    SendPayload(fd, rpc::Json{{"product", "ida-agent-plugin"}, {"protocol", 1},
        {"instance_id", id_}, {"pid", pid_}}.dump(), input_deadline);
    const auto payload = ReadPayload(fd, input_deadline);
    rpc::Request request;
    try { request = rpc::ParseRequest(payload); }
    catch ( const std::exception & )
    {
      const auto correlation = rpc::ParseRequestCorrelation(payload);
      SendPayload(fd, rpc::SerializeResponse({std::string(rpc::ProtocolVersion), correlation.request_id,
          correlation.session_id, std::nullopt,
          rpc::RpcError{rpc::ErrorCode::InvalidArgument, "RPC request is invalid", false}}), input_deadline);
      return;
    }
    const auto deadline = Clock::now() + std::chrono::milliseconds(request.timeout_ms);
    rpc::Response response;
    try { response = dispatcher_->Dispatch(request); }
    catch ( const std::exception & )
    {
      response = {std::string(rpc::ProtocolVersion), request.request_id, request.session_id,
          std::nullopt, rpc::RpcError{rpc::ErrorCode::InternalError, "RPC dispatch failed", false}};
    }
    if ( Clock::now() > deadline )
      response = {std::string(rpc::ProtocolVersion), request.request_id, request.session_id,
          std::nullopt, rpc::RpcError{rpc::ErrorCode::Timeout, "RPC request timed out", true}};
    auto encoded = rpc::SerializeResponse(response);
    if ( encoded.size() > MaxResponse )
      encoded = rpc::SerializeResponse({std::string(rpc::ProtocolVersion), request.request_id,
          request.session_id, std::nullopt,
          rpc::RpcError{rpc::ErrorCode::OutputLimit, "RPC response exceeds the configured limit", false}});
    SendPayload(fd, encoded, (std::max)(deadline, Clock::now()) + std::chrono::seconds(2));
  }

  void Accept() noexcept
  {
    while ( !stopping_ )
    {
      pollfd item{listener_, POLLIN, 0};
      const int result = poll(&item, 1, 100);
      if ( result < 0 && errno == EINTR ) continue;
      if ( result == 0 ) continue;
      if ( result < 0 || (item.revents & POLLIN) == 0 ) break;
      const int fd = socket_platform::Accept(listener_);
      if ( fd < 0 )
      {
        if ( errno == EINTR || errno == EAGAIN ) continue;
        break;
      }
      if ( !socket_platform::OwnedPeer(fd) )
      { close(fd); continue; }
      {
        std::lock_guard<std::mutex> lock(mutex_);
        if ( stopping_ || pending_.size() >= MaxPending ) { close(fd); continue; }
        pending_.push_back(fd);
      }
      ready_.notify_one();
    }
    if ( !stopping_ && unavailable_ )
    {
      try { unavailable_(); } catch ( ... ) {}
    }
  }

  void Worker() noexcept
  {
    for ( ;; )
    {
      int fd;
      {
        std::unique_lock<std::mutex> lock(mutex_);
        ready_.wait(lock, [this]() { return stopping_ || !pending_.empty(); });
        if ( stopping_ ) return;
        fd = pending_.front();
        pending_.pop_front();
        active_.insert(fd);
      }
      try { Handle(fd); } catch ( ... ) {}
      {
        std::lock_guard<std::mutex> lock(mutex_);
        active_.erase(fd);
        close(fd);
      }
    }
  }

  std::string path_, id_;
  std::uint32_t pid_ = 0;
  int listener_ = -1;
  bool bound_ = false;
  struct stat owned_socket_{};
  std::atomic<bool> stopping_{true};
  std::unique_ptr<Dispatcher> dispatcher_;
  std::function<void()> unavailable_;
  std::thread acceptor_;
  std::vector<std::thread> workers_;
  std::deque<int> pending_;
  std::set<int> active_;
  std::mutex mutex_;
  std::condition_variable ready_;
};

UnixSocketServer::UnixSocketServer() : impl_(std::make_unique<Impl>()) {}
UnixSocketServer::~UnixSocketServer() = default;
void UnixSocketServer::Start(std::string path, std::string id, std::uint32_t pid,
    Dispatcher::MethodHandlers handlers, std::function<void()> unavailable)
{ impl_->Start(std::move(path), std::move(id), pid, std::move(handlers), std::move(unavailable)); }
void UnixSocketServer::Stop(const std::function<void(const char *)> &) noexcept { impl_->Stop(); }
const std::string &UnixSocketServer::Path() const noexcept { return impl_->Path(); }
}
