#pragma once

#include "rpc/dispatcher.hpp"
#include "rpc/instance.hpp"
#include "instance/registry_file.hpp"
#ifdef _WIN32
#include "transport/named_pipe_server.hpp"
#else
#include "transport/unix_socket_server.hpp"
#endif

#include <cstdint>
#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

namespace ida_agent::bridge
{

struct DatabaseMetadata
{
  std::string database;
  std::string input_file;
  std::string ida_version;
  std::string processor;
  std::string arch;
  std::uint8_t address_bits;
  bool decompiler;
  bool debugger;
  bool ui;
};

Dispatcher::MethodHandler BuildInstanceInfoHandler(
    rpc::InstanceDescriptor descriptor,
    std::function<rpc::Capabilities(std::uint32_t)> capabilities = {});

class Bridge
{
public:
  Bridge() = default;
  ~Bridge();
  Bridge(const Bridge &) = delete;
  Bridge &operator=(const Bridge &) = delete;

  void Start(
      DatabaseMetadata metadata,
      Dispatcher::MethodHandlers handlers = {},
      std::function<void()> quiesce = {},
      std::function<void()> unavailable = {},
      std::function<rpc::Capabilities(std::uint32_t)> capabilities = {});
  void Stop(const std::function<void(const char *)> &trace = {}) noexcept;
  bool Running() const noexcept { return running_.load(); }
  const std::string &InstanceId() const noexcept { return instance_id_; }
#ifdef _WIN32
  const std::wstring &PipeName() const noexcept { return server_.PipeName(); }
  std::string EndpointAddress() const
  {
    std::string result;
    // BuildPipeName generates ASCII identifiers only.
    for ( wchar_t character : server_.PipeName() )
      result.push_back(static_cast<char>(character));
    return result;
  }
#else
  std::string EndpointAddress() const { return server_.Path(); }
#endif

private:
#ifdef _WIN32
  NamedPipeServer server_;
#else
  UnixSocketServer server_;
#endif
  RegistryFile registry_;
  std::string instance_id_;
  std::atomic<bool> running_{false};
  std::atomic<bool> unavailable_{false};
  std::atomic<bool> stopping_{false};
  std::thread publisher_thread_;
  std::mutex server_stop_mutex_;
};

} // namespace ida_agent::bridge
