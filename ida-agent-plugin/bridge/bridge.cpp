#include "bridge.hpp"

#include "envelope.hpp"
#include "framing.hpp"
#include "instance.hpp"
#include "instance/instance_identity.hpp"

#include "instance/instance_paths.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#include <unistd.h>
#endif

#include <algorithm>
#include <chrono>
#include <stdexcept>
#include <utility>
#include <vector>

namespace ida_agent::bridge
{

Dispatcher::MethodHandler BuildInstanceInfoHandler(
    rpc::InstanceDescriptor descriptor,
    std::function<rpc::Capabilities(std::uint32_t)> capabilities)
{
  return [descriptor = std::move(descriptor), capabilities = std::move(capabilities)](const rpc::Request &request) -> Dispatcher::MethodResult
  {
    if ( !request.params.empty() )
    {
      return rpc::RpcError{
          rpc::ErrorCode::InvalidArgument,
          "instance.info params must be empty",
          false,
      };
    }
    const auto current = capabilities ? capabilities(request.timeout_ms) : descriptor.capabilities;
    return nlohmann::json{
        {"instance_id", descriptor.instance_id},
        {"pid", descriptor.pid},
        {"ida_version", descriptor.ida_version},
        {"database", descriptor.database},
        {"input_file", descriptor.input_file},
        {"processor", descriptor.processor},
        {"bitness", descriptor.bitness},
        {"architecture", descriptor.arch},
        {"capabilities", {
            {"decompiler", current.decompiler},
            {"debugger", current.debugger},
            {"ui", current.ui},
            {"address_bits", current.address_bits},
        }},
    };
  };
}

Bridge::~Bridge()
{
  Stop();
}

void Bridge::Start(
    DatabaseMetadata metadata,
    Dispatcher::MethodHandlers handlers,
    std::function<void()> quiesce,
    std::function<void()> unavailable,
    std::function<rpc::Capabilities(std::uint32_t)> capabilities)
{
  if ( running_.load() )
    throw std::logic_error("Bridge is already running");
  if ( publisher_thread_.joinable() )
    publisher_thread_.join();
  registry_.Remove();
  if ( unavailable_.load() )
  {
    if ( quiesce )
      quiesce();
    server_.Stop();
    registry_.Remove();
    unavailable_.store(false);
  }

  instance_id_ = GenerateInstanceId();
  #ifdef _WIN32
  const std::uint32_t pid = static_cast<std::uint32_t>(GetCurrentProcessId());
  const std::wstring pipe_name = BuildPipeName(pid, instance_id_);
  const std::string pipe = "\\\\.\\pipe\\ida-agent-" + std::to_string(pid) + "-"
      + instance_id_.substr(0, 8);
  #else
  const std::uint32_t pid = static_cast<std::uint32_t>(getpid());
  const std::string pipe;
  const std::string pipe_name = (ResolveInstanceDirectory() /
      ("ida-agent-" + std::to_string(pid) + "-" + instance_id_.substr(0, 8) + ".sock")).string();
  #endif
  const auto started_at = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
  unavailable_.store(false);
  stopping_.store(false);
  running_.store(true);

  try
  {
    rpc::InstanceDescriptor descriptor{
        1,
        std::string(rpc::ProtocolVersion),
        instance_id_,
        pid,
        pipe,
        metadata.ida_version,
        metadata.database,
        metadata.input_file,
        metadata.processor,
        metadata.address_bits,
        started_at,
        metadata.arch,
        rpc::Capabilities{
            metadata.decompiler,
            metadata.debugger,
            metadata.ui,
            metadata.address_bits,
        },
    };
#ifndef _WIN32
    descriptor.version = 2;
    descriptor.endpoint = rpc::LocalEndpoint{"unix", pipe_name};
#endif
    handlers.emplace("instance.info", BuildInstanceInfoHandler(descriptor, std::move(capabilities)));
    server_.Start(pipe_name, instance_id_, pid, std::move(handlers), [
        this,
        quiesce,
        unavailable = std::move(unavailable)]()
    {
      if ( quiesce )
        quiesce();
      unavailable_.store(true);
      running_.store(false);
      registry_.Remove();
      if ( unavailable )
        unavailable();
    });
    publisher_thread_ = std::thread([
        this,
        descriptor = std::move(descriptor),
        quiesce]()
    {
      try
      {
        registry_.Publish(descriptor);
        if ( stopping_.load() || unavailable_.load() )
          registry_.Remove();
      }
      catch ( const std::exception & )
      {
        if ( quiesce )
          quiesce();
        stopping_.store(true);
        unavailable_.store(true);
        running_.store(false);
        {
          std::lock_guard<std::mutex> lock(server_stop_mutex_);
          server_.Stop();
        }
        registry_.Remove();
      }
    });
  }
  catch ( ... )
  {
    if ( quiesce )
      quiesce();
    {
      std::lock_guard<std::mutex> lock(server_stop_mutex_);
      server_.Stop();
    }
    if ( publisher_thread_.joinable() )
      publisher_thread_.join();
    registry_.Remove();
    instance_id_.clear();
    running_.store(false);
    throw;
  }
}

void Bridge::Stop(const std::function<void(const char *)> &trace) noexcept
{
  const auto emit = [&trace](const char *phase) noexcept
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
  };
  stopping_.store(true);
  running_.store(false);
  emit("bridge.server.stop.begin");
  {
    std::lock_guard<std::mutex> lock(server_stop_mutex_);
    server_.Stop(trace);
  }
  emit("bridge.server.stop.end");
  emit("bridge.publisher.join.begin");
  if ( publisher_thread_.joinable() )
    publisher_thread_.join();
  emit("bridge.publisher.join.end");
  emit("bridge.registry.remove.begin");
  registry_.Remove();
  emit("bridge.registry.remove.end");
  instance_id_.clear();
  unavailable_.store(false);
  stopping_.store(false);
  emit("bridge.stop.complete");
}

} // namespace ida_agent::bridge
