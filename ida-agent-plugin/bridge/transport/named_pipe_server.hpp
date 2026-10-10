#pragma once

#include "dispatcher.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace ida_agent::bridge
{

class NamedPipeServer
{
public:
  NamedPipeServer();
  ~NamedPipeServer();
  NamedPipeServer(const NamedPipeServer &) = delete;
  NamedPipeServer &operator=(const NamedPipeServer &) = delete;

  void Start(
      std::wstring pipe_name,
      std::string instance_id,
      std::uint32_t pid,
      Dispatcher::MethodHandlers handlers = {},
      std::function<void()> unavailable = {});
  void Stop(const std::function<void(const char *)> &trace = {}) noexcept;
  const std::wstring &PipeName() const noexcept;

private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace ida_agent::bridge
