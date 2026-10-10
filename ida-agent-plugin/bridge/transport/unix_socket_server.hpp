#pragma once

#include "dispatcher.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace ida_agent::bridge
{
class UnixSocketServer
{
public:
  UnixSocketServer();
  ~UnixSocketServer();
  UnixSocketServer(const UnixSocketServer &) = delete;
  UnixSocketServer &operator=(const UnixSocketServer &) = delete;
  void Start(std::string path, std::string instance_id, std::uint32_t pid,
      Dispatcher::MethodHandlers handlers = {}, std::function<void()> unavailable = {});
  void Stop(const std::function<void(const char *)> &trace = {}) noexcept;
  const std::string &Path() const noexcept;
private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};
}
