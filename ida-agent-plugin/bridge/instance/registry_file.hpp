#pragma once

#include "instance.hpp"

#include <filesystem>
#include <mutex>

namespace ida_agent::bridge
{

class RegistryFile
{
public:
  RegistryFile() = default;
  ~RegistryFile();
  RegistryFile(const RegistryFile &) = delete;
  RegistryFile &operator=(const RegistryFile &) = delete;

  void Publish(const rpc::InstanceDescriptor &descriptor);
  void Remove() noexcept;

private:
  std::mutex mutex_;
  std::filesystem::path path_;
#ifdef _WIN32
  void *handle_ = nullptr;
#else
  int file_ = -1;
#endif
};

} // namespace ida_agent::bridge
