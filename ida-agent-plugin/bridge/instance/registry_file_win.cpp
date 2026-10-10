#include "instance/registry_file.hpp"

#include "crypto/secure_random.hpp"
#include "instance/instance_paths.hpp"
#include "instance/secure_file.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

namespace ida_agent::bridge
{
namespace
{

void WriteAll(HANDLE file, std::string_view contents)
{
  std::size_t offset = 0;
  while ( offset < contents.size() )
  {
    const DWORD chunk = static_cast<DWORD>(
        (std::min)(contents.size() - offset, static_cast<std::size_t>(MAXDWORD)));
    DWORD written = 0;
    if ( !WriteFile(file, contents.data() + offset, chunk, &written, nullptr) || written == 0 )
      throw std::runtime_error("failed to write instance registry");
    offset += written;
  }
}

class Handle
{
public:
  explicit Handle(HANDLE value = INVALID_HANDLE_VALUE) : value_(value) {}
  ~Handle()
  {
    if ( value_ != INVALID_HANDLE_VALUE )
      CloseHandle(value_);
  }
  HANDLE Get() const noexcept { return value_; }
  HANDLE Release() noexcept
  {
    const HANDLE value = value_;
    value_ = INVALID_HANDLE_VALUE;
    return value;
  }

private:
  HANDLE value_;
};

} // namespace

RegistryFile::~RegistryFile()
{
  Remove();
}

void RegistryFile::Publish(const rpc::InstanceDescriptor &descriptor)
{
  std::lock_guard<std::mutex> lock(mutex_);
  if ( handle_ != nullptr )
    throw std::logic_error("instance registry is already published");

  const std::filesystem::path directory = ResolveInstanceDirectory();
  EnsureCurrentUserOnlyDirectory(directory);
  const std::filesystem::path target = directory /
      (std::to_wstring(descriptor.pid) + L"-"
       + std::wstring(descriptor.instance_id.begin(), descriptor.instance_id.begin() + 8)
       + L".json");
  const std::vector<std::uint8_t> random_suffix = SecureRandom(8);
  const std::filesystem::path temporary = directory /
      (target.filename().wstring() + L".tmp-"
       + std::filesystem::path(HexEncode(random_suffix.data(), random_suffix.size())).wstring());
  std::string serialized = rpc::SerializeInstanceDescriptor(descriptor);

  bool published = false;
  try
  {
    {
      Handle file(CreateFileW(
          temporary.c_str(),
          GENERIC_WRITE,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
          nullptr,
          CREATE_NEW,
          FILE_ATTRIBUTE_TEMPORARY,
          nullptr));
      if ( file.Get() == INVALID_HANDLE_VALUE )
        throw std::runtime_error("failed to create instance registry");
      WriteAll(file.Get(), serialized);
      if ( !FlushFileBuffers(file.Get()) )
        throw std::runtime_error("failed to flush instance registry");
    }
    ApplyCurrentUserOnlyFileAcl(temporary);
    if ( !MoveFileExW(
             temporary.c_str(),
             target.c_str(),
             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) )
    {
      throw std::runtime_error("failed to publish instance registry");
    }
    published = true;
    Handle lease(CreateFileW(
        target.c_str(),
        DELETE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE,
        nullptr));
    if ( lease.Get() == INVALID_HANDLE_VALUE )
      throw std::runtime_error("failed to acquire instance registry lifetime handle");
    path_ = target;
    handle_ = static_cast<void *>(lease.Release());
  }
  catch ( ... )
  {
    if ( !published )
      DeleteFileW(temporary.c_str());
    else
      DeleteFileW(target.c_str());
    throw;
  }
}

void RegistryFile::Remove() noexcept
{
  std::lock_guard<std::mutex> lock(mutex_);
  if ( handle_ != nullptr )
  {
    CloseHandle(static_cast<HANDLE>(handle_));
    handle_ = nullptr;
  }
  path_.clear();
}

} // namespace ida_agent::bridge
