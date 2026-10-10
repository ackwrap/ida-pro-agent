#include "registry_file.hpp"
#include "instance_paths.hpp"
#include "runtime_linux.hpp"
#include "crypto/secure_random.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>
#include <stdexcept>

namespace ida_agent::bridge
{
RegistryFile::~RegistryFile() { Remove(); }

void RegistryFile::Publish(const rpc::InstanceDescriptor &descriptor)
{
  std::lock_guard<std::mutex> lock(mutex_);
  if ( file_ != -1 ) throw std::logic_error("registry is already published");
  const auto directory = ResolveInstanceDirectory();
  EnsurePrivateDirectory(directory);
  const auto target = directory / (std::to_string(descriptor.pid) + "-"
      + descriptor.instance_id.substr(0, 8) + ".json");
  const auto random = SecureRandom(8);
  const auto temporary = directory / (target.filename().string() + ".tmp-" + HexEncode(random.data(), random.size()));
  const std::string data = rpc::SerializeInstanceDescriptor(descriptor);
  int fd = open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if ( fd < 0 ) throw std::runtime_error("cannot create registry file");
  try
  {
    std::size_t offset = 0;
    while ( offset < data.size() )
    {
      const auto count = write(fd, data.data() + offset, data.size() - offset);
      if ( count < 0 && errno == EINTR ) continue;
      if ( count <= 0 ) throw std::runtime_error("cannot write registry file");
      offset += static_cast<std::size_t>(count);
    }
    if ( fsync(fd) != 0 ) throw std::runtime_error("cannot flush registry file");
    path_ = target;
    // Atomic publication without replacing another instance's entry.
    if ( link(temporary.c_str(), target.c_str()) != 0 )
      throw std::runtime_error("cannot publish registry file");
    file_ = fd;
    unlink(temporary.c_str());
  }
  catch ( ... )
  {
    close(fd);
    unlink(temporary.c_str());
    throw;
  }
}

void RegistryFile::Remove() noexcept
{
  std::lock_guard<std::mutex> lock(mutex_);
  if ( file_ != -1 )
  {
    struct stat owned{}, current{};
    if ( fstat(file_, &owned) == 0 && lstat(path_.c_str(), &current) == 0
      && owned.st_dev == current.st_dev && owned.st_ino == current.st_ino )
      unlink(path_.c_str());
    close(file_);
    file_ = -1;
  }
  path_.clear();
}
}
