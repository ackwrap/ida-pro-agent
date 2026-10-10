#include "instance/secure_file.hpp"
#include "instance/private_file_linux.hpp"
#include "crypto/secure_random.hpp"
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>
#include <stdexcept>
#include <utility>

namespace ida_agent::bridge
{
namespace
{
class Fd
{
public:
  explicit Fd(int value = -1) : value_(value) {}
  ~Fd() { if (value_ >= 0) close(value_); }
  Fd(const Fd &) = delete;
  Fd &operator=(const Fd &) = delete;
  Fd(Fd &&other) noexcept : value_(std::exchange(other.value_, -1)) {}
  int Get() const { return value_; }
  void Reset(int value) { if (value_ >= 0) close(value_); value_ = value; }
private:
  int value_;
};

void Fail() { throw std::runtime_error("private file is unavailable or has unsafe permissions"); }

// Walk through handles so no component can be redirected through a symlink.
Fd Directory(const std::filesystem::path &path, bool create)
{
  if (!path.is_absolute() || path.lexically_normal() != path || path == "/") Fail();
  Fd parent(open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  std::filesystem::path current = "/";
  for (const auto &part : path.relative_path())
  {
    current /= part;
    if (create && mkdirat(parent.Get(), part.c_str(), 0700) != 0 && errno != EEXIST) Fail();
    const int next = openat(parent.Get(), part.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (next < 0)
    {
      if (!create && errno == ENOENT) return Fd{};
      Fail();
    }
    parent.Reset(next);
    struct stat info{};
    if (fstat(parent.Get(), &info) != 0 || !S_ISDIR(info.st_mode)
        || (info.st_uid != 0 && info.st_uid != getuid())) Fail();
    if (current == path)
    {
      if (info.st_uid != getuid() || (info.st_mode & 0077) != 0) Fail();
    }
    else if ((info.st_mode & 0022) != 0 && !(info.st_uid == 0 && (info.st_mode & S_ISVTX))) Fail();
  }
  return parent;
}

void Validate(const struct stat &info, bool allow_unlinked = false)
{
  if (!S_ISREG(info.st_mode) || info.st_uid != getuid()
      || (info.st_nlink != 1 && !(allow_unlinked && info.st_nlink == 0))
      || (info.st_mode & 0077) != 0) Fail();
}

void ValidateTarget(int directory, const std::filesystem::path &name)
{
  if (name.empty() || name == "." || name == "..") Fail();
  struct stat info{};
  // fstatat can finish on the old inode while another atomic writer replaces it.
  // Zero links is safe here: rename never writes through the old target inode.
  if (fstatat(directory, name.c_str(), &info, AT_SYMLINK_NOFOLLOW) == 0) Validate(info, true);
  else if (errno != ENOENT) Fail();
}
}

void EnsureCurrentUserOnlyDirectory(const std::filesystem::path &directory)
{
  Directory(directory, true);
}

void ApplyCurrentUserOnlyFileAcl(const std::filesystem::path &path)
{
  Fd directory = Directory(path.parent_path(), false);
  Fd file(openat(directory.Get(), path.filename().c_str(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC));
  struct stat info{};
  if (file.Get() < 0 || fstat(file.Get(), &info) != 0) Fail();
  Validate(info);
  if (fchmod(file.Get(), 0600) != 0) Fail();
}

void PreparePrivateFile(const std::filesystem::path &path)
{
  Fd directory = Directory(path.parent_path(), true);
  ValidateTarget(directory.Get(), path.filename());
  Fd file(openat(directory.Get(), path.filename().c_str(),
      O_RDWR | O_CREAT | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC, 0600));
  struct stat info{};
  if (file.Get() < 0 || fstat(file.Get(), &info) != 0) Fail();
  Validate(info);
}

PrivateReadResult ReadPrivateFile(const std::filesystem::path &path, std::size_t limit)
{
  try
  {
    Fd directory = Directory(path.parent_path(), false);
    if (directory.Get() < 0) return {PrivateReadStatus::Missing, {}};
    Fd file(openat(directory.Get(), path.filename().c_str(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC));
    if (file.Get() < 0 && errno == ENOENT) return {PrivateReadStatus::Missing, {}};
    struct stat info{};
    if (file.Get() < 0 || fstat(file.Get(), &info) != 0) Fail();
    // An atomic rename can unlink this already-open version before fstat.
    // It is still a private, complete snapshot; multiple links remain forbidden.
    Validate(info, true);
    if (info.st_size <= 0 || static_cast<std::uintmax_t>(info.st_size) > limit)
      return {PrivateReadStatus::Invalid, {}};
    std::string contents(static_cast<std::size_t>(info.st_size), '\0');
    std::size_t offset = 0;
    while (offset < contents.size())
    {
      const auto n = read(file.Get(), contents.data() + offset, contents.size() - offset);
      if (n < 0 && errno == EINTR) continue;
      if (n <= 0) Fail();
      offset += static_cast<std::size_t>(n);
    }
    char extra;
    ssize_t n;
    do { n = read(file.Get(), &extra, 1); } while (n < 0 && errno == EINTR);
    if (n != 0) return {PrivateReadStatus::Invalid, {}};
    return {PrivateReadStatus::Loaded, std::move(contents)};
  }
  catch (const std::exception &) { return {PrivateReadStatus::Unavailable, {}}; }
}

void AtomicWriteCurrentUserOnlyFile(const std::filesystem::path &target, std::string_view contents)
{
  Fd directory = Directory(target.parent_path(), true);
  const auto name = target.filename();
  ValidateTarget(directory.Get(), name);
  const auto random = SecureRandom(16);
  const auto temporary = name.string() + ".tmp-" + HexEncode(random.data(), random.size());
  Fd file(openat(directory.Get(), temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
  if (file.Get() < 0) Fail();
  try
  {
    while (!contents.empty())
    {
      const auto n = write(file.Get(), contents.data(), contents.size());
      if (n < 0 && errno == EINTR) continue;
      if (n <= 0) Fail();
      contents.remove_prefix(static_cast<std::size_t>(n));
    }
    if (fsync(file.Get()) != 0) Fail();
    ValidateTarget(directory.Get(), name);
    if (renameat(directory.Get(), temporary.c_str(), directory.Get(), name.c_str()) != 0) Fail();
    if (fsync(directory.Get()) != 0) Fail();
  }
  catch (...)
  {
    unlinkat(directory.Get(), temporary.c_str(), 0);
    throw;
  }
}
}
