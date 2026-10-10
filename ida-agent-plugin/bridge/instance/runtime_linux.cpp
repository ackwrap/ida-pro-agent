#include "runtime_linux.hpp"

#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>
#include <stdexcept>

namespace ida_agent::bridge
{
void EnsurePrivateDirectory(const std::filesystem::path &directory)
{
  if ( !directory.is_absolute() || directory.lexically_normal() != directory || directory == "/" )
    throw std::runtime_error("instance directory must be an absolute normalized path");
  std::filesystem::path current = "/";
  for ( const auto &part : directory.relative_path() )
  {
    current /= part;
    if ( mkdir(current.c_str(), 0700) != 0 && errno != EEXIST )
      throw std::runtime_error("cannot create instance directory");
    struct stat info{};
    if ( lstat(current.c_str(), &info) != 0 || !S_ISDIR(info.st_mode)
      || (info.st_uid != 0 && info.st_uid != getuid()) )
      throw std::runtime_error("unsafe instance directory");
    if ( current == directory )
    {
      if ( info.st_uid != getuid() || (info.st_mode & 0077) != 0 )
        throw std::runtime_error("instance directory must be private and owned by this user");
    }
    else if ( (info.st_mode & 0022) != 0 && !(info.st_uid == 0 && (info.st_mode & S_ISVTX) != 0) )
      throw std::runtime_error("instance directory ancestor is writable by other users");
  }
}
}
