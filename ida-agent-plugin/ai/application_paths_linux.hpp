#pragma once
#include "ai/application_paths.hpp"
#include <cstdlib>
#include <pwd.h>
#include <unistd.h>
#include <vector>

namespace ida_agent::ai
{
inline std::filesystem::path LinuxHomeDirectory()
{
  if (const char *home = std::getenv("HOME"); home && *home == '/')
    return std::filesystem::path(home).lexically_normal();
  struct passwd entry{}, *found = nullptr;
  std::vector<char> buffer(65536);
  if (getpwuid_r(getuid(), &entry, buffer.data(), buffer.size(), &found) != 0
      || !found || !entry.pw_dir || *entry.pw_dir != '/') return {};
  return std::filesystem::path(entry.pw_dir).lexically_normal();
}

inline std::filesystem::path LinuxAiPath(const char *xdg_name,
    const char *fallback, const std::filesystem::path &filename)
{
  std::filesystem::path base;
  if (const char *xdg = std::getenv(xdg_name); xdg && *xdg == '/') base = xdg;
  else
  {
    base = LinuxHomeDirectory();
    if (base.empty()) return {};
#ifdef __APPLE__
    base /= "Library/Application Support";
#else
    base /= fallback;
#endif
  }
  return ResolveAiDataPath(base.lexically_normal(), filename);
}
}
