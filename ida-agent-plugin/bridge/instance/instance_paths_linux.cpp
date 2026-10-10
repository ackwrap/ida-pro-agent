#include "instance_paths.hpp"

#include <unistd.h>
#include <cstdlib>
#include <string>

namespace ida_agent::bridge
{
std::filesystem::path ResolveInstanceDirectory()
{
  const char *override_path = std::getenv("IDA_AGENT_INSTANCE_DIR");
  if ( override_path != nullptr && *override_path != '\0' )
    return override_path;
#ifdef __APPLE__
  // macOS /tmp is a symlink; retain the no-symlink directory validation.
  const auto root = "/private/tmp";
#else
  const auto root = "/tmp";
#endif
  return std::filesystem::path(root) / ("ida-agent-" + std::to_string(getuid())) / "instances";
}
}
