#pragma once

#include <filesystem>

namespace ida_agent::ai
{

// All plugin stores use the current product directory. No old-name fallback.
inline std::filesystem::path ResolveAiDataPath(
    const std::filesystem::path &local_app_data,
    const std::filesystem::path &filename)
{
  return local_app_data / L"ida-agent" / L"ai" / filename;
}

} // namespace ida_agent::ai
