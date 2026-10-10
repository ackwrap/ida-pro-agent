#pragma once

#include "ai/http_client.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace ida_agent::ai
{

inline constexpr const char *LatestReleaseApi =
    "https://api.github.com/repos/ackwrap/ida-pro-agent/releases/latest";
inline constexpr const char *ReleasePagePrefix =
    "https://github.com/ackwrap/ida-pro-agent/releases/tag/";
inline constexpr std::int64_t UpdateCheckInterval = 24 * 60 * 60;
inline constexpr std::int64_t ManualUpdateInterval = 60;

struct ProductVersion
{
  std::array<std::uint32_t, 3> numbers{};
  bool prerelease = false;
};

struct UpdateCache
{
  std::int64_t checked_at = 0;
  std::string release_tag;
  std::string error;
};

std::optional<ProductVersion> ParseProductVersion(std::string_view text);
bool IsStableReleaseTag(std::string_view tag);
bool HasNewerRelease(std::string_view installed, std::string_view release_tag);
bool UpdateCheckDue(const UpdateCache &cache, std::int64_t now, bool manual);
HttpRequest MakeUpdateRequest(std::string_view installed);
// Successful metadata is restricted to a published stable release in our public repo.
UpdateCache DecodeUpdateResponse(
    const HttpResponse &response, std::int64_t now, const UpdateCache &previous);
std::string UpdateStatusText(std::string_view installed, const UpdateCache &cache);

} // namespace ida_agent::ai
