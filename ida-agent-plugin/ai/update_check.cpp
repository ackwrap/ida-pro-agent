#include "ai/update_check.hpp"

#include <nlohmann/json.hpp>

#include <charconv>
#include <limits>
#include <utility>

namespace ida_agent::ai
{
namespace
{
bool ValidIdentifiers(std::string_view text, bool numeric_leading_zero)
{
  if ( text.empty() ) return false;
  while ( !text.empty() )
  {
    const auto end = text.find('.');
    const auto part = text.substr(0, end);
    if ( part.empty() ) return false;
    bool numeric = true;
    for ( const char c : part )
    {
      if ( !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z')
          || (c >= 'a' && c <= 'z') || c == '-') ) return false;
      numeric = numeric && c >= '0' && c <= '9';
    }
    if ( numeric_leading_zero && numeric && part.size() > 1 && part[0] == '0' )
      return false;
    if ( end == std::string_view::npos ) return true;
    text.remove_prefix(end + 1);
  }
  return false;
}
}

std::optional<ProductVersion> ParseProductVersion(std::string_view text)
{
  if ( text.empty() || text.size() > 128 ) return std::nullopt;
  if ( text.front() == 'v' ) text.remove_prefix(1);
  const auto build = text.find('+');
  if ( build != std::string_view::npos )
  {
    if ( !ValidIdentifiers(text.substr(build + 1), false) ) return std::nullopt;
    text = text.substr(0, build);
  }
  ProductVersion version;
  const auto pre = text.find('-');
  if ( pre != std::string_view::npos )
  {
    if ( !ValidIdentifiers(text.substr(pre + 1), true) ) return std::nullopt;
    version.prerelease = true;
    text = text.substr(0, pre);
  }
  for ( std::size_t i = 0; i < version.numbers.size(); ++i )
  {
    const auto end = text.find('.');
    const auto part = text.substr(0, end);
    if ( part.empty() || (part.size() > 1 && part.front() == '0')
        || (i < 2 && end == std::string_view::npos)
        || (i == 2 && end != std::string_view::npos) ) return std::nullopt;
    const auto converted = std::from_chars(part.data(), part.data() + part.size(), version.numbers[i]);
    if ( converted.ec != std::errc{} || converted.ptr != part.data() + part.size()
        || version.numbers[i] > 2147483647u ) return std::nullopt;
    if ( end != std::string_view::npos ) text.remove_prefix(end + 1);
  }
  return version;
}

bool IsStableReleaseTag(std::string_view tag)
{
  const auto version = ParseProductVersion(tag);
  return version && !version->prerelease;
}

bool HasNewerRelease(std::string_view installed, std::string_view release_tag)
{
  const auto current = ParseProductVersion(installed);
  const auto latest = ParseProductVersion(release_tag);
  if ( !current || !latest || latest->prerelease ) return false;
  return latest->numbers > current->numbers
      || (latest->numbers == current->numbers && current->prerelease);
}

bool UpdateCheckDue(const UpdateCache &cache, std::int64_t now, bool manual)
{
  return now > 0 && (cache.checked_at <= 0 || cache.checked_at > now
      || now - cache.checked_at >= (manual ? ManualUpdateInterval : UpdateCheckInterval));
}

HttpRequest MakeUpdateRequest(std::string_view installed)
{
  HttpRequest request;
  request.url = LatestReleaseApi;
  request.user_agent = "ida-agent/" + std::string(installed);
  request.headers = {{"Accept", "application/vnd.github+json"},
                     {"X-GitHub-Api-Version", "2026-03-10"}};
  request.connect_timeout_ms = 5000;
  request.send_timeout_ms = 5000;
  request.receive_timeout_ms = 10000;
  request.max_response_bytes = 1024 * 1024;
  return request;
}

UpdateCache DecodeUpdateResponse(
    const HttpResponse &response, std::int64_t now, const UpdateCache &previous)
{
  UpdateCache result = previous;
  result.checked_at = now;
  result.error = "Unable to check for updates. Try again later.";
  if ( response.status != HttpResponseStatus::Success ) return result;
  if ( response.http_status == 403 || response.http_status == 429 )
  {
    result.error = "GitHub limited update requests. Try again later.";
    return result;
  }
  if ( response.http_status == 404 )
  {
    result.error = "No published stable release is available.";
    return result;
  }
  if ( response.http_status != 200 ) return result;
  const auto document = nlohmann::json::parse(response.body, nullptr, false);
  result.error = "GitHub returned invalid release information.";
  if ( !document.is_object() || !document.contains("tag_name")
      || !document["tag_name"].is_string() || !document.contains("html_url")
      || !document["html_url"].is_string() || !document.contains("draft")
      || !document["draft"].is_boolean() || document["draft"].get<bool>()
      || !document.contains("prerelease") || !document["prerelease"].is_boolean()
      || document["prerelease"].get<bool>() || !document.contains("published_at")
      || !document["published_at"].is_string() || document["published_at"].get<std::string>().empty() )
    return result;
  const auto tag = document["tag_name"].get<std::string>();
  if ( !IsStableReleaseTag(tag)
      || document["html_url"].get<std::string>() != ReleasePagePrefix + tag ) return result;
  result.release_tag = tag;
  result.error.clear();
  return result;
}

std::string UpdateStatusText(std::string_view installed, const UpdateCache &cache)
{
  std::string status = "Installed version: " + std::string(installed) + ". ";
  if ( HasNewerRelease(installed, cache.release_tag) )
    status += "Update available: " + cache.release_tag + ".";
  else if ( !cache.release_tag.empty() && cache.error.empty() )
    status += "You have the latest stable version.";
  else if ( cache.checked_at == 0 )
    status += "Updates have not been checked yet.";
  if ( !cache.error.empty() ) status += " " + cache.error;
  return status;
}

} // namespace ida_agent::ai
