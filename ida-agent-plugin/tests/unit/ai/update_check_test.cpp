#include "ai/update_check.hpp"
#include "ai/update_store.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <stdexcept>

namespace
{
void Require(bool value, const char *message)
{
  if ( !value ) throw std::runtime_error(message);
}
void Write(const std::filesystem::path &path, const nlohmann::json &document)
{
  std::ofstream file(path);
  file << document.dump();
  Require(static_cast<bool>(file), "fixture write failed");
}
}

int main()
{
  using namespace ida_agent::ai;
  std::ifstream input(IDA_AGENT_UPDATE_TESTDATA);
  const auto fixture = nlohmann::json::parse(input);
  for ( const auto &test : fixture["versions"] )
    Require(HasNewerRelease(test["installed"].get<std::string>(), test["tag"].get<std::string>())
        == test["newer"].get<bool>(), "version comparison mismatch");
  for ( const auto &text : fixture["invalidVersions"] )
    Require(!ParseProductVersion(text.get<std::string>()), "invalid version accepted");

  const std::int64_t now = fixture["cache"]["checkedAt"].get<std::int64_t>();
  HttpResponse response{HttpResponseStatus::Success, 200, fixture["release"].dump(), {}};
  const auto parsed = DecodeUpdateResponse(response, now, {});
  Require(parsed.release_tag == "v0.4.7" && parsed.error.empty(), "stable release rejected");
  Require(!UpdateCheckDue(parsed, now, false), "fresh automatic cache ignored");
  Require(!UpdateCheckDue(parsed, now + 59, true), "manual cooldown ignored");
  Require(UpdateCheckDue(parsed, now + 60, true), "manual retry blocked");
  Require(UpdateCheckDue(parsed, now + 86400, false), "daily retry blocked");
  Require(UpdateCheckDue(parsed, now - 1, false), "clock rollback blocks checks");
  for ( const char *field : {"draft", "prerelease"} )
  {
    auto release = fixture["release"];
    release[field] = true;
    response.body = release.dump();
    const auto invalid = DecodeUpdateResponse(response, now + 1, parsed);
    Require(!invalid.error.empty() && invalid.release_tag == parsed.release_tag,
        "unpublished release accepted or previous result lost");
    release[field] = "false";
    response.body = release.dump();
    Require(!DecodeUpdateResponse(response, now, {}).error.empty(), "invalid boolean accepted");
  }
  for ( const auto &pair : {std::pair{"html_url", "https://example.org/releases/tag/v0.4.7"},
      std::pair{"tag_name", "v0.4.7-beta"}, std::pair{"published_at", ""}} )
  {
    auto release = fixture["release"];
    release[pair.first] = pair.second;
    response.body = release.dump();
    Require(!DecodeUpdateResponse(response, now, {}).error.empty(), "unsafe release accepted");
  }
  response.body = "not-json";
  Require(!DecodeUpdateResponse(response, now, {}).error.empty(), "malformed response accepted");
  for ( const unsigned status : {403, 404, 429, 500} )
  {
    response.http_status = status;
    Require(!DecodeUpdateResponse(response, now, {}).error.empty(), "HTTP error reported as success");
  }
  response.status = HttpResponseStatus::NetworkError;
  const auto failed = DecodeUpdateResponse(response, now, parsed);
  Require(!failed.error.empty() && failed.release_tag == parsed.release_tag, "offline cache lost");
  Require(!UpdateCheckDue(failed, now + 10, false), "failure caused request loop");
  const auto request = MakeUpdateRequest("0.4.6");
  Require(request.url == LatestReleaseApi && request.user_agent == "ida-agent/0.4.6"
      && request.headers.size() == 2 && request.max_response_bytes == 1024 * 1024,
      "public update request contract mismatch");

  const auto root = std::filesystem::canonical(std::filesystem::temp_directory_path())
      / ("ida-agent-update-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
  std::filesystem::create_directories(root);
#ifndef _WIN32
  std::filesystem::permissions(root, std::filesystem::perms::owner_all);
#endif
  UpdateStore store(root);
  Require(store.Automatic(), "default automatic checks disabled");
  Require(store.SaveAutomatic(false), "opt-out save failed");
  Require(!UpdateStore(root).Automatic(), "opt-out did not persist");
  Require(store.SaveCache(parsed), "cache save failed");
  Require(!store.Automatic(), "background cache overwrote opt-out");
  Require(store.LoadCache().release_tag == parsed.release_tag, "cache did not round trip");
  Write(root / "update-settings.json", fixture["settings"]);
  Write(root / "update-cache.json", fixture["cache"]);
  Require(!store.Automatic() && store.LoadCache().checked_at == now, "shared store fixture mismatch");
  Write(root / "update-settings.json", {{"version", 1}, {"automatic", true}, {"unknown", 0}});
  Require(!store.Automatic(), "invalid config enabled network access");
  Write(root / "update-cache.json", {{"version", 1}, {"checkedAt", -1}, {"releaseTag", "v0.4.7"}, {"error", ""}});
  Require(store.LoadCache().checked_at == 0, "invalid cache accepted");
  Require(store.SaveAutomatic(true) && store.Automatic(), "manual opt-in failed");
  std::filesystem::remove_all(root);
}
