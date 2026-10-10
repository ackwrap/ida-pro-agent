#include "ai/update_store.hpp"
#include "ai/application_paths.hpp"
#include "instance/secure_file.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <knownfolders.h>
#include <shlobj.h>
#else
#include "ai/application_paths_linux.hpp"
#include "instance/private_file_linux.hpp"
#endif

#include <nlohmann/json.hpp>

#include <exception>
#include <fstream>
#include <memory>

namespace ida_agent::ai
{
namespace
{
constexpr std::size_t MaxBytes = 64 * 1024;

nlohmann::json ReadDocument(const std::filesystem::path &path, bool &missing)
{
  missing = false;
#ifdef _WIN32
  std::error_code error;
  const auto info = std::filesystem::symlink_status(path, error);
  if ( error == std::errc::no_such_file_or_directory
      || (!error && info.type() == std::filesystem::file_type::not_found) )
  {
    missing = true;
    return {};
  }
  if ( error || info.type() != std::filesystem::file_type::regular ) return {};
  const auto size = std::filesystem::file_size(path, error);
  if ( error || size == 0 || size > MaxBytes ) return {};
  std::ifstream file(path, std::ios::binary);
  std::string contents(static_cast<std::size_t>(size), '\0');
  if ( !file.read(contents.data(), static_cast<std::streamsize>(size)) ) return {};
#else
  const auto read = ida_agent::bridge::ReadPrivateFile(path, MaxBytes);
  missing = read.status == ida_agent::bridge::PrivateReadStatus::Missing;
  if ( read.status != ida_agent::bridge::PrivateReadStatus::Loaded ) return {};
  const auto &contents = read.contents;
#endif
  return nlohmann::json::parse(contents, nullptr, false);
}

bool SaveDocument(const std::filesystem::path &path, const nlohmann::json &document)
{
  try
  {
    ida_agent::bridge::AtomicWriteCurrentUserOnlyFile(path, document.dump(2) + "\n");
    return true;
  }
  catch ( const std::exception & ) { return false; }
}
}

UpdateStore::UpdateStore(std::filesystem::path directory) : directory_(std::move(directory)) {}

bool UpdateStore::ResolveDirectory()
{
  if ( !directory_.empty() ) return true;
#ifdef _WIN32
  PWSTR raw = nullptr;
  if ( FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_CREATE, nullptr, &raw)) ) return false;
  std::unique_ptr<wchar_t, decltype(&CoTaskMemFree)> base(raw, CoTaskMemFree);
  directory_ = ResolveAiDataPath(base.get(), L"update-settings.json").parent_path();
#else
  directory_ = LinuxAiPath("XDG_CONFIG_HOME", ".config", "update-settings.json").parent_path();
#endif
  return !directory_.empty();
}

bool UpdateStore::Automatic()
{
  if ( !ResolveDirectory() ) return false;
  bool missing = false;
  const auto doc = ReadDocument(directory_ / "update-settings.json", missing);
  return missing || (doc.is_object() && doc.size() == 2
      && doc.contains("version") && doc["version"].is_number_unsigned() && doc["version"] == 1
      && doc.contains("automatic") && doc["automatic"].is_boolean() && doc["automatic"].get<bool>());
}

bool UpdateStore::SaveAutomatic(bool automatic)
{
  return ResolveDirectory() && SaveDocument(directory_ / "update-settings.json",
      {{"version", 1}, {"automatic", automatic}});
}

UpdateCache UpdateStore::LoadCache()
{
  if ( !ResolveDirectory() ) return {};
  bool missing = false;
  const auto doc = ReadDocument(directory_ / "update-cache.json", missing);
  if ( !doc.is_object() || doc.size() != 4 || !doc.contains("version")
      || !doc["version"].is_number_unsigned() || doc["version"] != 1
      || !doc.contains("checkedAt") || !doc["checkedAt"].is_number_integer()
      || doc["checkedAt"] < 0 || doc["checkedAt"] > 253402300799LL
      || !doc.contains("releaseTag") || !doc["releaseTag"].is_string()
      || !doc.contains("error") || !doc["error"].is_string() ) return {};
  UpdateCache cache{doc["checkedAt"].get<std::int64_t>(), doc["releaseTag"].get<std::string>(),
      doc["error"].get<std::string>()};
  if ( (!cache.release_tag.empty() && !IsStableReleaseTag(cache.release_tag))
      || cache.error.size() > 256 ) return {};
  return cache;
}

bool UpdateStore::SaveCache(const UpdateCache &cache)
{
  return ResolveDirectory() && SaveDocument(directory_ / "update-cache.json",
      {{"version", 1}, {"checkedAt", cache.checked_at},
       {"releaseTag", cache.release_tag}, {"error", cache.error}});
}

} // namespace ida_agent::ai
