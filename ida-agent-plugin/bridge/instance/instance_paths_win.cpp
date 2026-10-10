#include "instance/instance_paths.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <knownfolders.h>
#include <shlobj.h>

#include <cstdlib>
#include <memory>
#include <stdexcept>

namespace ida_agent::bridge
{

std::filesystem::path ResolveInstanceDirectory()
{
  if ( const wchar_t *override_path = _wgetenv(L"IDA_AGENT_INSTANCE_DIR");
       override_path != nullptr && *override_path != L'\0' )
  {
    return std::filesystem::path(override_path);
  }

  PWSTR raw_path = nullptr;
  if ( FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_CREATE, nullptr, &raw_path)) )
    throw std::runtime_error("LocalAppData directory is unavailable");
  std::unique_ptr<wchar_t, decltype(&CoTaskMemFree)> local_app_data(raw_path, CoTaskMemFree);
  return std::filesystem::path(local_app_data.get()) / L"ida-agent" / L"instances";
}

} // namespace ida_agent::bridge
