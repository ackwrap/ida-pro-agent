#include "ai/provider_url.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winhttp.h>

#include <algorithm>
#include <limits>
#include <string>

namespace ida_agent::ai::provider_detail
{
std::wstring Utf8ToWide(std::string_view value)
{
  if ( value.empty()
      || value.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()) )
  {
    return {};
  }
  const int input_size = static_cast<int>(value.size());
  const int size = MultiByteToWideChar(
      CP_UTF8,
      MB_ERR_INVALID_CHARS,
      value.data(),
      input_size,
      nullptr,
      0);
  if ( size <= 0 )
    return {};
  std::wstring converted(static_cast<std::size_t>(size), L'\0');
  if ( MultiByteToWideChar(
           CP_UTF8,
           MB_ERR_INVALID_CHARS,
           value.data(),
           input_size,
           converted.data(),
           size)
      != size )
  {
    return {};
  }
  return converted;
}

bool IsValidBaseUrl(std::string_view value)
{
  if ( value.empty()
      || value.size() > 2048
      || std::any_of(value.begin(), value.end(), [](unsigned char c) { return c < 0x20 || c == 0x7f; })
      || value.find('?') != std::string_view::npos
      || value.find('#') != std::string_view::npos )
  {
    return false;
  }

  const std::wstring url = Utf8ToWide(value);
  if ( url.empty() )
    return false;
  URL_COMPONENTS components{};
  components.dwStructSize = sizeof(components);
  components.dwSchemeLength = static_cast<DWORD>(-1);
  components.dwHostNameLength = static_cast<DWORD>(-1);
  components.dwUserNameLength = static_cast<DWORD>(-1);
  components.dwPasswordLength = static_cast<DWORD>(-1);
  components.dwUrlPathLength = static_cast<DWORD>(-1);
  components.dwExtraInfoLength = static_cast<DWORD>(-1);
  if ( !WinHttpCrackUrl(
           url.c_str(),
           static_cast<DWORD>(url.size()),
           0,
           &components)
      || components.dwHostNameLength == 0
      || components.dwUserNameLength != 0
      || components.dwPasswordLength != 0
      || components.dwExtraInfoLength != 0
      || (components.nScheme != INTERNET_SCHEME_HTTP
          && components.nScheme != INTERNET_SCHEME_HTTPS) )
  {
    return false;
  }

  return true;
}

}
