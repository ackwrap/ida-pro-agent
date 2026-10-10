#include "ai/chat_history_store.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

namespace ida_agent::ai
{
namespace
{
class WinHandle final
{
public:
  explicit WinHandle(HANDLE value) : value_(value) {}
  ~WinHandle()
  {
    if ( value_ != INVALID_HANDLE_VALUE && value_ != nullptr )
      CloseHandle(value_);
  }
  WinHandle(const WinHandle &) = delete;
  WinHandle &operator=(const WinHandle &) = delete;
  HANDLE Get() const noexcept { return value_; }

private:
  HANDLE value_;
};

}

std::optional<std::string> NormalizeDatabaseKey(const std::filesystem::path &idb_path)
{
  if ( idb_path.empty() )
    return std::nullopt;
  WinHandle file(CreateFileW(
      idb_path.c_str(),
      FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      nullptr,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      nullptr));
  if ( file.Get() == INVALID_HANDLE_VALUE )
    return std::nullopt;

  const DWORD flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
  const DWORD required = GetFinalPathNameByHandleW(file.Get(), nullptr, 0, flags);
  if ( required == 0 )
    return std::nullopt;
  std::wstring final_path(required, L'\0');
  const DWORD written = GetFinalPathNameByHandleW(
      file.Get(), final_path.data(), static_cast<DWORD>(final_path.size()), flags);
  if ( written == 0 || written >= final_path.size() )
    return std::nullopt;
  final_path.resize(written);
  if ( final_path.rfind(L"\\\\?\\UNC\\", 0) == 0 )
    final_path = L"\\\\" + final_path.substr(8);
  else if ( final_path.rfind(L"\\\\?\\", 0) == 0 )
    final_path.erase(0, 4);

  const int lowercase_size = LCMapStringEx(
      LOCALE_NAME_INVARIANT,
      LCMAP_LOWERCASE,
      final_path.data(),
      static_cast<int>(final_path.size()),
      nullptr,
      0,
      nullptr,
      nullptr,
      0);
  if ( lowercase_size <= 0 )
    return std::nullopt;
  std::wstring lowercase(static_cast<std::size_t>(lowercase_size), L'\0');
  if ( LCMapStringEx(
           LOCALE_NAME_INVARIANT,
           LCMAP_LOWERCASE,
           final_path.data(),
           static_cast<int>(final_path.size()),
           lowercase.data(),
           lowercase_size,
           nullptr,
           nullptr,
           0) != lowercase_size )
  {
    return std::nullopt;
  }

  const int utf8_size = WideCharToMultiByte(
      CP_UTF8,
      WC_ERR_INVALID_CHARS,
      lowercase.data(),
      lowercase_size,
      nullptr,
      0,
      nullptr,
      nullptr);
  if ( utf8_size <= 0 )
    return std::nullopt;
  std::string key(static_cast<std::size_t>(utf8_size), '\0');
  if ( WideCharToMultiByte(
           CP_UTF8,
           WC_ERR_INVALID_CHARS,
           lowercase.data(),
           lowercase_size,
           key.data(),
           utf8_size,
           nullptr,
           nullptr) != utf8_size )
  {
    return std::nullopt;
  }
  return key;
}

}
