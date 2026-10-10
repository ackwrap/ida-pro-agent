#include "ai/agent_file_service.hpp"
#include "ai/agent_effect_digest.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cwctype>
#include <limits>
#include <stdexcept>
#include <utility>
#include <vector>

namespace ida_agent::ai
{
namespace
{
using Json = nlohmann::json;
constexpr std::uint64_t MaxAgentFileSize = 16ULL * 1024 * 1024;
constexpr std::size_t MaxDirectoryEntries = 4096;
constexpr std::size_t MaxTreeDepth = 64;
constexpr std::size_t MaxTreeEntries = 4096;
constexpr std::uint64_t MaxTreeBytes = 64ULL * 1024 * 1024;

class Handle final
{
public:
  Handle() = default;
  explicit Handle(HANDLE value) : value_(value) {}
  ~Handle() { if ( value_ != INVALID_HANDLE_VALUE ) CloseHandle(value_); }
  Handle(Handle &&other) noexcept : value_(std::exchange(other.value_, INVALID_HANDLE_VALUE)) {}
  Handle &operator=(Handle &&other) noexcept
  {
    if ( this != &other )
    {
      if ( value_ != INVALID_HANDLE_VALUE ) CloseHandle(value_);
      value_ = std::exchange(other.value_, INVALID_HANDLE_VALUE);
    }
    return *this;
  }
  Handle(const Handle &) = delete;
  Handle &operator=(const Handle &) = delete;
  explicit operator bool() const noexcept { return value_ != INVALID_HANDLE_VALUE; }
  HANDLE get() const noexcept { return value_; }
private:
  HANDLE value_ = INVALID_HANDLE_VALUE;
};

struct Root
{
  Handle handle;
  std::wstring path;
  std::wstring idb_name;
};

struct Opened
{
  Handle handle;
  BY_HANDLE_FILE_INFORMATION info{};
  std::wstring final_path;
};

bool ValidUtf8(std::string_view value)
{
  if ( value.find('\0') != std::string_view::npos ) return false;
  if ( value.empty() ) return true;
  return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
      static_cast<int>(value.size()), nullptr, 0) > 0;
}

std::wstring Wide(std::string_view value)
{
  if ( value.empty() ) return {};
  if ( value.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()) )
    throw std::runtime_error("invalid utf8");
  const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
      value.data(), static_cast<int>(value.size()), nullptr, 0);
  if ( count <= 0 ) throw std::runtime_error("invalid utf8");
  std::wstring result(static_cast<std::size_t>(count), L'\0');
  if ( MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
          static_cast<int>(value.size()), result.data(), count) != count )
    throw std::runtime_error("invalid utf8");
  return result;
}

class Utf8StreamValidator final
{
public:
  void Feed(std::string_view bytes)
  {
    for ( unsigned char byte : bytes ) Feed(byte);
  }

  bool AtBoundary() const noexcept { return remaining_ == 0; }

  void Finish() const
  {
    if ( !AtBoundary() ) throw std::runtime_error("incomplete utf8");
  }

private:
  void Feed(unsigned char byte)
  {
    if ( remaining_ == 0 )
    {
      if ( byte < 0x80 ) { CheckPoint(byte); return; }
      if ( byte >= 0xC2 && byte <= 0xDF )
      { point_ = byte & 0x1F; minimum_ = 0x80; remaining_ = 1; return; }
      if ( byte >= 0xE0 && byte <= 0xEF )
      { point_ = byte & 0x0F; minimum_ = 0x800; remaining_ = 2; return; }
      if ( byte >= 0xF0 && byte <= 0xF4 )
      { point_ = byte & 0x07; minimum_ = 0x10000; remaining_ = 3; return; }
      throw std::runtime_error("invalid utf8");
    }
    if ( (byte & 0xC0) != 0x80 ) throw std::runtime_error("invalid utf8");
    point_ = (point_ << 6) | (byte & 0x3F);
    if ( --remaining_ == 0 )
    {
      if ( point_ < minimum_ || point_ > 0x10FFFF
          || (point_ >= 0xD800 && point_ <= 0xDFFF) )
        throw std::runtime_error("invalid utf8");
      CheckPoint(point_);
    }
  }

  static void CheckPoint(std::uint32_t point)
  {
    if ( (point < 0x20 && point != '\t' && point != '\r' && point != '\n')
        || (point >= 0x7F && point <= 0x9F) )
      throw std::runtime_error("non-text control character");
  }

  std::uint32_t point_ = 0;
  std::uint32_t minimum_ = 0;
  unsigned remaining_ = 0;
};

bool ValidTextUtf8(std::string_view value)
{
  try
  {
    Utf8StreamValidator validator;
    validator.Feed(value);
    validator.Finish();
    return true;
  }
  catch ( ... ) { return false; }
}

std::string Utf8(std::wstring_view value)
{
  if ( value.empty() ) return {};
  const int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
      value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
  if ( count <= 0 ) throw std::runtime_error("invalid wide path");
  std::string result(static_cast<std::size_t>(count), '\0');
  if ( WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
          static_cast<int>(value.size()), result.data(), count, nullptr, nullptr) != count )
    throw std::runtime_error("invalid wide path");
  return result;
}

std::wstring Lower(std::wstring value)
{
  std::transform(value.begin(), value.end(), value.begin(),
      [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

std::wstring StripDevicePrefix(std::wstring path)
{
  if ( path.rfind(L"\\\\?\\UNC\\", 0) == 0 ) return L"\\\\" + path.substr(8);
  if ( path.rfind(L"\\\\?\\", 0) == 0 ) return path.substr(4);
  return path;
}

std::wstring FinalPath(HANDLE handle)
{
  const DWORD needed = GetFinalPathNameByHandleW(handle, nullptr, 0,
      FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if ( needed == 0 ) throw std::runtime_error("path unavailable");
  std::wstring value(needed, L'\0');
  const DWORD written = GetFinalPathNameByHandleW(handle, value.data(), needed,
      FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if ( written == 0 || written >= needed ) throw std::runtime_error("path unavailable");
  value.resize(written);
  while ( value.size() > 3 && (value.back() == L'\\' || value.back() == L'/') ) value.pop_back();
  return StripDevicePrefix(std::move(value));
}

bool Within(std::wstring_view root, std::wstring_view path)
{
  const std::wstring base = Lower(std::wstring(root));
  const std::wstring candidate = Lower(std::wstring(path));
  return candidate == base || (candidate.size() > base.size()
      && candidate.compare(0, base.size(), base) == 0
      && (candidate[base.size()] == L'\\' || candidate[base.size()] == L'/'));
}

bool SensitiveComponent(std::wstring_view value);

bool SensitiveRoot(std::wstring_view root)
{
  std::size_t start = 0;
  while ( start <= root.size() )
  {
    const std::size_t separator = root.find_first_of(L"\\/", start);
    const std::size_t end = separator == std::wstring_view::npos ? root.size() : separator;
    if ( end > start && SensitiveComponent(root.substr(start, end - start)) ) return true;
    if ( separator == std::wstring_view::npos ) break;
    start = separator + 1;
  }
  std::vector<std::wstring> blocked;
  std::array<wchar_t, 32768> buffer{};
  const UINT windows = GetWindowsDirectoryW(buffer.data(), static_cast<UINT>(buffer.size()));
  if ( windows > 0 && windows < buffer.size() ) blocked.emplace_back(buffer.data(), windows);
  const wchar_t *variables[]{L"ProgramFiles", L"ProgramFiles(x86)", L"ProgramData",
                             L"APPDATA", L"LOCALAPPDATA"};
  for ( const wchar_t *name : variables )
  {
    const DWORD count = GetEnvironmentVariableW(name, buffer.data(), static_cast<DWORD>(buffer.size()));
    if ( count == 0 || count >= buffer.size() ) continue;
    std::wstring value(buffer.data(), count);
    const std::wstring lowered = Lower(value);
    const std::size_t appdata = lowered.find(L"\\appdata");
    if ( appdata != std::wstring::npos ) value.resize(appdata + 8);
    blocked.push_back(std::move(value));
  }
  for ( const std::wstring &entry : blocked ) if ( Within(entry, root) ) return true;
  return false;
}

bool SensitiveComponent(std::wstring_view value)
{
  const std::wstring lower = Lower(std::wstring(value));
  static const std::wstring blocked[]{L".git", L".hg", L".svn", L".ssh", L".gnupg",
      L"system volume information", L"$recycle.bin"};
  return std::find(std::begin(blocked), std::end(blocked), lower) != std::end(blocked);
}

bool SensitiveFile(std::wstring_view value)
{
  const std::wstring lower = Lower(std::wstring(value));
  if ( lower == L".env" || lower.rfind(L".env.", 0) == 0
      || lower == L".netrc" || lower == L".npmrc" || lower == L".pypirc"
      || lower == L"credentials" || lower == L"credentials.json"
      || lower.rfind(L"secrets.", 0) == 0 ) return true;
  const std::size_t dot = lower.rfind(L'.');
  if ( dot == std::wstring::npos ) return false;
  const std::wstring extension = lower.substr(dot);
  static const std::wstring blocked[]{L".pem",L".key",L".pfx",L".p12",L".kdbx"};
  return std::find(std::begin(blocked), std::end(blocked), extension) != std::end(blocked);
}

bool DosDevice(std::wstring_view value)
{
  std::wstring name(value.substr(0, value.find(L'.')));
  while ( !name.empty() && (name.back() == L' ' || name.back() == L'.') ) name.pop_back();
  name = Lower(std::move(name));
  if ( name == L"con" || name == L"prn" || name == L"aux" || name == L"nul"
      || name == L"conin$" || name == L"conout$" || name == L"clock$" ) return true;
  if ( name.size() != 4 || (name.rfind(L"com", 0) != 0 && name.rfind(L"lpt", 0) != 0) )
    return false;
  const wchar_t digit = name[3];
  return (digit >= L'1' && digit <= L'9') || digit == L'\u00B9'
      || digit == L'\u00B2' || digit == L'\u00B3';
}

std::vector<std::wstring> Components(std::string_view path, bool allow_empty)
{
  if ( path.empty() )
  {
    if ( allow_empty ) return {};
    throw std::runtime_error("empty path");
  }
  if ( path.size() > MaxAgentFilePathBytes || !ValidUtf8(path) ) throw std::runtime_error("invalid path");
  if ( path.front() == '/' || path.front() == '\\' || (path.size() >= 2
      && std::isalpha(static_cast<unsigned char>(path[0])) && path[1] == ':') )
    throw std::runtime_error("rooted path");
  std::wstring wide = Wide(path);
  std::vector<std::wstring> result;
  std::size_t start = 0;
  while ( start <= wide.size() )
  {
    const std::size_t separator = wide.find_first_of(L"\\/", start);
    const std::size_t end = separator == std::wstring::npos ? wide.size() : separator;
    std::wstring component = wide.substr(start, end - start);
    if ( component.empty() || component == L"." || component == L".."
        || component.back() == L'.' || component.back() == L' '
        || component.find_first_of(L":*?\"<>|") != std::wstring::npos
        || std::any_of(component.begin(), component.end(), [](wchar_t ch) { return ch < 0x20 || ch == 0x7F; })
        || SensitiveComponent(component) || SensitiveFile(component) || DosDevice(component) )
      throw std::runtime_error("invalid component");
    result.push_back(std::move(component));
    if ( separator == std::wstring::npos ) break;
    start = separator + 1;
  }
  return result;
}

std::string Relative(const std::vector<std::wstring> &components)
{
  std::string result;
  for ( const std::wstring &component : components )
  {
    if ( !result.empty() ) result.push_back('/');
    result += Utf8(component);
  }
  return result;
}

Handle OpenRaw(const std::wstring &path, DWORD access, DWORD creation,
    DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
{
  return Handle(CreateFileW(path.c_str(), access, share, nullptr, creation,
      FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
}

Opened Inspect(Handle handle, std::wstring_view root)
{
  if ( !handle ) throw std::runtime_error("open failed");
  Opened result;
  result.handle = std::move(handle);
  if ( !GetFileInformationByHandle(result.handle.get(), &result.info)
      || (result.info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 )
    throw std::runtime_error("unsafe object");
  result.final_path = FinalPath(result.handle.get());
  if ( !Within(root, result.final_path) ) throw std::runtime_error("outside root");
  return result;
}

void ValidateOpened(Opened &opened, std::wstring_view root)
{
  if ( !opened.handle || !GetFileInformationByHandle(opened.handle.get(), &opened.info)
      || (opened.info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 )
    throw std::runtime_error("unsafe object");
  opened.final_path = FinalPath(opened.handle.get());
  if ( !Within(root, opened.final_path) ) throw std::runtime_error("outside root");
}

Root CurrentRoot(const AgentFileService::IdbPathProvider &provider)
{
  const std::string idb_utf8 = provider ? provider() : std::string();
  if ( idb_utf8.empty() || !ValidUtf8(idb_utf8) ) throw std::runtime_error("no idb");
  std::wstring idb = Wide(idb_utf8);
  std::array<wchar_t, 32768> full{};
  wchar_t *leaf = nullptr;
  const DWORD count = GetFullPathNameW(idb.c_str(), static_cast<DWORD>(full.size()), full.data(), &leaf);
  if ( count == 0 || count >= full.size() || leaf == nullptr || leaf == full.data() )
    throw std::runtime_error("invalid idb path");
  const std::wstring idb_name(leaf);
  *leaf = L'\0';
  std::wstring root_path(full.data());
  while ( root_path.size() > 3 && (root_path.back() == L'\\' || root_path.back() == L'/') ) root_path.pop_back();
  if ( SensitiveRoot(root_path) ) throw std::runtime_error("sensitive idb root");
  Handle handle = OpenRaw(root_path, FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY, OPEN_EXISTING);
  if ( !handle ) throw std::runtime_error("idb root unavailable");
  BY_HANDLE_FILE_INFORMATION info{};
  if ( !GetFileInformationByHandle(handle.get(), &info)
      || (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != FILE_ATTRIBUTE_DIRECTORY )
    throw std::runtime_error("unsafe idb root");
  std::wstring canonical = FinalPath(handle.get());
  if ( SensitiveRoot(canonical) ) throw std::runtime_error("sensitive idb root");
  return {std::move(handle), std::move(canonical), idb_name};
}

Opened OpenComponents(const Root &root, const std::vector<std::wstring> &components,
    DWORD final_access,
    DWORD final_share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
{
  if ( components.empty() )
  {
    HANDLE duplicate = INVALID_HANDLE_VALUE;
    if ( !DuplicateHandle(GetCurrentProcess(), root.handle.get(), GetCurrentProcess(),
            &duplicate, final_access, FALSE, 0) )
      throw std::runtime_error("root unavailable");
    return Inspect(Handle(duplicate), root.path);
  }
  std::wstring current = root.path;
  for ( std::size_t index = 0; index < components.size(); ++index )
  {
    current += L"\\" + components[index];
    const bool final = index + 1 == components.size();
    Opened opened = Inspect(OpenRaw(current,
        final ? final_access : FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY,
        OPEN_EXISTING, final ? final_share
            : FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE), root.path);
    if ( !final && (opened.info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 )
      throw std::runtime_error("parent is not directory");
    if ( final ) return opened;
  }
  throw std::runtime_error("open failed");
}

std::uint64_t FileIndex(const BY_HANDLE_FILE_INFORMATION &info)
{
  return (static_cast<std::uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
}

std::uint64_t FileSize(const BY_HANDLE_FILE_INFORMATION &info)
{
  return (static_cast<std::uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
}

std::uint64_t ModifiedMillis(const FILETIME &time)
{
  ULARGE_INTEGER value{};
  value.HighPart = time.dwHighDateTime;
  value.LowPart = time.dwLowDateTime;
  constexpr std::uint64_t epoch = 116444736000000000ULL;
  return value.QuadPart < epoch ? 0 : (value.QuadPart - epoch) / 10000;
}

void RequireOrdinaryFile(const Opened &opened, bool single_link)
{
  if ( (opened.info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 )
    throw std::runtime_error("not file");
  if ( single_link && opened.info.nNumberOfLinks != 1 )
    throw std::runtime_error("multiple hard links");
}

template <typename Consumer>
void StreamHandle(HANDLE handle, std::uint64_t size, Consumer consumer)
{
  if ( size > MaxAgentFileSize ) throw std::runtime_error("file too large");
  LARGE_INTEGER zero{};
  if ( !SetFilePointerEx(handle, zero, nullptr, FILE_BEGIN) ) throw std::runtime_error("seek failed");
  std::array<char, 64 * 1024> buffer{};
  std::uint64_t remaining = size;
  while ( remaining != 0 )
  {
    DWORD read = 0;
    const DWORD amount = static_cast<DWORD>((std::min<std::uint64_t>)(buffer.size(), remaining));
    if ( !ReadFile(handle, buffer.data(), amount, &read, nullptr) || read == 0 || read > remaining )
      throw std::runtime_error("read failed");
    consumer(std::string_view(buffer.data(), read));
    remaining -= read;
  }
  LARGE_INTEGER current{};
  if ( !GetFileSizeEx(handle, &current) || current.QuadPart < 0
      || static_cast<std::uint64_t>(current.QuadPart) != size )
    throw std::runtime_error("file changed during read");
}

std::string HashTextHandle(HANDLE handle, std::uint64_t size)
{
  Utf8StreamValidator validator;
  AgentEffectSha256State hash;
  StreamHandle(handle, size, [&](std::string_view block)
  {
    validator.Feed(block);
    hash.Update(block);
  });
  validator.Finish();
  return hash.Final();
}

std::string ReadSmallTextHandle(HANDLE handle, std::uint64_t size, std::size_t maximum)
{
  if ( size > maximum ) throw std::runtime_error("file too large");
  Utf8StreamValidator validator;
  std::string result;
  result.reserve(static_cast<std::size_t>(size));
  StreamHandle(handle, size, [&](std::string_view block)
  {
    validator.Feed(block);
    result.append(block);
  });
  validator.Finish();
  return result;
}

std::string ReadTextPage(
    HANDLE handle,
    std::uint64_t size,
    std::uint64_t offset,
    std::uint32_t maximum)
{
  Utf8StreamValidator validator;
  std::string page;
  page.reserve(maximum);
  std::uint64_t position = 0;
  std::size_t complete_bytes = 0;
  const std::uint64_t page_limit = offset + maximum;
  StreamHandle(handle, size, [&](std::string_view block)
  {
    for ( unsigned char byte : block )
    {
      if ( position == offset && !validator.AtBoundary() )
        throw std::runtime_error("offset splits utf8");
      if ( position >= offset && position <= page_limit && validator.AtBoundary() )
        complete_bytes = static_cast<std::size_t>(position - offset);
      if ( position >= offset && position < page_limit )
        page.push_back(static_cast<char>(byte));
      validator.Feed(std::string_view(reinterpret_cast<const char *>(&byte), 1));
      ++position;
    }
  });
  validator.Finish();
  if ( position == offset && !validator.AtBoundary() ) throw std::runtime_error("offset splits utf8");
  if ( position >= offset && position <= page_limit && validator.AtBoundary() )
    complete_bytes = static_cast<std::size_t>(position - offset);
  if ( complete_bytes == 0 && offset < size ) throw std::runtime_error("page too small");
  page.resize(complete_bytes);
  return page;
}

bool DirectoryEmpty(HANDLE handle)
{
  std::array<unsigned char, 4096> buffer{};
  if ( !GetFileInformationByHandleEx(handle, FileIdBothDirectoryRestartInfo,
          buffer.data(), static_cast<DWORD>(buffer.size())) )
    return GetLastError() == ERROR_NO_MORE_FILES;
  auto *item = reinterpret_cast<FILE_ID_BOTH_DIR_INFO *>(buffer.data());
  for ( ;; )
  {
    const std::wstring_view name(item->FileName, item->FileNameLength / sizeof(wchar_t));
    if ( name != L"." && name != L".." ) return false;
    if ( item->NextEntryOffset == 0 ) break;
    item = reinterpret_cast<FILE_ID_BOTH_DIR_INFO *>(
        reinterpret_cast<unsigned char *>(item) + item->NextEntryOffset);
  }
  return true;
}

AgentFileState State(Opened &opened, bool hash_file)
{
  AgentFileState state;
  state.exists = true;
  const bool directory = (opened.info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
  state.type = directory ? "directory" : "file";
  state.size = directory ? 0 : FileSize(opened.info);
  state.volume = opened.info.dwVolumeSerialNumber;
  state.file_index = FileIndex(opened.info);
  if ( directory )
  {
    if ( !DirectoryEmpty(opened.handle.get()) ) throw std::runtime_error("directory not empty");
    state.sha256 = AgentEffectSha256("empty-directory-v1");
  }
  else if ( hash_file )
  {
    state.sha256 = HashTextHandle(opened.handle.get(), state.size);
  }
  return state;
}

bool Same(const AgentFileState &left, const AgentFileState &right)
{
  return left.exists == right.exists && left.type == right.type && left.size == right.size
      && left.sha256 == right.sha256 && left.volume == right.volume
      && left.file_index == right.file_index;
}

bool IsIdb(const Root &root, const std::vector<std::wstring> &components)
{
  return components.size() == 1 && Lower(components[0]) == Lower(root.idb_name);
}

bool DatabaseComponent(std::wstring_view value)
{
  const std::wstring lower = Lower(std::wstring(value));
  const std::size_t dot = lower.rfind(L'.');
  if ( dot == std::wstring::npos ) return false;
  const std::wstring extension = lower.substr(dot);
  static const std::wstring blocked[]{L".idb",L".i64",L".id0",L".id1",L".id2",
      L".id3",L".id4",L".id5",L".id6",L".id7",L".id8",L".nam",L".til"};
  return std::find(std::begin(blocked), std::end(blocked), extension) != std::end(blocked);
}

bool ForbiddenObject(const Root &root, const std::vector<std::wstring> &components)
{
  if ( components.empty() ) return false;
  if ( IsIdb(root, components) || DatabaseComponent(components.back())
      || SensitiveFile(components.back()) || DosDevice(components.back()) ) return true;
  return std::any_of(components.begin(), components.end(), [](const std::wstring &component) {
    return SensitiveComponent(component);
  });
}

Json Metadata(const std::string &path, const std::string &name,
    const BY_HANDLE_FILE_INFORMATION &info)
{
  const bool reparse = (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
  const bool directory = (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
  return {{"path",path},{"name",name},{"type",reparse ? "reparse" : directory ? "directory" : "file"},
      {"size",directory ? 0 : FileSize(info)},
      {"modifiedTimeMs",ModifiedMillis(info.ftLastWriteTime)},
      {"readOnly",(info.dwFileAttributes & FILE_ATTRIBUTE_READONLY) != 0}};
}

bool DeleteHandle(HANDLE handle)
{
  FILE_DISPOSITION_INFO disposition{TRUE};
  return SetFileInformationByHandle(handle, FileDispositionInfo,
      &disposition, sizeof(disposition)) != FALSE;
}

bool ParentIdentityMatches(
    const Root &root,
    const std::vector<std::wstring> &components,
    const std::wstring &target_path,
    std::uint64_t volume,
    std::uint64_t file_index)
{
  try
  {
    Opened parent = OpenComponents(root, components,
        FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE);
    const std::size_t separator = target_path.find_last_of(L"\\/");
    if ( separator == std::wstring::npos
        || Lower(target_path.substr(0, separator)) != Lower(parent.final_path) ) return false;
    return (parent.info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0
        && parent.info.dwVolumeSerialNumber == volume
        && FileIndex(parent.info) == file_index;
  }
  catch ( ... ) { return false; }
}

AgentFileMutationOutcome Rejected() { return {AgentFileMutationStatus::Rejected, Json::object()}; }
AgentFileMutationOutcome Uncertain() { return {AgentFileMutationStatus::StateUncertain, Json::object()}; }

struct TreeCounters
{
  std::uint64_t entries = 0;
  std::uint64_t bytes = 0;
};

bool ChildNameLess(const std::wstring &left, const std::wstring &right)
{
  const int insensitive = _wcsicmp(left.c_str(), right.c_str());
  return insensitive != 0 ? insensitive < 0 : left < right;
}

bool UnsafeEntryName(std::wstring_view name)
{
  return SensitiveComponent(name) || SensitiveFile(name) || DosDevice(name)
      || DatabaseComponent(name);
}

std::wstring ChildPath(const std::wstring &directory_path, const std::wstring &name)
{
  return directory_path + L"\\" + name;
}

void ReadChildNames(HANDLE handle, std::vector<std::wstring> &names)
{
  names.clear();
  bool first = true;
  std::vector<unsigned char> buffer(64 * 1024);
  for ( ;; )
  {
    const FILE_INFO_BY_HANDLE_CLASS kind = first ? FileIdBothDirectoryRestartInfo : FileIdBothDirectoryInfo;
    first = false;
    if ( !GetFileInformationByHandleEx(handle, kind, buffer.data(), static_cast<DWORD>(buffer.size())) )
    {
      if ( GetLastError() == ERROR_NO_MORE_FILES ) break;
      throw std::runtime_error("directory query failed");
    }
    auto *item = reinterpret_cast<FILE_ID_BOTH_DIR_INFO *>(buffer.data());
    for ( ;; )
    {
      const std::wstring_view name(item->FileName, item->FileNameLength / sizeof(wchar_t));
      if ( name != L"." && name != L".." ) names.emplace_back(name);
      if ( item->NextEntryOffset == 0 ) break;
      item = reinterpret_cast<FILE_ID_BOTH_DIR_INFO *>(
          reinterpret_cast<unsigned char *>(item) + item->NextEntryOffset);
    }
  }
  std::sort(names.begin(), names.end(), ChildNameLess);
}

Opened OpenChild(
    const Root &root,
    const std::wstring &directory_path,
    const std::wstring &name,
    DWORD access,
    DWORD share)
{
  Opened child;
  child.handle = OpenRaw(ChildPath(directory_path, name), access, OPEN_EXISTING, share);
  ValidateOpened(child, root.path);
  return child;
}

std::string RawHashHandle(HANDLE handle, std::uint64_t size)
{
  AgentEffectSha256State hash;
  StreamHandle(handle, size, [&](std::string_view block) { hash.Update(block); });
  return hash.Final();
}

void FeedField(AgentEffectSha256State &hash, std::string_view value)
{
  const std::string size = std::to_string(value.size());
  hash.Update(size);
  hash.Update(std::string_view(":", 1));
  hash.Update(value);
}

void FeedEntry(
    AgentEffectSha256State &hash,
    char kind,
    std::string_view name,
    const BY_HANDLE_FILE_INFORMATION &info)
{
  hash.Update(std::string_view(&kind, 1));
  FeedField(hash, name);
  FeedField(hash, std::to_string(info.dwVolumeSerialNumber));
  FeedField(hash, std::to_string(FileIndex(info)));
}

void SnapshotTree(
    const Root &root,
    const std::wstring &directory_path,
    Opened &directory,
    AgentEffectSha256State &hash,
    TreeCounters &counters,
    std::size_t depth)
{
  if ( depth > MaxTreeDepth ) throw std::runtime_error("directory tree too deep");
  std::vector<std::wstring> names;
  ReadChildNames(directory.handle.get(), names);
  if ( counters.entries + names.size() > MaxTreeEntries )
    throw std::runtime_error("directory tree too large");
  for ( const std::wstring &name : names )
  {
    if ( UnsafeEntryName(name) ) throw std::runtime_error("unsafe directory entry");
    const std::string encoded_name = Utf8(name);
    Opened child = OpenChild(root, directory_path, name,
        GENERIC_READ | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    ++counters.entries;
    const bool child_directory = (child.info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    if ( child_directory )
    {
      FeedEntry(hash, 'D', encoded_name, child.info);
      SnapshotTree(root, child.final_path, child, hash, counters, depth + 1);
      continue;
    }
    if ( child.info.nNumberOfLinks != 1 ) throw std::runtime_error("shared file in tree");
    const std::uint64_t size = FileSize(child.info);
    if ( size > MaxAgentFileSize ) throw std::runtime_error("file too large");
    counters.bytes += size;
    if ( counters.bytes > MaxTreeBytes ) throw std::runtime_error("directory tree too large");
    FeedEntry(hash, 'F', encoded_name, child.info);
    FeedField(hash, std::to_string(size));
    FeedField(hash, RawHashHandle(child.handle.get(), size));
    hash.Update(std::string_view("E", 1));
  }
  hash.Update(std::string_view("E", 1));
}

AgentFileState DirectoryState(
    const Opened &directory,
    const TreeCounters &counters,
    AgentEffectSha256State &hash)
{
  AgentFileState state;
  state.exists = true;
  state.type = "directory";
  state.size = counters.bytes;
  state.sha256 = hash.Final();
  state.volume = directory.info.dwVolumeSerialNumber;
  state.file_index = FileIndex(directory.info);
  return state;
}

AgentFileState DirectorySnapshotState(Opened &directory, const Root &root)
{
  AgentEffectSha256State hash;
  TreeCounters counters;
  SnapshotTree(root, directory.final_path, directory, hash, counters, 1);
  return DirectoryState(directory, counters, hash);
}

struct LockedTree
{
  Opened opened;
  bool directory = false;
  std::vector<LockedTree> children;
};

LockedTree LockTree(
    const Root &root,
    Opened directory,
    AgentEffectSha256State &hash,
    TreeCounters &counters,
    std::size_t depth)
{
  if ( depth > MaxTreeDepth ) throw std::runtime_error("directory tree too deep");
  LockedTree node;
  node.opened = std::move(directory);
  node.directory = true;
  std::vector<std::wstring> names;
  ReadChildNames(node.opened.handle.get(), names);
  if ( counters.entries + names.size() > MaxTreeEntries )
    throw std::runtime_error("directory tree too large");
  node.children.reserve(names.size());
  for ( const std::wstring &name : names )
  {
    if ( UnsafeEntryName(name) ) throw std::runtime_error("unsafe directory entry");
    const std::string encoded_name = Utf8(name);
    Opened child = OpenChild(root, node.opened.final_path, name,
        DELETE | GENERIC_READ | FILE_READ_ATTRIBUTES, 0);
    ++counters.entries;
    const bool child_directory = (child.info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    if ( child_directory )
    {
      FeedEntry(hash, 'D', encoded_name, child.info);
      node.children.push_back(LockTree(
          root, std::move(child), hash, counters, depth + 1));
    }
    else
    {
      if ( child.info.nNumberOfLinks != 1 ) throw std::runtime_error("shared file in tree");
      const std::uint64_t size = FileSize(child.info);
      if ( size > MaxAgentFileSize ) throw std::runtime_error("file too large");
      counters.bytes += size;
      if ( counters.bytes > MaxTreeBytes ) throw std::runtime_error("directory tree too large");
      FeedEntry(hash, 'F', encoded_name, child.info);
      FeedField(hash, std::to_string(size));
      FeedField(hash, RawHashHandle(child.handle.get(), size));
      hash.Update(std::string_view("E", 1));
      LockedTree file;
      file.opened = std::move(child);
      node.children.push_back(std::move(file));
    }
  }
  hash.Update(std::string_view("E", 1));
  return node;
}

void DeleteLockedTree(LockedTree &node)
{
  for ( LockedTree &child : node.children )
  {
    if ( child.directory ) DeleteLockedTree(child);
    else
    {
      if ( !DeleteHandle(child.opened.handle.get()) )
        throw std::runtime_error("file deletion failed");
      child.opened.handle = Handle();
    }
  }
  if ( !DeleteHandle(node.opened.handle.get()) )
    throw std::runtime_error("directory deletion failed");
  node.opened.handle = Handle();
}

} // namespace

AgentFileService::AgentFileService(IdbPathProvider provider)
    : idb_path_provider_(std::move(provider))
{
}

Json AgentFileService::List(std::string_view path, std::uint32_t limit) const
{
  if ( limit < 1 || limit > 100 ) throw std::runtime_error("invalid limit");
  Root root = CurrentRoot(idb_path_provider_);
  const auto components = Components(path, true);
  if ( ForbiddenObject(root, components) ) throw std::runtime_error("directory denied");
  Opened directory = OpenComponents(root, components, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES);
  if ( (directory.info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ) throw std::runtime_error("not directory");
  struct Entry { std::wstring wide; Json value; };
  std::vector<Entry> entries;
  std::array<unsigned char, 64 * 1024> buffer{};
  bool first = true;
  std::size_t seen_entries = 0;
  for ( ;; )
  {
    const FILE_INFO_BY_HANDLE_CLASS kind = first ? FileIdBothDirectoryRestartInfo : FileIdBothDirectoryInfo;
    first = false;
    if ( !GetFileInformationByHandleEx(directory.handle.get(), kind, buffer.data(), static_cast<DWORD>(buffer.size())) )
    {
      if ( GetLastError() == ERROR_NO_MORE_FILES ) break;
      throw std::runtime_error("directory query failed");
    }
    auto *item = reinterpret_cast<FILE_ID_BOTH_DIR_INFO *>(buffer.data());
    for ( ;; )
    {
      std::wstring name(item->FileName, item->FileNameLength / sizeof(wchar_t));
      if ( name != L"." && name != L".." )
      {
        if ( seen_entries++ >= MaxDirectoryEntries ) throw std::runtime_error("directory too large");
        std::vector<std::wstring> child = components;
        child.push_back(name);
        if ( ForbiddenObject(root, child) )
        {
          if ( item->NextEntryOffset == 0 ) break;
          item = reinterpret_cast<FILE_ID_BOTH_DIR_INFO *>(
              reinterpret_cast<unsigned char *>(item) + item->NextEntryOffset);
          continue;
        }
        const std::string utf8 = Utf8(name);
        std::string relative = Relative(components);
        if ( !relative.empty() ) relative.push_back('/');
        relative += utf8;
        const bool reparse = (item->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
        const bool is_directory = (item->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        entries.push_back({name, {{"path",relative},{"name",utf8},
            {"type",reparse ? "reparse" : is_directory ? "directory" : "file"},
            {"size",is_directory ? 0 : static_cast<std::uint64_t>(item->EndOfFile.QuadPart)}}});
      }
      if ( item->NextEntryOffset == 0 ) break;
      item = reinterpret_cast<FILE_ID_BOTH_DIR_INFO *>(
          reinterpret_cast<unsigned char *>(item) + item->NextEntryOffset);
    }
  }
  std::sort(entries.begin(), entries.end(), [](const Entry &left, const Entry &right) {
    const int insensitive = _wcsicmp(left.wide.c_str(), right.wide.c_str());
    return insensitive != 0 ? insensitive < 0 : left.wide < right.wide;
  });
  Json items = Json::array();
  for ( std::size_t index = 0; index < entries.size() && index < limit; ++index )
    items.push_back(std::move(entries[index].value));
  return {{"items",std::move(items)},{"hasMore",entries.size() > limit}};
}

Json AgentFileService::Stat(std::string_view path) const
{
  Root root = CurrentRoot(idb_path_provider_);
  const auto components = Components(path, false);
  if ( ForbiddenObject(root, components) ) throw std::runtime_error("file denied");
  Opened opened = OpenComponents(root, components, FILE_READ_ATTRIBUTES);
  if ( (opened.info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0
      && opened.info.nNumberOfLinks != 1 ) throw std::runtime_error("multiple hard links");
  return Metadata(Relative(components), Utf8(components.back()), opened.info);
}

Json AgentFileService::Read(std::string_view path, std::uint64_t offset,
    std::uint32_t max_bytes) const
{
  if ( max_bytes == 0 || max_bytes > MaxAgentFileContentBytes ) throw std::runtime_error("invalid size");
  Root root = CurrentRoot(idb_path_provider_);
  const auto components = Components(path, false);
  if ( ForbiddenObject(root, components) ) throw std::runtime_error("file denied");
  Opened opened = OpenComponents(root, components,
      GENERIC_READ | FILE_READ_ATTRIBUTES, FILE_SHARE_READ);
  RequireOrdinaryFile(opened, true);
  const std::uint64_t size = FileSize(opened.info);
  if ( offset > size ) throw std::runtime_error("invalid offset");
  const std::string content = ReadTextPage(opened.handle.get(), size, offset, max_bytes);
  return {{"path",Relative(components)},{"content",content},{"bytesRead",content.size()},
      {"hasMore",offset + content.size() < size},
      {"nextOffset",offset + content.size() < size ? Json(offset + content.size()) : Json(nullptr)}};
}

std::optional<AgentFileMutationPlan> AgentFileService::PrepareMutation(
    std::string_view path, std::string_view mode, std::string_view content) const
{
  try
  {
    const bool writes = mode == "overwrite" || mode == "append" || mode == "create_file";
    const bool directory = mode == "create_directory" || mode == "delete_directory";
    if ( !writes && !directory && mode != "delete_file" ) return std::nullopt;
    if ( (writes && (content.size() > MaxAgentFileContentBytes || !ValidTextUtf8(content)))
        || (!writes && !content.empty()) ) return std::nullopt;
    Root root = CurrentRoot(idb_path_provider_);
    const auto components = Components(path, false);
    if ( ForbiddenObject(root, components) ) return std::nullopt;
    std::vector<std::wstring> parents(components.begin(), components.end() - 1);
    Opened parent = OpenComponents(root, parents,
        FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE);
    if ( (parent.info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ) return std::nullopt;
    AgentFileMutationPlan plan;
    plan.path = Relative(components);
    plan.mode = std::string(mode);
    plan.content = std::string(content);
    plan.parent_volume = parent.info.dwVolumeSerialNumber;
    plan.parent_file_index = FileIndex(parent.info);
    try
    {
      Opened target = OpenComponents(root, components,
          GENERIC_READ | FILE_READ_ATTRIBUTES, FILE_SHARE_READ);
      const bool is_directory = (target.info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
      if ( (directory != is_directory && mode != "create_directory")
          || mode == "create_file" || mode == "create_directory" ) return std::nullopt;
      if ( mode == "delete_directory" )
      {
        if ( !is_directory ) return std::nullopt;
        plan.expected = DirectorySnapshotState(target, root);
      }
      else
      {
        if ( !is_directory && target.info.nNumberOfLinks != 1 ) return std::nullopt;
        plan.expected = State(target, true);
      }
    }
    catch ( const std::exception & )
    {
      if ( mode == "delete_file" || mode == "delete_directory" ) return std::nullopt;
      plan.expected = AgentFileState{};
    }
    return plan;
  }
  catch ( ... ) { return std::nullopt; }
}

AgentFileMutationOutcome AgentFileService::ExecuteMutation(
    const AgentFileMutationPlan &plan) const noexcept
{
  bool side_effect_started = false;
  try
  {
    Root root = CurrentRoot(idb_path_provider_);
    const auto components = Components(plan.path, false);
    if ( ForbiddenObject(root, components) ) return Rejected();
    std::vector<std::wstring> parents(components.begin(), components.end() - 1);
    Opened parent = OpenComponents(root, parents,
        FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE);
    if ( parent.info.dwVolumeSerialNumber != plan.parent_volume
        || FileIndex(parent.info) != plan.parent_file_index ) return Rejected();
    const bool writes = plan.mode == "overwrite" || plan.mode == "append" || plan.mode == "create_file";
    const bool make_directory = plan.mode == "create_directory";
    if ( (writes && (plan.content.size() > MaxAgentFileContentBytes || !ValidTextUtf8(plan.content)))
        || (!writes && !plan.content.empty()) ) return Rejected();
    std::wstring target_path = parent.final_path + L"\\" + components.back();
    if ( make_directory )
    {
      if ( plan.expected.exists || !CreateDirectoryW(target_path.c_str(), nullptr) ) return Rejected();
      side_effect_started = true;
      Handle raw = OpenRaw(target_path, DELETE | FILE_READ_ATTRIBUTES, OPEN_EXISTING, 0);
      Opened created;
      created.handle = std::move(raw);
      try
      {
        ValidateOpened(created, root.path);
        if ( !ParentIdentityMatches(root, parents, created.final_path,
                plan.parent_volume, plan.parent_file_index) )
        {
          if ( !DeleteHandle(created.handle.get()) ) return Uncertain();
          side_effect_started = false;
          return Rejected();
        }
        if ( (created.info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 )
        {
          if ( !DeleteHandle(created.handle.get()) ) return Uncertain();
          side_effect_started = false;
          return Rejected();
        }
        return {AgentFileMutationStatus::Success, {{"path",plan.path},{"mode",plan.mode},{"type","directory"}}};
      }
      catch ( ... )
      {
        if ( !created.handle || !DeleteHandle(created.handle.get()) ) return Uncertain();
        side_effect_started = false;
        return Rejected();
      }
    }
    if ( !plan.expected.exists )
    {
      if ( !writes ) return Rejected();
      Handle raw = OpenRaw(target_path, GENERIC_READ | GENERIC_WRITE | DELETE, CREATE_NEW, 0);
      if ( !raw ) return Rejected();
      side_effect_started = true;
      Opened created;
      created.handle = std::move(raw);
      try
      {
        ValidateOpened(created, root.path);
        RequireOrdinaryFile(created, true);
        if ( !ParentIdentityMatches(root, parents, created.final_path,
                plan.parent_volume, plan.parent_file_index) )
        {
          if ( !DeleteHandle(created.handle.get()) ) return Uncertain();
          side_effect_started = false;
          return Rejected();
        }
        DWORD written = 0;
        // A failed new-file write is downgraded to Rejected only after the
        // same validated handle successfully marks the new object for deletion.
        if ( !plan.content.empty() && (!WriteFile(created.handle.get(), plan.content.data(),
                static_cast<DWORD>(plan.content.size()), &written, nullptr) || written != plan.content.size()) )
        {
          if ( !DeleteHandle(created.handle.get()) ) return Uncertain();
          side_effect_started = false;
          return Rejected();
        }
        return {AgentFileMutationStatus::Success, {{"path",plan.path},{"mode",plan.mode},
            {"type","file"},{"bytesWritten",plan.content.size()}}};
      }
      catch ( ... )
      {
        if ( !created.handle || !DeleteHandle(created.handle.get()) ) return Uncertain();
        side_effect_started = false;
        return Rejected();
      }
    }
    const bool deleting = plan.mode == "delete_file" || plan.mode == "delete_directory";
    const DWORD access = deleting ? DELETE | GENERIC_READ | FILE_READ_ATTRIBUTES
                                  : GENERIC_READ | GENERIC_WRITE | FILE_READ_ATTRIBUTES;
    Opened target = OpenComponents(root, components, access, 0);
    const bool is_directory = (target.info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    if ( !is_directory && target.info.nNumberOfLinks != 1 ) return Rejected();
    if ( deleting )
    {
      if ( (plan.mode == "delete_file") == is_directory ) return Rejected();
      if ( plan.mode == "delete_directory" )
      {
        AgentEffectSha256State hash;
        TreeCounters counters;
        LockedTree locked = LockTree(root, std::move(target), hash, counters, 1);
        AgentFileState actual = DirectoryState(locked.opened, counters, hash);
        if ( !Same(actual, plan.expected) ) return Rejected();
        side_effect_started = true;
        try
        {
          DeleteLockedTree(locked);
        }
        catch ( ... ) { return Uncertain(); }
      }
      else
      {
        AgentFileState actual = State(target, true);
        if ( !Same(actual, plan.expected) ) return Rejected();
        side_effect_started = true;
        if ( !DeleteHandle(target.handle.get()) ) return Uncertain();
      }
      return {AgentFileMutationStatus::Success, {{"path",plan.path},{"mode",plan.mode},{"deleted",true}}};
    }
    if ( is_directory || (plan.mode != "overwrite" && plan.mode != "append") ) return Rejected();
    AgentFileState actual = State(target, true);
    if ( !Same(actual, plan.expected) ) return Rejected();
    // Existing content is changed only through this validated, non-shared
    // handle. From the first WriteFile/SetEndOfFile onward every failure is
    // StateUncertain because a partial write or truncation may have occurred.
    LARGE_INTEGER position{};
    if ( plan.mode == "append" ) position.QuadPart = static_cast<LONGLONG>(actual.size);
    if ( !SetFilePointerEx(target.handle.get(), position, nullptr, FILE_BEGIN) ) return Rejected();
    DWORD written = 0;
    if ( !plan.content.empty() )
    {
      side_effect_started = true;
      if ( !WriteFile(target.handle.get(), plan.content.data(),
              static_cast<DWORD>(plan.content.size()), &written, nullptr)
          || written != plan.content.size() ) return Uncertain();
    }
    if ( plan.mode == "overwrite" )
    {
      side_effect_started = true;
      if ( !SetEndOfFile(target.handle.get()) ) return Uncertain();
    }
    return {AgentFileMutationStatus::Success, {{"path",plan.path},{"mode",plan.mode},
        {"type","file"},{"bytesWritten",plan.content.size()}}};
  }
  catch ( ... ) { return side_effect_started ? Uncertain() : Rejected(); }
}

std::optional<AgentFileScriptSnapshot> AgentFileService::PrepareScript(
    std::string_view path, std::string_view language) const
{
  try
  {
    if ( language != "python" && language != "idc" ) return std::nullopt;
    Root root = CurrentRoot(idb_path_provider_);
    const auto components = Components(path, false);
    if ( ForbiddenObject(root, components) ) return std::nullopt;
    Opened opened = OpenComponents(root, components,
        GENERIC_READ | FILE_READ_ATTRIBUTES, FILE_SHARE_READ);
    RequireOrdinaryFile(opened, true);
    const std::uint64_t size = FileSize(opened.info);
    if ( size == 0 || size > MaxAgentScriptBytes ) return std::nullopt;
    std::string source = ReadSmallTextHandle(opened.handle.get(), size, MaxAgentScriptBytes);
    return AgentFileScriptSnapshot{Relative(components), std::string(language),
        source, AgentEffectSha256(source)};
  }
  catch ( ... ) { return std::nullopt; }
}

} // namespace ida_agent::ai
