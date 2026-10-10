#include "instance/secure_file.hpp"

#include "crypto/secure_random.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <aclapi.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace ida_agent::bridge
{
namespace
{

class Handle
{
public:
  explicit Handle(HANDLE value = INVALID_HANDLE_VALUE) : value_(value) {}
  ~Handle()
  {
    if ( value_ != INVALID_HANDLE_VALUE && value_ != nullptr )
      CloseHandle(value_);
  }
  Handle(const Handle &) = delete;
  Handle &operator=(const Handle &) = delete;
  HANDLE Get() const { return value_; }

private:
  HANDLE value_;
};

std::vector<std::uint8_t> CurrentUserTokenInformation()
{
  HANDLE raw_token = nullptr;
  if ( !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token) )
    throw std::runtime_error("failed to query current process token");
  Handle token(raw_token);

  DWORD size = 0;
  GetTokenInformation(token.Get(), TokenUser, nullptr, 0, &size);
  if ( size == 0 )
    throw std::runtime_error("failed to size current user token");
  std::vector<std::uint8_t> information(size);
  if ( !GetTokenInformation(token.Get(), TokenUser, information.data(), size, &size) )
    throw std::runtime_error("failed to read current user token");
  return information;
}

void ApplyCurrentUserOnlyAcl(const std::filesystem::path &path, bool directory)
{
  std::vector<std::uint8_t> information = CurrentUserTokenInformation();
  const auto *token_user = reinterpret_cast<const TOKEN_USER *>(information.data());

  EXPLICIT_ACCESSW access{};
  access.grfAccessPermissions = GENERIC_ALL;
  access.grfAccessMode = SET_ACCESS;
  access.grfInheritance = directory ? SUB_CONTAINERS_AND_OBJECTS_INHERIT : NO_INHERITANCE;
  access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  access.Trustee.TrusteeType = TRUSTEE_IS_USER;
  access.Trustee.ptstrName = static_cast<LPWSTR>(token_user->User.Sid);

  PACL raw_acl = nullptr;
  if ( SetEntriesInAclW(1, &access, nullptr, &raw_acl) != ERROR_SUCCESS )
    throw std::runtime_error("failed to create current-user ACL");
  std::unique_ptr<ACL, decltype(&LocalFree)> acl(raw_acl, LocalFree);

  std::wstring mutable_path = path.wstring();
  const DWORD result = SetNamedSecurityInfoW(
      mutable_path.data(),
      SE_FILE_OBJECT,
      DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
      nullptr,
      nullptr,
      acl.get(),
      nullptr);
  if ( result != ERROR_SUCCESS )
    throw std::runtime_error("failed to apply current-user ACL");
}

void WriteAll(HANDLE file, std::string_view contents)
{
  std::size_t offset = 0;
  while ( offset < contents.size() )
  {
    const DWORD chunk = static_cast<DWORD>(
        (std::min)(contents.size() - offset, static_cast<std::size_t>(MAXDWORD)));
    DWORD written = 0;
    if ( !WriteFile(file, contents.data() + offset, chunk, &written, nullptr) || written == 0 )
      throw std::runtime_error("failed to write session descriptor");
    offset += written;
  }
}

} // namespace

void EnsureCurrentUserOnlyDirectory(const std::filesystem::path &directory)
{
  std::error_code error;
  std::filesystem::create_directories(directory, error);
  if ( error || !std::filesystem::is_directory(directory) )
    throw std::runtime_error("failed to create session directory");
  ApplyCurrentUserOnlyAcl(directory, true);
}

void ApplyCurrentUserOnlyFileAcl(const std::filesystem::path &path)
{
  ApplyCurrentUserOnlyAcl(path, false);
}

void AtomicWriteCurrentUserOnlyFile(
    const std::filesystem::path &target,
    std::string_view contents)
{
  EnsureCurrentUserOnlyDirectory(target.parent_path());
  const std::vector<std::uint8_t> random_suffix = SecureRandom(8);
  const std::filesystem::path temporary =
      target.parent_path() / (target.filename().wstring() + L".tmp-"
      + std::filesystem::path(HexEncode(random_suffix.data(), random_suffix.size())).wstring());

  bool moved = false;
  try
  {
    {
      Handle file(CreateFileW(
          temporary.c_str(),
          GENERIC_WRITE,
          0,
          nullptr,
          CREATE_NEW,
          FILE_ATTRIBUTE_TEMPORARY,
          nullptr));
      if ( file.Get() == INVALID_HANDLE_VALUE )
        throw std::runtime_error("failed to create temporary session descriptor");
      WriteAll(file.Get(), contents);
      if ( !FlushFileBuffers(file.Get()) )
        throw std::runtime_error("failed to flush session descriptor");
    }
    ApplyCurrentUserOnlyAcl(temporary, false);

    if ( !MoveFileExW(
             temporary.c_str(),
             target.c_str(),
             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) )
    {
      throw std::runtime_error("failed to publish session descriptor");
    }
    moved = true;
    ApplyCurrentUserOnlyAcl(target, false);
  }
  catch ( ... )
  {
    if ( !moved )
      DeleteFileW(temporary.c_str());
    else if ( !DeleteFileW(target.c_str()) )
      throw std::runtime_error("failed to roll back insecure session descriptor");
    throw;
  }
}

} // namespace ida_agent::bridge
