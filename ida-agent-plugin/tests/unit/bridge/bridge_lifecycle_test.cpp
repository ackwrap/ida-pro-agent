#include "bridge.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <thread>

namespace
{

void Require(bool condition, const char *message)
{
  if ( !condition )
    throw std::runtime_error(message);
}

} // namespace

int main()
{
  wchar_t temporary_root[MAX_PATH]{};
  Require(GetTempPathW(MAX_PATH, temporary_root) > 0, "temporary directory is unavailable");
  const std::filesystem::path root = std::filesystem::path(temporary_root)
      / (L"ida-agent-bridge-lifecycle-" + std::to_wstring(GetCurrentProcessId()));
  std::filesystem::create_directories(root);
  const std::filesystem::path invalid_directory = root / L"not-a-directory";
  std::ofstream(invalid_directory).put('x');
  _wputenv_s(L"IDA_AGENT_INSTANCE_DIR", invalid_directory.c_str());

  ida_agent::bridge::Bridge bridge;
  bridge.Start(ida_agent::bridge::DatabaseMetadata{
      "test.i64",
      "test.exe",
      "9.4",
      "metapc",
      "x86_64",
      64,
      false,
      false,
      false,
  });
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  while ( bridge.Running() && std::chrono::steady_clock::now() < deadline )
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  Require(!bridge.Running(), "registry publication failure did not stop the Bridge");

  const auto stop_started = std::chrono::steady_clock::now();
  bridge.Stop();
  Require(
      std::chrono::steady_clock::now() - stop_started < std::chrono::seconds(2),
      "Bridge stop blocked after registry publication failure");
  _wputenv_s(L"IDA_AGENT_INSTANCE_DIR", L"");
  std::error_code ignored;
  std::filesystem::remove_all(root, ignored);
  return 0;
}
