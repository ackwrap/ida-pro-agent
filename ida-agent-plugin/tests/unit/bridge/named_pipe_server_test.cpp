#include "transport/named_pipe_server.hpp"

#include "envelope.hpp"
#include "error.hpp"
#include "framing.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <nlohmann/json.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <future>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace
{

class Handle
{
public:
  explicit Handle(HANDLE value = INVALID_HANDLE_VALUE) : value_(value) {}
  ~Handle()
  {
    if ( value_ != INVALID_HANDLE_VALUE )
      CloseHandle(value_);
  }
  Handle(const Handle &) = delete;
  Handle &operator=(const Handle &) = delete;
  Handle(Handle &&other) noexcept : value_(other.value_)
  {
    other.value_ = INVALID_HANDLE_VALUE;
  }
  HANDLE Get() const noexcept { return value_; }

private:
  HANDLE value_;
};

void Require(bool condition, const char *message)
{
  if ( !condition )
    throw std::runtime_error(message);
}

Handle Connect(const std::wstring &pipe_name)
{
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  while ( std::chrono::steady_clock::now() < deadline )
  {
    Handle pipe(CreateFileW(
        pipe_name.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));
    if ( pipe.Get() != INVALID_HANDLE_VALUE )
      return pipe;
    const DWORD error = GetLastError();
    if ( error != ERROR_PIPE_BUSY && error != ERROR_FILE_NOT_FOUND )
      throw std::runtime_error("failed to connect to named pipe: " + std::to_string(error));

    // Another concurrent client can take the available pipe after a wait.
    // Retry the open within the same bounded deadline instead of failing the test.
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - std::chrono::steady_clock::now()).count();
    if ( remaining <= 0 )
      break;
    if ( error == ERROR_PIPE_BUSY )
      WaitNamedPipeW(pipe_name.c_str(), static_cast<DWORD>(remaining));
    else
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  throw std::runtime_error("named pipe connection timed out");
}

void WriteAll(HANDLE pipe, const std::uint8_t *data, std::size_t size)
{
  std::size_t offset = 0;
  while ( offset < size )
  {
    DWORD written = 0;
    if ( !WriteFile(
             pipe,
             data + offset,
             static_cast<DWORD>(size - offset),
             &written,
             nullptr) || written == 0 )
    {
      throw std::runtime_error("pipe write failed");
    }
    offset += written;
  }
}

void ReadAll(HANDLE pipe, std::uint8_t *data, std::size_t size)
{
  std::size_t offset = 0;
  while ( offset < size )
  {
    DWORD received = 0;
    if ( !ReadFile(
             pipe,
             data + offset,
             static_cast<DWORD>(size - offset),
             &received,
             nullptr) || received == 0 )
    {
      throw std::runtime_error("pipe read failed");
    }
    offset += received;
  }
}

void SendFrame(HANDLE pipe, std::string_view payload)
{
  std::array<std::uint8_t, ida_agent::rpc::RequestHeaderBytes> header{
      'I', 'M', 'C', 'P', ida_agent::rpc::FramingVersion};
  const std::uint32_t size = static_cast<std::uint32_t>(payload.size());
  header[5] = static_cast<std::uint8_t>(size >> 24);
  header[6] = static_cast<std::uint8_t>(size >> 16);
  header[7] = static_cast<std::uint8_t>(size >> 8);
  header[8] = static_cast<std::uint8_t>(size);
  WriteAll(pipe, header.data(), header.size());
  WriteAll(
      pipe,
      reinterpret_cast<const std::uint8_t *>(payload.data()),
      payload.size());
}

std::string ReadFrame(HANDLE pipe)
{
  std::array<std::uint8_t, ida_agent::rpc::ResponseHeaderBytes> header{};
  ReadAll(pipe, header.data(), header.size());
  Require(
      header[0] == 'I' && header[1] == 'M' && header[2] == 'C' && header[3] == 'R'
        && header[4] == ida_agent::rpc::FramingVersion,
      "response frame prefix mismatch");
  const std::uint32_t size = (static_cast<std::uint32_t>(header[5]) << 24)
      | (static_cast<std::uint32_t>(header[6]) << 16)
      | (static_cast<std::uint32_t>(header[7]) << 8)
      | static_cast<std::uint32_t>(header[8]);
  Require(size > 0 && size <= ida_agent::rpc::MaxMessageBytes, "response size mismatch");
  std::string payload(size, '\0');
  ReadAll(pipe, reinterpret_cast<std::uint8_t *>(payload.data()), payload.size());
  return payload;
}

void WaitForResponseBytes(HANDLE pipe)
{
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  while ( std::chrono::steady_clock::now() < deadline )
  {
    DWORD available = 0;
    if ( !PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr) )
      throw std::runtime_error("peek unread response failed");
    if ( available > 0 )
      return;
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  throw std::runtime_error("unread response was not written");
}

ida_agent::rpc::Response Exchange(
    const std::wstring &pipe_name,
    std::string_view instance_id,
    std::string_view request)
{
  Handle pipe = Connect(pipe_name);
  SendFrame(
      pipe.Get(),
      R"({"method":"hello","params":{"protocol":1,"client":"ida-mcp"}})");
  const nlohmann::json hello = nlohmann::json::parse(ReadFrame(pipe.Get()));
  Require(hello.at("product") == "ida-agent-plugin", "hello product mismatch");
  Require(hello.at("protocol") == 1, "hello protocol mismatch");
  Require(
      hello.at("instance_id").get<std::string>() == instance_id,
      "hello instance mismatch");
  SendFrame(pipe.Get(), request);
  return ida_agent::rpc::ParseResponse(ReadFrame(pipe.Get()));
}

} // namespace

int main() try
{
  constexpr std::string_view InstanceId = "8dd304b5-8a3e-4d55-94ec-b931924e38fd";
  const std::wstring pipe_name = L"\\\\.\\pipe\\ida-agent-test-" + std::to_wstring(GetCurrentProcessId());
  ida_agent::bridge::Dispatcher::MethodHandlers handlers;
  handlers.emplace(
      "database.info",
      [](const ida_agent::rpc::Request &) -> ida_agent::bridge::Dispatcher::MethodResult
      {
        return nlohmann::json{{"database", "sample.i64"}};
      });
  handlers.emplace(
      "database.slow",
      [](const ida_agent::rpc::Request &) -> ida_agent::bridge::Dispatcher::MethodResult
      {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        return nlohmann::json{{"status", "late"}};
      });
  handlers.emplace(
      "database.large",
      [](const ida_agent::rpc::Request &) -> ida_agent::bridge::Dispatcher::MethodResult
      {
        return nlohmann::json{{"value", std::string(300 * 1024, 'x')}};
      });

  ida_agent::bridge::NamedPipeServer server;
  server.Start(pipe_name, std::string(InstanceId), GetCurrentProcessId(), std::move(handlers));
  Require(server.PipeName() == pipe_name, "server pipe name mismatch");

  const std::string ping = R"({"protocolVersion":"ida-rpc/1","requestId":"req-ping","sessionId":"8dd304b5-8a3e-4d55-94ec-b931924e38fd","method":"system.ping","params":{},"timeoutMs":5000})";
  const auto ping_response = Exchange(pipe_name, InstanceId, ping);
  Require(ping_response.result.has_value(), "ping result missing");

  const std::string database = R"({"protocolVersion":"ida-rpc/1","requestId":"req-db","sessionId":"8dd304b5-8a3e-4d55-94ec-b931924e38fd","method":"database.info","params":{},"timeoutMs":5000})";
  std::vector<std::future<ida_agent::rpc::Response>> concurrent;
  for ( int index = 0; index < 4; ++index )
  {
    concurrent.push_back(std::async(std::launch::async, [&]()
    {
      return Exchange(pipe_name, InstanceId, database);
    }));
  }
  for ( auto &request : concurrent )
    Require(request.get().result.has_value(), "concurrent request failed");

  const std::string slow = R"({"protocolVersion":"ida-rpc/1","requestId":"req-slow","sessionId":"8dd304b5-8a3e-4d55-94ec-b931924e38fd","method":"database.slow","params":{},"timeoutMs":20})";
  const auto slow_response = Exchange(pipe_name, InstanceId, slow);
  Require(
      slow_response.error && slow_response.error->code == ida_agent::rpc::ErrorCode::Timeout
        && slow_response.error->retryable,
      "slow request timeout mismatch");

  const std::string large = R"({"protocolVersion":"ida-rpc/1","requestId":"req-large","sessionId":"8dd304b5-8a3e-4d55-94ec-b931924e38fd","method":"database.large","params":{},"timeoutMs":5000})";
  const auto large_response = Exchange(pipe_name, InstanceId, large);
  Require(
      large_response.error && large_response.error->code == ida_agent::rpc::ErrorCode::OutputLimit,
      "large response output limit mismatch");

  std::vector<Handle> half_open;
  const std::uint8_t partial = 'I';
  for ( int index = 0; index < 3; ++index )
  {
    half_open.push_back(Connect(pipe_name));
    WriteAll(half_open.back().Get(), &partial, 1);
  }
  Require(Exchange(pipe_name, InstanceId, ping).result.has_value(), "half-open clients blocked server");

  Handle unread_response = Connect(pipe_name);
  SendFrame(
      unread_response.Get(),
      R"({"method":"hello","params":{"protocol":1,"client":"ida-mcp"}})");
  const nlohmann::json unread_hello = nlohmann::json::parse(ReadFrame(unread_response.Get()));
  Require(
      unread_hello.at("instance_id").get<std::string>() == InstanceId,
      "unread client hello mismatch");
  SendFrame(unread_response.Get(), ping);
  WaitForResponseBytes(unread_response.Get());

  const auto stop_started = std::chrono::steady_clock::now();
  server.Stop();
  Require(
      std::chrono::steady_clock::now() - stop_started < std::chrono::seconds(2),
      "server shutdown was blocked by pipe I/O");
  std::cout << "named pipe server tests passed\n";
  return 0;
}

catch ( const std::exception &error )
{
  std::cerr << error.what() << "\n";
  return 1;
}
