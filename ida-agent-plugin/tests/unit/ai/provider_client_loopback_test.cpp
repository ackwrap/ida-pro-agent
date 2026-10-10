#include "ai/provider_client.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <functional>
#include <iostream>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

namespace
{

using namespace std::chrono_literals;

void Require(bool condition, const char *message)
{
  if ( !condition )
    throw std::runtime_error(message);
}

class WinsockRuntime final
{
public:
  WinsockRuntime()
  {
    WSADATA data{};
    Require(WSAStartup(MAKEWORD(2, 2), &data) == 0, "WSAStartup failed");
  }
  ~WinsockRuntime() { WSACleanup(); }
};

void CloseSocket(std::atomic<SOCKET> &socket)
{
  const SOCKET value = socket.exchange(INVALID_SOCKET);
  if ( value != INVALID_SOCKET )
  {
    shutdown(value, SD_BOTH);
    closesocket(value);
  }
}

void SetSocketTimeouts(SOCKET socket, DWORD timeout_ms)
{
  Require(
      setsockopt(
          socket,
          SOL_SOCKET,
          SO_RCVTIMEO,
          reinterpret_cast<const char *>(&timeout_ms),
          sizeof(timeout_ms)) == 0,
      "loopback receive timeout setup failed");
  Require(
      setsockopt(
          socket,
          SOL_SOCKET,
          SO_SNDTIMEO,
          reinterpret_cast<const char *>(&timeout_ms),
          sizeof(timeout_ms)) == 0,
      "loopback send timeout setup failed");
}

void SendAll(SOCKET socket, std::string_view bytes)
{
  while ( !bytes.empty() )
  {
    const int sent = send(
        socket,
        bytes.data(),
        static_cast<int>((std::min)(bytes.size(), static_cast<std::size_t>(INT_MAX))),
        0);
    if ( sent <= 0 )
      throw std::runtime_error("loopback send failed");
    bytes.remove_prefix(static_cast<std::size_t>(sent));
  }
}

std::string ReadHttpHeaders(SOCKET socket)
{
  std::string headers;
  std::array<char, 1024> buffer{};
  while ( headers.find("\r\n\r\n") == std::string::npos )
  {
    const int received = recv(socket, buffer.data(), static_cast<int>(buffer.size()), 0);
    if ( received <= 0 )
      throw std::runtime_error("HTTP request header receive failed");
    headers.append(buffer.data(), received);
    if ( headers.size() > 64 * 1024 )
      throw std::runtime_error("HTTP request headers exceeded test limit");
  }
  return headers;
}

std::string LowerAscii(std::string value)
{
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character)
  {
    return character >= 'A' && character <= 'Z'
        ? static_cast<char>(character - 'A' + 'a')
        : static_cast<char>(character);
  });
  return value;
}

std::string FindHeader(const std::string &headers, std::string name)
{
  const std::string lowered = LowerAscii(headers);
  name = "\r\n" + LowerAscii(std::move(name)) + ":";
  const std::size_t start = lowered.find(name);
  if ( start == std::string::npos )
    return {};
  std::size_t value_start = start + name.size();
  while ( value_start < headers.size()
      && (headers[value_start] == ' ' || headers[value_start] == '\t') )
  {
    ++value_start;
  }
  const std::size_t end = headers.find("\r\n", value_start);
  return headers.substr(value_start, end - value_start);
}

class LoopbackServer final
{
public:
  using Handler = std::function<void(SOCKET)>;

  explicit LoopbackServer(Handler handler, int receive_buffer = 0)
  {
    const SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Require(listener != INVALID_SOCKET, "loopback listener creation failed");
    listener_.store(listener);
    if ( receive_buffer != 0 )
    {
      Require(
          setsockopt(
              listener,
              SOL_SOCKET,
              SO_RCVBUF,
              reinterpret_cast<const char *>(&receive_buffer),
              sizeof(receive_buffer)) == 0,
          "loopback receive buffer setup failed");
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if ( bind(listener, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0
        || listen(listener, 2) != 0 )
    {
      CloseSocket(listener_);
      throw std::runtime_error("loopback listener setup failed");
    }
    int address_size = sizeof(address);
    Require(
        getsockname(listener, reinterpret_cast<sockaddr *>(&address), &address_size) == 0,
        "loopback port query failed");
    port_ = ntohs(address.sin_port);

    worker_ = std::thread([this, handler = std::move(handler)]
    {
      try
      {
        const SOCKET listener_socket = listener_.load();
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(listener_socket, &readable);
        timeval timeout{5, 0};
        if ( select(0, &readable, nullptr, nullptr, &timeout) != 1 )
          throw std::runtime_error("loopback accept timed out");
        const SOCKET accepted = accept(listener_socket, nullptr, nullptr);
        if ( accepted == INVALID_SOCKET )
          throw std::runtime_error("loopback accept failed");
        CloseSocket(listener_);
        client_.store(accepted);
        SetSocketTimeouts(accepted, 5000);
        handler(accepted);
      }
      catch ( ... )
      {
        std::lock_guard<std::mutex> lock(error_mutex_);
        error_ = std::current_exception();
      }
      CloseSocket(client_);
      CloseSocket(listener_);
    });
  }

  ~LoopbackServer()
  {
    CloseSocket(client_);
    CloseSocket(listener_);
    if ( worker_.joinable() )
      worker_.join();
  }

  std::uint16_t port() const noexcept { return port_; }

  void Join()
  {
    if ( worker_.joinable() )
      worker_.join();
    std::exception_ptr error;
    {
      std::lock_guard<std::mutex> lock(error_mutex_);
      error = error_;
    }
    if ( error != nullptr )
      std::rethrow_exception(error);
  }

private:
  std::atomic<SOCKET> listener_{INVALID_SOCKET};
  std::atomic<SOCKET> client_{INVALID_SOCKET};
  std::uint16_t port_ = 0;
  std::thread worker_;
  std::mutex error_mutex_;
  std::exception_ptr error_;
};

class RedirectServer final
{
public:
  RedirectServer()
  {
    const SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Require(listener != INVALID_SOCKET, "redirect listener creation failed");
    listener_.store(listener);

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if ( bind(listener, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0
        || listen(listener, 2) != 0 )
    {
      CloseSocket(listener_);
      throw std::runtime_error("redirect listener setup failed");
    }
    int address_size = sizeof(address);
    Require(
        getsockname(listener, reinterpret_cast<sockaddr *>(&address), &address_size) == 0,
        "redirect port query failed");
    port_ = ntohs(address.sin_port);

    worker_ = std::thread([this]
    {
      try
      {
        const SOCKET listener_socket = listener_.load();
        const SOCKET first = AcceptWithin(listener_socket, 5s);
        Require(first != INVALID_SOCKET, "redirect accept timed out");
        ++request_count_;
        SetSocketTimeouts(first, 5000);
        const std::string request = ReadHttpHeaders(first);
        Require(
            request.rfind("GET /v1/models HTTP/1.1\r\n", 0) == 0,
            "redirect request path mismatch");
        SendAll(
            first,
            "HTTP/1.1 302 Found\r\n"
            "Location: /followed\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n\r\n");
        shutdown(first, SD_BOTH);
        closesocket(first);

        const SOCKET second = AcceptWithin(listener_socket, 750ms);
        if ( second != INVALID_SOCKET )
        {
          ++request_count_;
          SetSocketTimeouts(second, 1000);
          ReadHttpHeaders(second);
          closesocket(second);
        }
      }
      catch ( ... )
      {
        std::lock_guard<std::mutex> lock(error_mutex_);
        error_ = std::current_exception();
      }
      CloseSocket(listener_);
    });
  }

  ~RedirectServer()
  {
    CloseSocket(listener_);
    if ( worker_.joinable() )
      worker_.join();
  }

  std::uint16_t port() const noexcept { return port_; }
  int request_count() const noexcept { return request_count_.load(); }

  void Join()
  {
    if ( worker_.joinable() )
      worker_.join();
    std::exception_ptr error;
    {
      std::lock_guard<std::mutex> lock(error_mutex_);
      error = error_;
    }
    if ( error != nullptr )
      std::rethrow_exception(error);
  }

private:
  static SOCKET AcceptWithin(SOCKET listener, std::chrono::milliseconds wait)
  {
    fd_set readable;
    FD_ZERO(&readable);
    FD_SET(listener, &readable);
    timeval timeout{};
    timeout.tv_sec = static_cast<long>(wait.count() / 1000);
    timeout.tv_usec = static_cast<long>((wait.count() % 1000) * 1000);
    if ( select(0, &readable, nullptr, nullptr, &timeout) != 1 )
      return INVALID_SOCKET;
    return accept(listener, nullptr, nullptr);
  }

  std::atomic<SOCKET> listener_{INVALID_SOCKET};
  std::atomic<int> request_count_{0};
  std::uint16_t port_ = 0;
  std::thread worker_;
  std::mutex error_mutex_;
  std::exception_ptr error_;
};

ida_agent::ai::ProviderProfileDraft MakeLoopbackProfile(std::uint16_t port)
{
  ida_agent::ai::ProviderProfileDraft profile;
  profile.settings = ida_agent::ai::DraftForPreset(ida_agent::ai::ProviderPreset::OpenAI);
  profile.settings.base_url =
      "http://127.0.0.1:" + std::to_string(port) + "/v1";
  profile.settings.api_key = "provider-loopback-fake-key";
  profile.proxy.mode = ida_agent::ai::ProviderProxyMode::Direct;
  return profile;
}

ida_agent::ai::ProviderDiscoveryResult WaitForResult(
    ida_agent::ai::ProviderClient &client,
    ida_agent::ai::ProviderClient::RequestId request_id,
    const char *stage)
{
  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while ( std::chrono::steady_clock::now() < deadline )
  {
    if ( std::optional<ida_agent::ai::ProviderDiscoveryResult> result =
             client.TryTakeResult(request_id) )
    {
      return std::move(*result);
    }
    std::this_thread::sleep_for(2ms);
  }
  throw std::runtime_error(std::string(stage) + " timed out");
}

void WaitForFlag(const std::atomic<bool> &flag, const char *message)
{
  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while ( !flag.load() && std::chrono::steady_clock::now() < deadline )
    std::this_thread::sleep_for(1ms);
  Require(flag.load(), message);
}

void RequireForgottenProviderResult(
    ida_agent::ai::ProviderClient &client,
    ida_agent::ai::ProviderClient::RequestId request_id)
{
  const auto deadline = std::chrono::steady_clock::now() + 20ms;
  while ( std::chrono::steady_clock::now() < deadline )
  {
    Require(
        !client.TryTakeResult(request_id).has_value(),
        "forgotten provider request produced a result");
    std::this_thread::sleep_for(1ms);
  }
}

void RequireForgottenHttpResult(
    ida_agent::ai::HttpClient &client,
    ida_agent::ai::HttpClient::RequestId request_id)
{
  const auto deadline = std::chrono::steady_clock::now() + 20ms;
  while ( std::chrono::steady_clock::now() < deadline )
  {
    Require(
        !client.TryTakeResult(request_id).has_value(),
        "forgotten HTTP request produced a result");
    std::this_thread::sleep_for(1ms);
  }
}

void TestListModels()
{
  LoopbackServer server([](SOCKET socket)
  {
    const std::string request = ReadHttpHeaders(socket);
    Require(
        request.rfind("GET /v1/models HTTP/1.1\r\n", 0) == 0,
        "model request path mismatch");
    Require(
        FindHeader(request, "Authorization") ==
            "Bearer provider-loopback-fake-key",
        "model request authorization mismatch");
    Require(
        FindHeader(request, "User-Agent") == ida_agent::ai::DefaultBrowserUserAgent(),
        "model request default user agent mismatch");
    constexpr std::string_view body =
        R"({"data":[{"id":"z-model"},{"id":"a-model"},{"id":"z-model"}]})";
    SendAll(
        socket,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n"
        "Connection: close\r\n\r\n" + std::string(body));
  });

  ida_agent::ai::HttpClient http_client;
  ida_agent::ai::ProviderClient provider_client(http_client);
  const auto request_id = provider_client.SubmitListModels(
      MakeLoopbackProfile(server.port()));
  const auto result = WaitForResult(provider_client, request_id, "model request");
  Require(
      result.status == ida_agent::ai::ProviderDiscoveryStatus::Success,
      "model request did not succeed");
  Require(result.http_status == 200, "model request HTTP status mismatch");
  Require(result.models.size() == 2, "model response de-duplication mismatch");
  Require(
      result.models[0].id == "a-model" && result.models[1].id == "z-model",
      "model response sorting mismatch");
  provider_client.Shutdown();
  http_client.Shutdown();
  server.Join();
}

void TestRedirectDisabled()
{
  RedirectServer server;
  ida_agent::ai::HttpClient http_client;
  ida_agent::ai::ProviderClient provider_client(http_client);
  const auto request_id = provider_client.SubmitListModels(
      MakeLoopbackProfile(server.port()));
  const auto result = WaitForResult(provider_client, request_id, "redirect request");
  Require(
      result.status == ida_agent::ai::ProviderDiscoveryStatus::HttpError,
      "redirect was not returned as an HTTP error");
  Require(result.http_status == 302, "redirect HTTP status mismatch");
  provider_client.Shutdown();
  http_client.Shutdown();
  server.Join();
  Require(server.request_count() == 1, "redirect caused an additional request");
}

void TestActiveCancelAndForget()
{
  std::atomic<bool> request_received{false};
  LoopbackServer server([&](SOCKET socket)
  {
    ReadHttpHeaders(socket);
    request_received.store(true);
    char byte = 0;
    const int received = recv(socket, &byte, 1, 0);
    Require(received <= 0, "cancelled provider connection remained open");
  });

  ida_agent::ai::HttpClient http_client;
  ida_agent::ai::ProviderClient provider_client(http_client);
  const auto request_id = provider_client.SubmitListModels(
      MakeLoopbackProfile(server.port()));
  const auto request_deadline = std::chrono::steady_clock::now() + 5s;
  while ( !request_received.load() && std::chrono::steady_clock::now() < request_deadline )
    std::this_thread::sleep_for(2ms);
  Require(request_received.load(), "blocking provider request was not received");

  const auto shutdown_started = std::chrono::steady_clock::now();
  provider_client.CancelAndForget(request_id);
  const auto forgotten_deadline = std::chrono::steady_clock::now() + 250ms;
  while ( std::chrono::steady_clock::now() < forgotten_deadline )
  {
    Require(
        !provider_client.TryTakeResult(request_id).has_value(),
        "forgotten provider request produced a result");
    std::this_thread::sleep_for(2ms);
  }
  provider_client.Shutdown();
  http_client.Shutdown();
  Require(
      std::chrono::steady_clock::now() - shutdown_started < 3s,
      "provider cancellation and shutdown exceeded the time bound");
  Require(
      !provider_client.TryTakeResult(request_id).has_value(),
      "forgotten provider result appeared after shutdown");
  server.Join();
}

void TestResponseReadCancelStress()
{
  constexpr int iterations = 25;
  const auto stress_started = std::chrono::steady_clock::now();
  ida_agent::ai::HttpClient http_client;
  ida_agent::ai::ProviderClient provider_client(http_client);
  for ( int iteration = 0; iteration < iterations; ++iteration )
  {
    std::atomic<bool> partial_response_sent{false};
    LoopbackServer server([&](SOCKET socket)
    {
      ReadHttpHeaders(socket);
      constexpr std::size_t response_size = 64 * 1024;
      SendAll(
          socket,
          "HTTP/1.1 200 OK\r\n"
          "Content-Type: application/json\r\n"
          "Content-Length: " + std::to_string(response_size) + "\r\n"
          "Connection: close\r\n\r\n" + std::string(1024, 'x'));
      std::this_thread::sleep_for(20ms);
      partial_response_sent.store(true);
      char byte = 0;
      const int received = recv(socket, &byte, 1, 0);
      Require(received <= 0, "cancelled response-read connection remained open");
    });

    const auto request_id = provider_client.SubmitListModels(
        MakeLoopbackProfile(server.port()));
    WaitForFlag(partial_response_sent, "partial provider response was not sent");
    provider_client.CancelAndForget(request_id);
    RequireForgottenProviderResult(provider_client, request_id);
    server.Join();
  }
  provider_client.Shutdown();
  http_client.Shutdown();
  Require(
      std::chrono::steady_clock::now() - stress_started < 15s,
      "response-read cancellation stress exceeded the time bound");
}

void TestPostSendCancelStress()
{
  constexpr int iterations = 25;
  constexpr std::size_t request_body_size = 8 * 1024 * 1024;
  const auto stress_started = std::chrono::steady_clock::now();
  ida_agent::ai::HttpClient http_client;
  for ( int iteration = 0; iteration < iterations; ++iteration )
  {
    std::atomic<bool> request_headers_received{false};
    LoopbackServer server([&](SOCKET socket)
    {
      const std::string request = ReadHttpHeaders(socket);
      Require(
          request.rfind("POST /upload HTTP/1.1\r\n", 0) == 0,
          "POST cancellation request path mismatch");
      request_headers_received.store(true);
      std::this_thread::sleep_for(20ms);
      std::array<char, 4096> drain{};
      int received = 0;
      do
      {
        received = recv(socket, drain.data(), static_cast<int>(drain.size()), 0);
      } while ( received > 0 );
      Require(received <= 0, "cancelled POST connection remained open");
    }, 1024);

    ida_agent::ai::HttpRequest request;
    request.method = ida_agent::ai::HttpMethod::Post;
    request.url = "http://127.0.0.1:" + std::to_string(server.port()) + "/upload";
    request.user_agent = "ida-agent-provider-loopback-test";
    request.headers.push_back({"Content-Type", "application/octet-stream"});
    request.body.assign(request_body_size, 'p');
    request.proxy.mode = ida_agent::ai::HttpProxyMode::Direct;
    request.connect_timeout_ms = 5000;
    request.send_timeout_ms = 5000;
    request.receive_timeout_ms = 5000;
    const auto request_id = http_client.Submit(std::move(request));
    WaitForFlag(request_headers_received, "POST cancellation request was not received");
    http_client.CancelAndForget(request_id);
    RequireForgottenHttpResult(http_client, request_id);
    server.Join();
  }
  http_client.Shutdown();
  Require(
      std::chrono::steady_clock::now() - stress_started < 15s,
      "POST cancellation stress exceeded the time bound");
}

} // namespace

int main()
{
  try
  {
    WinsockRuntime winsock;
    const auto run = [](const char *name, const std::function<void()> &test)
    {
      try
      {
        test();
      }
      catch ( const std::exception &error )
      {
        throw std::runtime_error(std::string(name) + ": " + error.what());
      }
    };
    run("list models", TestListModels);
    run("redirect disabled", TestRedirectDisabled);
    run("active cancel and forget", TestActiveCancelAndForget);
    run("response read cancellation stress", TestResponseReadCancelStress);
    run("POST send cancellation stress", TestPostSendCancelStress);
    return 0;
  }
  catch ( const std::exception &error )
  {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
