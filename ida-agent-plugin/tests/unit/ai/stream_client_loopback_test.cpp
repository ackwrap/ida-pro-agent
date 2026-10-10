#include "ai/stream_client.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <functional>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

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

std::string ReadExact(SOCKET socket, std::size_t size)
{
  std::string result(size, '\0');
  std::size_t offset = 0;
  while ( offset < size )
  {
    const int received = recv(
        socket,
        result.data() + offset,
        static_cast<int>(size - offset),
        0);
    if ( received <= 0 )
      throw std::runtime_error("loopback receive failed");
    offset += static_cast<std::size_t>(received);
  }
  return result;
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

  explicit LoopbackServer(Handler handler)
  {
    const SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Require(listener != INVALID_SOCKET, "loopback listener creation failed");
    listener_.store(listener);

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if ( bind(listener, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0
        || listen(listener, 1) != 0 )
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
        const DWORD io_timeout_ms = 5000;
        setsockopt(
            accepted,
            SOL_SOCKET,
            SO_RCVTIMEO,
            reinterpret_cast<const char *>(&io_timeout_ms),
            sizeof(io_timeout_ms));
        setsockopt(
            accepted,
            SOL_SOCKET,
            SO_SNDTIMEO,
            reinterpret_cast<const char *>(&io_timeout_ms),
            sizeof(io_timeout_ms));
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

ida_agent::ai::StreamRequest MakeLoopbackRequest(
    std::uint16_t port,
    std::string_view path,
    bool websocket = false)
{
  ida_agent::ai::StreamRequest request;
  request.url = std::string(websocket ? "ws" : "http")
      + "://127.0.0.1:" + std::to_string(port) + std::string(path);
  request.user_agent = "ida-agent-loopback-test";
  request.proxy.mode = ida_agent::ai::HttpProxyMode::Direct;
  request.connect_timeout_ms = 2000;
  request.send_timeout_ms = 2000;
  request.idle_timeout_ms = 5000;
  request.overall_timeout_ms = 10000;
  return request;
}

ida_agent::ai::StreamEvent WaitNextEvent(
    ida_agent::ai::StreamClient &client,
    ida_agent::ai::StreamClient::StreamId id,
    const char *stage)
{
  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while ( std::chrono::steady_clock::now() < deadline )
  {
    if ( std::optional<ida_agent::ai::StreamEvent> event = client.TryTakeEvent(id) )
      return std::move(*event);
    std::this_thread::sleep_for(2ms);
  }
  throw std::runtime_error(std::string(stage) + " event wait timed out");
}

void TestSseIncremental()
{
  std::atomic<bool> allow_close{false};
  LoopbackServer server([&](SOCKET socket)
  {
    const std::string request = ReadHttpHeaders(socket);
    const std::string lowered = LowerAscii(request);
    Require(
        lowered.find("\r\naccept: text/event-stream\r\n") != std::string::npos,
        "SSE Accept header mismatch");
    Require(
        lowered.find("\r\ncache-control: no-cache\r\n") != std::string::npos,
        "SSE Cache-Control header mismatch");
    SendAll(
        socket,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: Text/Event-Stream; charset=utf-8\r\n"
        "Connection: close\r\n\r\n");
    std::this_thread::sleep_for(300ms);
    SendAll(socket, ": heartbeat\r");
    std::this_thread::sleep_for(5ms);
    SendAll(socket, "\n" "data: first\r\n" "data: second ");
    SendAll(socket, std::string_view("\xF0\x9F", 2));
    std::this_thread::sleep_for(5ms);
    SendAll(socket, std::string_view("\x98\x80\r", 3));
    std::this_thread::sleep_for(5ms);
    SendAll(socket, "\n\r");
    std::this_thread::sleep_for(5ms);
    SendAll(socket, "\n");
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while ( !allow_close.load() && std::chrono::steady_clock::now() < deadline )
      std::this_thread::sleep_for(2ms);
    Require(allow_close.load(), "SSE client did not consume the event incrementally");
  });

  ida_agent::ai::StreamClient client;
  const auto id = client.OpenSse(MakeLoopbackRequest(server.port(), "/events"));
  const auto opened = WaitNextEvent(client, id, "SSE Opened");
  Require(opened.kind == ida_agent::ai::StreamEventKind::Opened, "SSE Opened missing");
  Require(opened.http_status == 200, "SSE HTTP status mismatch");
  const auto event = WaitNextEvent(client, id, "SSE data");
  Require(event.kind == ida_agent::ai::StreamEventKind::Sse, "SSE event missing");
  Require(event.sse.event == "message", "SSE default event mismatch");
  Require(event.sse.data == "first\nsecond \xF0\x9F\x98\x80", "SSE incremental data mismatch");
  Require(!allow_close.load(), "SSE event was buffered until EOF");
  allow_close.store(true);
  const auto closed = WaitNextEvent(client, id, "SSE Closed");
  Require(closed.kind == ida_agent::ai::StreamEventKind::Closed, "SSE Closed missing");
  server.Join();
}

void TestSseContentTypeRejection()
{
  LoopbackServer server([](SOCKET socket)
  {
    ReadHttpHeaders(socket);
    SendAll(
        socket,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}");
  });
  ida_agent::ai::StreamClient client;
  const auto id = client.OpenSse(MakeLoopbackRequest(server.port(), "/wrong-type"));
  Require(WaitNextEvent(client, id, "SSE rejection Opened").kind == ida_agent::ai::StreamEventKind::Opened, "SSE rejection Opened missing");
  const auto error = WaitNextEvent(client, id, "SSE rejection Error");
  Require(error.kind == ida_agent::ai::StreamEventKind::Error, "invalid SSE Content-Type was accepted");
  Require(error.http_status == 200, "SSE Content-Type error status mismatch");
  server.Join();
}

void TestSseIdleTimeoutMessage()
{
  LoopbackServer server([](SOCKET socket)
  {
    ReadHttpHeaders(socket);
    SendAll(
        socket,
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
        "Connection: close\r\n\r\n");
    char byte = 0;
    recv(socket, &byte, 1, 0);
  });
  ida_agent::ai::StreamRequest request =
      MakeLoopbackRequest(server.port(), "/idle-timeout");
  request.idle_timeout_ms = 100;
  ida_agent::ai::StreamClient client;
  const auto id = client.OpenSse(std::move(request));
  Require(
      WaitNextEvent(client, id, "idle timeout Opened").kind
          == ida_agent::ai::StreamEventKind::Opened,
      "idle timeout Opened missing");
  const auto error = WaitNextEvent(client, id, "idle timeout Error");
  Require(
      error.kind == ida_agent::ai::StreamEventKind::Error
          && error.message == "SSE idle timeout expired.",
      "SSE idle timeout message was not specific");
  server.Join();
}

void TestActiveStop(bool shutdown_client)
{
  LoopbackServer server([](SOCKET socket)
  {
    ReadHttpHeaders(socket);
    SendAll(
        socket,
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n");
    char byte = 0;
    const int received = recv(socket, &byte, 1, 0);
    Require(received <= 0, "active SSE connection was not interrupted");
  });
  ida_agent::ai::StreamClient client;
  const auto id = client.OpenSse(MakeLoopbackRequest(server.port(), "/blocking"));
  Require(WaitNextEvent(client, id, "blocking SSE Opened").kind == ida_agent::ai::StreamEventKind::Opened, "blocking SSE Opened missing");
  if ( shutdown_client )
    client.Shutdown();
  else
    client.Cancel(id);
  const auto terminal = WaitNextEvent(client, id, "blocking SSE terminal");
  Require(terminal.kind == ida_agent::ai::StreamEventKind::Cancelled, "active SSE stop did not cancel");
  server.Join();
}

void TestTerminalQueueLimit()
{
  LoopbackServer server([](SOCKET socket)
  {
    ReadHttpHeaders(socket);
    SendAll(
        socket,
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
  });
  ida_agent::ai::StreamRequest request = MakeLoopbackRequest(server.port(), "/queue-limit");
  request.max_event_bytes = 1;
  request.max_message_bytes = 1;
  request.max_queued_bytes = 1;
  ida_agent::ai::StreamClient client;
  const auto id = client.OpenSse(std::move(request));
  Require(WaitNextEvent(client, id, "queue limit Opened").kind
          == ida_agent::ai::StreamEventKind::Opened,
      "queue limit Opened missing");
  const auto terminal = WaitNextEvent(client, id, "queue limit terminal");
  Require(terminal.kind == ida_agent::ai::StreamEventKind::Error, "queue limit terminal kind was lost");
  Require(terminal.message.empty(), "oversized terminal diagnostic was retained");
  server.Join();
}

std::string Base64Encode(const std::vector<unsigned char> &bytes)
{
  constexpr char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string encoded;
  encoded.reserve(((bytes.size() + 2) / 3) * 4);
  for ( std::size_t offset = 0; offset < bytes.size(); offset += 3 )
  {
    const std::uint32_t value = static_cast<std::uint32_t>(bytes[offset]) << 16
        | (offset + 1 < bytes.size() ? static_cast<std::uint32_t>(bytes[offset + 1]) << 8 : 0)
        | (offset + 2 < bytes.size() ? bytes[offset + 2] : 0);
    encoded.push_back(alphabet[(value >> 18) & 0x3f]);
    encoded.push_back(alphabet[(value >> 12) & 0x3f]);
    encoded.push_back(offset + 1 < bytes.size() ? alphabet[(value >> 6) & 0x3f] : '=');
    encoded.push_back(offset + 2 < bytes.size() ? alphabet[value & 0x3f] : '=');
  }
  return encoded;
}

void RequireNtSuccess(NTSTATUS status, const char *message)
{
  if ( status < 0 )
    throw std::runtime_error(message);
}

std::string WebSocketAccept(std::string key)
{
  key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  RequireNtSuccess(
      BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA1_ALGORITHM, nullptr, 0),
      "SHA-1 provider setup failed");
  DWORD object_size = 0;
  DWORD returned = 0;
  RequireNtSuccess(
      BCryptGetProperty(
          algorithm,
          BCRYPT_OBJECT_LENGTH,
          reinterpret_cast<PUCHAR>(&object_size),
          sizeof(object_size),
          &returned,
          0),
      "SHA-1 object size query failed");
  std::vector<unsigned char> object(object_size);
  std::vector<unsigned char> digest(20);
  RequireNtSuccess(
      BCryptCreateHash(
          algorithm,
          &hash,
          object.data(),
          static_cast<ULONG>(object.size()),
          nullptr,
          0,
          0),
      "SHA-1 hash setup failed");
  RequireNtSuccess(
      BCryptHashData(
          hash,
          reinterpret_cast<PUCHAR>(key.data()),
          static_cast<ULONG>(key.size()),
          0),
      "SHA-1 data update failed");
  RequireNtSuccess(
      BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0),
      "SHA-1 finish failed");
  BCryptDestroyHash(hash);
  BCryptCloseAlgorithmProvider(algorithm, 0);
  return Base64Encode(digest);
}

void SendWebSocketFrame(
    SOCKET socket,
    std::uint8_t opcode,
    bool final,
    std::string_view payload)
{
  Require(payload.size() <= 125, "test WebSocket frame is too large");
  std::string frame;
  frame.push_back(static_cast<char>((final ? 0x80 : 0) | opcode));
  frame.push_back(static_cast<char>(payload.size()));
  frame.append(payload.data(), payload.size());
  SendAll(socket, frame);
}

struct WebSocketFrame
{
  std::uint8_t opcode = 0;
  bool final = false;
  std::string payload;
};

WebSocketFrame ReceiveWebSocketFrame(SOCKET socket)
{
  const std::string header = ReadExact(socket, 2);
  WebSocketFrame frame;
  frame.final = (static_cast<unsigned char>(header[0]) & 0x80) != 0;
  frame.opcode = static_cast<unsigned char>(header[0]) & 0x0f;
  const bool masked = (static_cast<unsigned char>(header[1]) & 0x80) != 0;
  std::uint64_t length = static_cast<unsigned char>(header[1]) & 0x7f;
  if ( length == 126 )
  {
    const std::string extended = ReadExact(socket, 2);
    length = static_cast<unsigned char>(extended[0]) << 8
        | static_cast<unsigned char>(extended[1]);
  }
  Require(length < 64 * 1024, "client WebSocket frame exceeded test limit");
  Require(masked, "client WebSocket frame was not masked");
  const std::string mask = ReadExact(socket, 4);
  frame.payload = ReadExact(socket, static_cast<std::size_t>(length));
  for ( std::size_t index = 0; index < frame.payload.size(); ++index )
    frame.payload[index] ^= mask[index % 4];
  return frame;
}

void AcceptWebSocket(SOCKET socket)
{
  const std::string request = ReadHttpHeaders(socket);
  const std::string key = FindHeader(request, "Sec-WebSocket-Key");
  Require(!key.empty(), "WebSocket key was missing");
  SendAll(
      socket,
      "HTTP/1.1 101 Switching Protocols\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Accept: " + WebSocketAccept(key) + "\r\n\r\n");
}

void TestWebSocket()
{
  LoopbackServer server([](SOCKET socket)
  {
    AcceptWebSocket(socket);
    std::this_thread::sleep_for(300ms);
    SendWebSocketFrame(socket, 0x1, true, "hello");
    SendWebSocketFrame(socket, 0x1, false, "frag-");
    SendWebSocketFrame(socket, 0x0, true, "mented");
    SendWebSocketFrame(socket, 0x2, true, std::string_view("\x00\x01\xFF", 3));
    SendWebSocketFrame(socket, 0x2, false, "bin-");
    SendWebSocketFrame(socket, 0x0, true, std::string_view("ary\x00", 4));
    const WebSocketFrame client_text = ReceiveWebSocketFrame(socket);
    Require(client_text.final && client_text.opcode == 0x1, "client text frame flags mismatch");
    Require(client_text.payload == "from-client", "client text frame payload mismatch");
    const std::string close_payload{"\x03\xE8", 2};
    SendWebSocketFrame(socket, 0x8, true, close_payload);
    const WebSocketFrame close_reply = ReceiveWebSocketFrame(socket);
    Require(close_reply.opcode == 0x8, "client close reply was missing");
  });

  ida_agent::ai::StreamClient client;
  const auto id = client.OpenWebSocket(
      MakeLoopbackRequest(server.port(), "/socket", true));
  const auto opened = WaitNextEvent(client, id, "WebSocket Opened");
  Require(opened.kind == ida_agent::ai::StreamEventKind::Opened, "WebSocket Opened missing");
  Require(opened.http_status == 101, "WebSocket HTTP status mismatch");
  Require(client.SendText(id, "from-client"), "WebSocket SendText was rejected");
  const auto text = WaitNextEvent(client, id, "WebSocket text");
  Require(
      text.kind == ida_agent::ai::StreamEventKind::WebSocketText
          && text.payload == "hello",
      "WebSocket text message mismatch");
  const auto fragmented = WaitNextEvent(client, id, "WebSocket fragmented text");
  Require(
      fragmented.kind == ida_agent::ai::StreamEventKind::WebSocketText
          && fragmented.payload == "frag-mented",
      "WebSocket fragmented text mismatch");
  const auto binary = WaitNextEvent(client, id, "WebSocket binary");
  Require(
      binary.kind == ida_agent::ai::StreamEventKind::WebSocketBinary
          && binary.payload == std::string("\x00\x01\xFF", 3),
      "WebSocket binary message mismatch");
  const auto fragmented_binary = WaitNextEvent(client, id, "WebSocket fragmented binary");
  Require(
      fragmented_binary.kind == ida_agent::ai::StreamEventKind::WebSocketBinary
          && fragmented_binary.payload == std::string("bin-ary\x00", 8),
      "WebSocket fragmented binary mismatch");
  const auto closed = WaitNextEvent(client, id, "WebSocket Closed");
  Require(closed.kind == ida_agent::ai::StreamEventKind::Closed, "WebSocket Closed missing");
  Require(closed.close_code == 1000, "WebSocket close code mismatch");
  server.Join();
}

void TestWebSocketLocalClose()
{
  ida_agent::ai::StreamClient client;
  for ( int iteration = 0; iteration < 25; ++iteration )
  {
    LoopbackServer server([](SOCKET socket)
    {
      AcceptWebSocket(socket);
      const WebSocketFrame close = ReceiveWebSocketFrame(socket);
      Require(close.final && close.opcode == 0x8, "local close frame was missing");
      Require(
          close.payload.size() >= 2
              && static_cast<unsigned char>(close.payload[0]) == 0x03
              && static_cast<unsigned char>(close.payload[1]) == 0xE8,
          "local close code mismatch");
      SendWebSocketFrame(socket, 0x8, true, std::string_view("\x03\xE8", 2));
    });
    const auto id = client.OpenWebSocket(
        MakeLoopbackRequest(server.port(), "/local-close", true));
    Require(
        WaitNextEvent(client, id, "local close Opened").kind
            == ida_agent::ai::StreamEventKind::Opened,
        "local close Opened missing");
    client.Close(id, 1000);
    const auto closed = WaitNextEvent(client, id, "local close Closed");
    Require(closed.kind == ida_agent::ai::StreamEventKind::Closed, "local close Closed missing");
    Require(closed.close_code == 1000, "local close event code mismatch");
    server.Join();
    client.TryTakeEvent(id);
  }
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
    run("SSE incremental", TestSseIncremental);
    run("SSE content type", TestSseContentTypeRejection);
    run("SSE idle timeout", TestSseIdleTimeoutMessage);
    run("SSE cancel", [] { TestActiveStop(false); });
    run("SSE shutdown", [] { TestActiveStop(true); });
    run("terminal queue limit", TestTerminalQueueLimit);
    run("WebSocket", TestWebSocket);
    run("WebSocket local close", TestWebSocketLocalClose);
    return 0;
  }
  catch ( const std::exception &error )
  {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
