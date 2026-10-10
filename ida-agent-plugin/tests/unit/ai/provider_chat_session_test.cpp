#include "ai/provider_chat_session.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <climits>
using SOCKET = int;
constexpr int INVALID_SOCKET = -1;
constexpr int SD_BOTH = SHUT_RDWR;
inline void closesocket(int socket) { close(socket); }
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <exception>
#include <functional>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>

namespace
{

using namespace ida_agent::ai;
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
#ifdef _WIN32
    WSADATA data{};
    Require(WSAStartup(MAKEWORD(2, 2), &data) == 0, "WSAStartup failed");
#endif
  }
  ~WinsockRuntime() {
#ifdef _WIN32
    WSACleanup();
#endif
  }
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
#ifdef _WIN32
        0);
#else
        MSG_NOSIGNAL);
#endif
    Require(sent > 0, "loopback send failed");
    bytes.remove_prefix(static_cast<std::size_t>(sent));
  }
}

std::string ReadHeaders(SOCKET socket)
{
  std::string headers;
  std::array<char, 1024> buffer{};
  while ( headers.find("\r\n\r\n") == std::string::npos )
  {
    const int received = recv(socket, buffer.data(), static_cast<int>(buffer.size()), 0);
    Require(received > 0, "request header receive failed");
    headers.append(buffer.data(), received);
    Require(headers.size() <= 64 * 1024, "request headers too large");
  }
  return headers;
}

class LoopbackServer final
{
public:
  using Handler = std::function<void(SOCKET)>;

  explicit LoopbackServer(Handler handler)
  {
    const SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Require(listener != INVALID_SOCKET, "listener creation failed");
    listener_.store(listener);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    Require(bind(listener, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) == 0,
            "listener bind failed");
    Require(listen(listener, 1) == 0, "listener setup failed");
#ifdef _WIN32
    int size = sizeof(address);
#else
    socklen_t size = sizeof(address);
#endif
    Require(getsockname(listener, reinterpret_cast<sockaddr *>(&address), &size) == 0,
            "listener port query failed");
    port_ = ntohs(address.sin_port);
    worker_ = std::thread([this, handler = std::move(handler)]
    {
      try
      {
        const SOCKET accepted = accept(listener_.load(), nullptr, nullptr);
        Require(accepted != INVALID_SOCKET, "loopback accept failed");
        CloseSocket(listener_);
        client_.store(accepted);
#ifdef _WIN32
        const DWORD timeout = 5000;
#else
        const timeval timeout{5, 0};
#endif
        setsockopt(accepted, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char *>(&timeout), sizeof(timeout));
        setsockopt(accepted, SOL_SOCKET, SO_SNDTIMEO,
                   reinterpret_cast<const char *>(&timeout), sizeof(timeout));
        handler(accepted);
      }
      catch ( ... )
      {
        std::lock_guard<std::mutex> lock(mutex_);
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
      std::lock_guard<std::mutex> lock(mutex_);
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
  std::mutex mutex_;
  std::exception_ptr error_;
};

ProviderChatBuildResult MakeBuild(
    std::uint16_t port,
    ProviderChatCodec codec = ProviderChatCodec::OpenAIChatCompletions)
{
  ProviderChatBuildResult build;
  build.codec = codec;
  build.request.method = HttpMethod::Post;
  build.request.url = "http://127.0.0.1:" + std::to_string(port) + "/chat";
  build.request.user_agent = "ida-agent-provider-chat-session-test";
  build.request.headers.push_back({"Content-Type", "application/json"});
  build.request.body.clear();
  build.request.proxy.mode = HttpProxyMode::Direct;
  build.request.connect_timeout_ms = 2000;
  build.request.send_timeout_ms = 2000;
  build.request.idle_timeout_ms = 5000;
  build.request.overall_timeout_ms = 10000;
  return build;
}

ProviderChatSessionEvent WaitEvent(ProviderChatSession &session)
{
  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while ( std::chrono::steady_clock::now() < deadline )
  {
    ProviderChatSessionEvent event = session.Poll();
    if ( event.kind != ProviderChatSessionEventKind::None
        && event.kind != ProviderChatSessionEventKind::Progress )
      return event;
    std::this_thread::sleep_for(2ms);
  }
  throw std::runtime_error("session event wait timed out");
}

bool IsPending(ProviderChatSessionEventKind kind)
{
  return kind == ProviderChatSessionEventKind::None || kind == ProviderChatSessionEventKind::Progress;
}

void SendSseHeaders(SOCKET socket)
{
  SendAll(socket,
          "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
          "Connection: close\r\n\r\n");
}

void TestTerminalPriority()
{
  Require(
      SelectProviderChatTerminalKindForTesting(true, true, true, true)
          == ProviderChatSessionEventKind::Error,
      "pending error did not win terminal priority");
  Require(
      SelectProviderChatTerminalKindForTesting(false, true, true, false)
          == ProviderChatSessionEventKind::Completed,
      "transport error overrode codec completion");
  Require(
      SelectProviderChatTerminalKindForTesting(false, true, true, true)
          == ProviderChatSessionEventKind::ToolCalls,
      "transport error overrode completed tool calls");
  Require(
      SelectProviderChatTerminalKindForTesting(false, false, true, false)
          == ProviderChatSessionEventKind::Cancelled,
      "user cancellation did not precede transport failure");
  Require(
      SelectProviderChatTerminalKindForTesting(false, false, false, false)
          == ProviderChatSessionEventKind::Error,
      "bare transport failure was not an error");
}

void TestOpenAIChunkedCompletion()
{
  std::atomic<bool> disconnected{false};
  LoopbackServer server([&](SOCKET socket)
  {
    const std::string headers = ReadHeaders(socket);
    Require(headers.find("POST /chat") != std::string::npos, "chat request path mismatch");
    SendSseHeaders(socket);
    SendAll(socket, "data: {\"choices\":[{\"delta\":{\"content\":\"hel");
    SendAll(socket, "lo\"},\"finish_reason\":null}]}\n\n");
    SendAll(socket, "data: [DONE]\n\n");
    char byte = 0;
    Require(recv(socket, &byte, 1, 0) <= 0,
            "codec completion did not cancel keepalive transport");
    disconnected.store(true);
  });
  StreamClient client;
#ifdef IDA_AGENT_STREAM_CLIENT_TESTING
  client.SetWorkerExitDelayForTesting(200);
#endif
  ProviderChatSession session;
  Require(session.Start(client, MakeBuild(server.port())), "session start failed");
  const ProviderChatSessionEvent delta = WaitEvent(session);
  Require(delta.kind == ProviderChatSessionEventKind::Delta && delta.text_delta == "hello",
          "chunked OpenAI delta mismatch");
  const auto disconnect_deadline = std::chrono::steady_clock::now() + 5s;
  while ( !disconnected.load()
      && std::chrono::steady_clock::now() < disconnect_deadline )
  {
    Require(IsPending(session.Poll().kind),
            "codec completion published before transport terminal");
    std::this_thread::sleep_for(2ms);
  }
  Require(disconnected.load(), "keepalive transport was not cancelled");
  session.Cancel();
  const auto retirement_delay = std::chrono::steady_clock::now() + 100ms;
  while ( std::chrono::steady_clock::now() < retirement_delay )
  {
    Require(IsPending(session.Poll().kind),
            "terminal published before deterministic retirement");
    Require(session.IsActive(), "session became inactive before retirement");
    std::this_thread::sleep_for(2ms);
  }
  const ProviderChatSessionEvent completed = WaitEvent(session);
  if ( completed.kind != ProviderChatSessionEventKind::Completed )
  {
    throw std::runtime_error(
        "OpenAI completion missing: kind="
        + std::to_string(static_cast<int>(completed.kind))
        + " message=" + completed.safe_message);
  }
  server.Join();
}

void TestEarlyClose()
{
  LoopbackServer server([](SOCKET socket)
  {
    ReadHeaders(socket);
    SendSseHeaders(socket);
  });
  StreamClient client;
  ProviderChatSession session;
  Require(session.Start(client, MakeBuild(server.port())), "early-close start failed");
  const ProviderChatSessionEvent event = WaitEvent(session);
  Require(event.kind == ProviderChatSessionEventKind::Error,
          "early close was not an error");
  Require(event.safe_message == ProviderChatEarlyCloseMessage,
          "early-close safe message mismatch");
  server.Join();
}

void TestCancel()
{
  LoopbackServer server([](SOCKET socket)
  {
    ReadHeaders(socket);
    SendSseHeaders(socket);
    char byte = 0;
    Require(recv(socket, &byte, 1, 0) <= 0, "cancel did not close transport");
  });
  StreamClient client;
  ProviderChatSession session;
  Require(session.Start(client, MakeBuild(server.port())), "cancel start failed");
  std::this_thread::sleep_for(30ms);
  session.Cancel();
  Require(WaitEvent(session).kind == ProviderChatSessionEventKind::Cancelled,
          "cancel terminal mismatch");
  server.Join();
}

void TestToolCall()
{
  std::atomic<bool> disconnected{false};
  LoopbackServer server([&](SOCKET socket)
  {
    ReadHeaders(socket);
    SendSseHeaders(socket);
    SendAll(socket,
            "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"thought\","
            "\"content\":\"checking\","
            "\"tool_calls\":[{\"index\":0,\"id\":\"call-\","
            "\"type\":\"function\",\"function\":{\"name\":\"look\","
            "\"arguments\":\"{\\\"name\\\":\"}}]},"
            "\"finish_reason\":null}]}\n\n");
    SendAll(socket,
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,"
            "\"id\":\"1\",\"function\":{\"name\":\"up\","
            "\"arguments\":\"\\\"main\\\"}\"}}]},"
            "\"finish_reason\":null}]}\n\n");
    for ( int index = 0; index < 128; ++index )
      SendAll(socket, "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\" \"}}]},\"finish_reason\":null}]}\n\n");
    SendAll(socket,
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":["
            "{\"index\":1,\"id\":\"call-2\",\"type\":\"function\",\"function\":{\"name\":\"lookup\",\"arguments\":\"{}\"}},"
            "{\"index\":2,\"id\":\"call-3\",\"type\":\"function\",\"function\":{\"name\":\"lookup\",\"arguments\":\"{}\"}},"
            "{\"index\":3,\"id\":\"call-4\",\"type\":\"function\",\"function\":{\"name\":\"lookup\",\"arguments\":\"{}\"}},"
            "{\"index\":4,\"id\":\"call-5\",\"type\":\"function\",\"function\":{\"name\":\"lookup\",\"arguments\":\"{}\"}},"
            "{\"index\":5,\"id\":\"call-6\",\"type\":\"function\",\"function\":{\"name\":\"lookup\",\"arguments\":\"{}\"}}]},"
            "\"finish_reason\":null}]}\n\n");
    SendAll(socket,
            "data: {\"choices\":[{\"delta\":{},"
            "\"finish_reason\":\"tool_calls\"}]}\n\n");
    char byte = 0;
    Require(recv(socket, &byte, 1, 0) <= 0,
            "tool completion did not cancel transport");
    disconnected.store(true);
  });
  StreamClient client;
#ifdef IDA_AGENT_STREAM_CLIENT_TESTING
  client.SetWorkerExitDelayForTesting(200);
#endif
  ProviderChatSession session;
  ProviderChatBuildResult build = MakeBuild(server.port());
  build.show_reasoning = true;
  Require(session.Start(client, std::move(build)), "tool-call start failed");
  const ProviderChatSessionEvent delta = WaitEvent(session);
  Require(delta.kind == ProviderChatSessionEventKind::Delta
              && delta.reasoning_delta == "thought"
              && delta.text_delta == "checking",
          "tool-call text delta was lost");
  const auto disconnect_deadline = std::chrono::steady_clock::now() + 5s;
  std::size_t progress_count = 0;
  while ( !disconnected.load()
      && std::chrono::steady_clock::now() < disconnect_deadline )
  {
    const auto kind = session.Poll().kind;
    if ( kind == ProviderChatSessionEventKind::Progress ) ++progress_count;
    Require(IsPending(kind),
            "tool calls published before transport terminal");
    if ( kind == ProviderChatSessionEventKind::None ) std::this_thread::sleep_for(2ms);
  }
  Require(disconnected.load(), "tool-call transport remained open");
  Require(progress_count >= 128, "tool argument fragments were reported as an empty queue");
  const auto retirement_delay = std::chrono::steady_clock::now() + 100ms;
  while ( std::chrono::steady_clock::now() < retirement_delay )
  {
    Require(IsPending(session.Poll().kind),
            "tool calls published before retirement");
    Require(session.IsActive(), "tool session retired nondeterministically");
    std::this_thread::sleep_for(2ms);
  }
  const ProviderChatSessionEvent event = WaitEvent(session);
  Require(event.kind == ProviderChatSessionEventKind::ToolCalls,
          "tool calls terminal mismatch");
  Require(event.calls.size() == 6
              && event.calls.front().id == "call-1"
              && event.calls.front().name == "lookup"
              && event.calls.front().arguments_json == std::string(R"({"name":"main"})") + std::string(128, ' ')
              && event.calls.back().id == "call-6",
          "accumulated tool call mismatch");
  Require(event.assistant_text == "checking",
          "tool-call assistant text was not preserved");
  Require(event.assistant_text.find("thought") == std::string::npos,
          "reasoning leaked into tool-call assistant text");
  Require(!session.IsActive(), "tool session remained active after retirement");
  server.Join();
}

void TestTextLimit()
{
  std::atomic<bool> consumed{false};
  LoopbackServer server([&](SOCKET socket)
  {
    ReadHeaders(socket);
    SendSseHeaders(socket);
    SendAll(socket,
            "data: {\"choices\":[{\"delta\":{\"content\":\"hello\"},"
            "\"finish_reason\":null}]}\n\n");
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while ( !consumed.load() && std::chrono::steady_clock::now() < deadline )
      std::this_thread::sleep_for(2ms);
    Require(consumed.load(), "bounded delta was not consumed");
    SendAll(socket,
            "data: {\"choices\":[{\"delta\":{\"content\":\"x\"},"
            "\"finish_reason\":null}]}\n\n");
    char byte = 0;
    recv(socket, &byte, 1, 0);
  });
  StreamClient client;
  ProviderChatSession session(5);
  Require(session.Start(client, MakeBuild(server.port())), "limit start failed");
  const ProviderChatSessionEvent bounded = WaitEvent(session);
  Require(bounded.kind == ProviderChatSessionEventKind::Delta
              && bounded.text_delta == "hello",
          "bounded delta missing");
  consumed.store(true);
  const ProviderChatSessionEvent event = WaitEvent(session);
  Require(event.kind == ProviderChatSessionEventKind::Error,
          "cumulative text limit was not terminal");
  Require(event.safe_message == ProviderChatTextLimitMessage,
          "text-limit safe message mismatch");
  server.Join();
}

void TestLeadingReasoningHidden()
{
  StreamClient client;
  ProviderChatSession session;
  {
    LoopbackServer first_server([](SOCKET socket)
    {
      ReadHeaders(socket);
      SendSseHeaders(socket);
      SendAll(socket,
              "data: {\"choices\":[{\"delta\":{\"content\":\"visible\"},"
              "\"finish_reason\":null}]}\n\n"
              "data: [DONE]\n\n");
      char byte = 0;
      recv(socket, &byte, 1, 0);
    });
    Require(session.Start(client, MakeBuild(first_server.port())),
            "first reusable session start failed");
    Require(WaitEvent(session).text_delta == "visible",
            "first reusable session delta mismatch");
    Require(WaitEvent(session).kind == ProviderChatSessionEventKind::Completed,
            "first reusable session did not complete");
    first_server.Join();
  }

  LoopbackServer server([](SOCKET socket)
  {
    ReadHeaders(socket);
    SendSseHeaders(socket);
    SendAll(socket,
            "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"separate secret\"},"
            "\"finish_reason\":null}]}\n\n");
    SendAll(socket,
            "data: {\"choices\":[{\"delta\":{\"content\":\" \\n<thi\"},"
            "\"finish_reason\":null}]}\n\n");
    SendAll(socket,
            "data: {\"choices\":[{\"delta\":{\"content\":\"nk>tag secret\"},"
            "\"finish_reason\":null}]}\n\n");
    SendAll(socket,
            "data: {\"choices\":[{\"delta\":{\"content\":\"</thi\"},"
            "\"finish_reason\":null}]}\n\n");
    SendAll(socket,
            "data: {\"choices\":[{\"delta\":{\"content\":\"nk>fi\"},"
            "\"finish_reason\":null}]}\n\n");
    SendAll(socket,
            "data: {\"choices\":[{\"delta\":{\"content\":\"nal\"},"
            "\"finish_reason\":null}]}\n\n"
            "data: [DONE]\n\n");
    char byte = 0;
    recv(socket, &byte, 1, 0);
  });
  Require(session.Start(client, MakeBuild(server.port())),
          "reasoning filter start failed");
  const ProviderChatSessionEvent first = WaitEvent(session);
  const ProviderChatSessionEvent second = WaitEvent(session);
  Require(first.kind == ProviderChatSessionEventKind::Delta
              && first.text_delta == "fi",
          "leading reasoning close did not reveal final text");
  Require(second.kind == ProviderChatSessionEventKind::Delta
              && second.text_delta == "nal",
          "final text did not remain streamed");
  Require(WaitEvent(session).kind == ProviderChatSessionEventKind::Completed,
          "reasoning-filtered response did not complete");
  server.Join();
}

void TestReasoningVisible()
{
  LoopbackServer server([](SOCKET socket)
  {
    ReadHeaders(socket);
    SendSseHeaders(socket);
    SendAll(socket,
            "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"summary\"},"
            "\"finish_reason\":null}]}\n\n");
    SendAll(socket,
            "data: {\"choices\":[{\"delta\":{\"content\":\"<think>tag thought</think>answer\"},"
            "\"finish_reason\":null}]}\n\n"
            "data: [DONE]\n\n");
    char byte = 0;
    recv(socket, &byte, 1, 0);
  });
  StreamClient client;
  ProviderChatSession session;
  ProviderChatBuildResult build = MakeBuild(server.port());
  build.show_reasoning = true;
  Require(session.Start(client, std::move(build)),
          "visible reasoning session start failed");
  const ProviderChatSessionEvent reasoning = WaitEvent(session);
  const ProviderChatSessionEvent answer = WaitEvent(session);
  Require(reasoning.kind == ProviderChatSessionEventKind::Delta
              && reasoning.reasoning_delta == "summary"
              && reasoning.text_delta.empty(),
          "reasoning summary was not separated");
  Require(answer.kind == ProviderChatSessionEventKind::Delta
              && answer.reasoning_delta == "tag thought"
              && answer.text_delta == "answer",
          "answer delta was not separated");
  Require(WaitEvent(session).kind == ProviderChatSessionEventKind::Completed,
          "visible reasoning response did not complete");
  server.Join();
}

void TestToolArgumentLimit()
{
  LoopbackServer server([](SOCKET socket)
  {
    ReadHeaders(socket);
    SendSseHeaders(socket);
    const std::string first(MaxAgentToolArgumentsBytes / 2, 'x');
    const std::string second(MaxAgentToolArgumentsBytes / 2 + 1, 'x');
    SendAll(socket,
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,"
            "\"id\":\"call-1\",\"function\":{\"name\":\"lookup\","
            "\"arguments\":\"" + first
            + "\"}}]},\"finish_reason\":null}]}\n\n");
    SendAll(socket,
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,"
            "\"function\":{\"arguments\":\"" + second
            + "\"}}]},\"finish_reason\":null}]}\n\n");
    char byte = 0;
    recv(socket, &byte, 1, 0);
  });
  StreamClient client;
  ProviderChatSession session;
  Require(session.Start(client, MakeBuild(server.port())),
          "tool-limit start failed");
  const ProviderChatSessionEvent event = WaitEvent(session);
  Require(event.kind == ProviderChatSessionEventKind::Error
              && event.safe_message == ProviderChatToolLimitMessage,
          "tool argument limit mismatch");
  server.Join();
}

void TestFileMutationArgumentBudget()
{
  const std::string arguments = std::string(
      R"({"path":"large.txt","mode":"overwrite","content":")")
      + std::string(MaxAgentToolArgumentsBytes + 1, 'x') + R"("})";
  std::string events;
  for ( std::size_t offset = 0; offset < arguments.size(); offset += 16 * 1024 )
  {
    const std::string_view chunk(arguments.data() + offset,
        (std::min)(std::size_t{16 * 1024}, arguments.size() - offset));
    std::string encoded;
    encoded.reserve(chunk.size() + 32);
    for ( char ch : chunk )
    {
      if ( ch == '\\' || ch == '"' ) encoded.push_back('\\');
      encoded.push_back(ch);
    }
    events += "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,";
    if ( offset == 0 )
      events += "\"id\":\"file-1\",\"function\":{\"name\":\"ida_file_mutate\",";
    else
      events += "\"function\":{";
    events += "\"arguments\":\"" + encoded
        + "\"}}]},\"finish_reason\":null}]}\n\n";
  }
  events += "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n";
  LoopbackServer server([events](SOCKET socket)
  {
    ReadHeaders(socket);
    SendSseHeaders(socket);
    SendAll(socket, events);
    char byte = 0;
    recv(socket, &byte, 1, 0);
  });
  StreamClient client;
  ProviderChatSession session;
  Require(session.Start(client, MakeBuild(server.port())),
      "file mutation argument-budget start failed");
  const ProviderChatSessionEvent event = WaitEvent(session);
  Require(event.kind == ProviderChatSessionEventKind::ToolCalls
      && event.calls.size() == 1 && event.calls.front().name == "ida_file_mutate"
      && event.calls.front().arguments_json == arguments,
      "bounded file mutation arguments were rejected or changed");
  server.Join();
}

void TestMalformedToolArguments()
{
  LoopbackServer server([](SOCKET socket)
  {
    ReadHeaders(socket);
    SendSseHeaders(socket);
    SendAll(socket,
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,"
            "\"id\":\"call-1\",\"function\":{\"name\":\"lookup\","
            "\"arguments\":\"{\"}}]},\"finish_reason\":null}]}\n\n");
    SendAll(socket,
            "data: {\"choices\":[{\"delta\":{},"
            "\"finish_reason\":\"tool_calls\"}]}\n\n");
    char byte = 0;
    recv(socket, &byte, 1, 0);
  });
  StreamClient client;
  ProviderChatSession session;
  Require(session.Start(client, MakeBuild(server.port())),
          "malformed-tool start failed");
  const ProviderChatSessionEvent event = WaitEvent(session);
  Require(event.kind == ProviderChatSessionEventKind::Error
              && event.safe_message == ProviderChatProtocolErrorMessage,
          "malformed tool arguments mismatch");
  server.Join();
}

void TestTransportError()
{
  LoopbackServer server([](SOCKET socket)
  {
    ReadHeaders(socket);
    SendAll(socket,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            "Connection: close\r\n\r\nsecret-body");
  });
  StreamClient client;
  ProviderChatSession session;
  Require(session.Start(client, MakeBuild(server.port())), "transport-error start failed");
  const ProviderChatSessionEvent event = WaitEvent(session);
  Require(event.kind == ProviderChatSessionEventKind::Error,
          "transport failure was not an error");
  Require(event.safe_message.find(ProviderChatTransportErrorMessage)
              != std::string::npos
              && event.safe_message.find("content type is invalid")
                  != std::string::npos,
          "transport detail was not surfaced");
  Require(event.safe_message.find("secret-body") == std::string::npos,
          "transport body leaked");
  server.Join();
}

void TestHttpStatusError()
{
  LoopbackServer server([](SOCKET socket)
  {
    ReadHeaders(socket);
    const std::string body =
        R"({"error":{"type":"invalid_request_error","code":"bad_request","message":"request rejected; Bearer secret-token"}})";
    SendAll(socket,
            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n"
            "Content-Length: " + std::to_string(body.size())
            + "\r\nConnection: close\r\n\r\n" + body);
  });
  StreamClient client;
  ProviderChatSession session;
  Require(session.Start(client, MakeBuild(server.port())),
          "HTTP-status start failed");
  const ProviderChatSessionEvent event = WaitEvent(session);
  Require(event.kind == ProviderChatSessionEventKind::Error
              && event.safe_message.find(
                     "Provider chat request failed with HTTP status 400") != std::string::npos
              && event.safe_message.find("type=invalid_request_error") != std::string::npos
              && event.safe_message.find("code=bad_request") != std::string::npos
              && event.safe_message.find("message=request rejected") != std::string::npos,
          "HTTP error detail was not surfaced");
  Require(event.safe_message.find("secret-token") == std::string::npos,
          "HTTP error detail exposed a credential marker");
  server.Join();
}

void TestClaudeEmptyInputToolCall()
{
  LoopbackServer server([](SOCKET socket)
  {
    ReadHeaders(socket);
    SendSseHeaders(socket);
    SendAll(socket,
            "data: {\"type\":\"content_block_start\",\"index\":0,"
            "\"content_block\":{\"type\":\"tool_use\",\"id\":\"tool-1\","
            "\"name\":\"ida_symbol_exports\",\"input\":{}}}\n\n");
    SendAll(socket,
            "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n"
            "data: {\"type\":\"message_stop\"}\n\n");
    char byte = 0;
    recv(socket, &byte, 1, 0);
  });
  StreamClient client;
  ProviderChatSession session;
  Require(session.Start(
      client, MakeBuild(server.port(), ProviderChatCodec::ClaudeMessages)),
      "Claude empty-input tool start failed");
  const ProviderChatSessionEvent event = WaitEvent(session);
  Require(event.kind == ProviderChatSessionEventKind::ToolCalls
              && event.calls.size() == 1
              && event.calls.front().arguments_json == "{}",
          "Claude empty object tool arguments were rejected");
  server.Join();
}

} // namespace

int main()
{
  try
  {
    WinsockRuntime winsock;
    TestTerminalPriority();
    TestOpenAIChunkedCompletion();
    TestEarlyClose();
    TestCancel();
    TestToolCall();
    TestTextLimit();
    TestLeadingReasoningHidden();
    TestReasoningVisible();
    TestToolArgumentLimit();
    TestFileMutationArgumentBudget();
    TestMalformedToolArguments();
    TestClaudeEmptyInputToolCall();
    TestTransportError();
    TestHttpStatusError();
    return 0;
  }
  catch ( const std::exception &error )
  {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
