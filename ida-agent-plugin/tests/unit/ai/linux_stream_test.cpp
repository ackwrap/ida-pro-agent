#include "ai/stream_client.hpp"
#ifndef __APPLE__
#include <curl/curl.h>
#endif
#include <sqlite3.h>
#include <algorithm>
#include <chrono>
#include <iostream>
#include <set>
#include <stdexcept>
#include <thread>

namespace
{
using namespace ida_agent::ai;
using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;
void Require(bool value, const char *message) { if (!value) throw std::runtime_error(message); }
bool Terminal(StreamEventKind kind)
{ return kind == StreamEventKind::Error || kind == StreamEventKind::Closed || kind == StreamEventKind::Cancelled; }
StreamRequest Request(const std::string &url)
{
  StreamRequest request;
  request.url = url;
  request.user_agent = "ida-linux-stream-test";
  request.proxy.mode = HttpProxyMode::Direct;
  request.connect_timeout_ms = 1000;
  request.send_timeout_ms = 1000;
  request.idle_timeout_ms = 2000;
  request.overall_timeout_ms = 5000;
  return request;
}
StreamEvent Next(StreamClient &client, StreamClient::StreamId id, std::chrono::milliseconds wait = 6s)
{
  const auto deadline = Clock::now() + wait;
  while (Clock::now() < deadline)
  {
    if (auto event = client.TryTakeEvent(id)) return std::move(*event);
    std::this_thread::sleep_for(2ms);
  }
  throw std::runtime_error("stream event did not arrive");
}
std::vector<StreamEvent> Drain(StreamClient &client, StreamClient::StreamId id, StreamEventKind kind,
    std::chrono::milliseconds wait = 6s)
{
  Require(id != 0, "stream was not allocated");
  std::vector<StreamEvent> events;
  do { events.push_back(Next(client, id, wait)); } while (!Terminal(events.back().kind));
  if (events.back().kind != kind)
    throw std::runtime_error("wrong terminal event: kind=" + std::to_string(static_cast<int>(events.back().kind))
        + " close=" + std::to_string(events.back().close_code) + " " + events.back().message);
  const auto deadline = Clock::now() + 1s;
  while (!client.Retire(id) && Clock::now() < deadline) std::this_thread::sleep_for(2ms);
  Require(client.Retire(id), "finished stream could not retire");
  Require(!client.TryTakeEvent(id), "multiple terminal events");
  return events;
}
void Opened(StreamClient &client, StreamClient::StreamId id)
{
  auto event = Next(client, id);
  if (event.kind != StreamEventKind::Opened) throw std::runtime_error("stream did not open: " + event.message);
}
void Echo(StreamClient &client, StreamRequest request, bool large = false)
{
  auto id = client.OpenWebSocket(request);
  Opened(client, id);
  Require(!client.SendText(id, "\xff"), "invalid UTF-8 send accepted");
  const std::string text = large ? std::string(3 * 1024 * 1024, 'z') : "hello 中";
  Require(client.SendText(id, text), "text send rejected");
  auto event = Next(client, id);
  Require(event.kind == StreamEventKind::WebSocketText && event.payload == text, "text echo mismatch");
  Require(client.SendBinary(id, std::string("\0\xff", 2)), "binary send rejected");
  event = Next(client, id);
  Require(event.kind == StreamEventKind::WebSocketBinary && event.payload == std::string("\0\xff", 2), "binary echo mismatch");
  Require(client.SendText(id, ""), "empty send rejected");
  event = Next(client, id);
  Require(event.kind == StreamEventKind::WebSocketText && event.payload.empty(), "empty echo mismatch");
  client.Close(id, 1000);
  Require(!client.SendText(id, "late"), "send after close accepted");
  Require(Drain(client, id, StreamEventKind::Closed).back().close_code == 1000, "close code lost");
}
void Sse(StreamClient &client, StreamRequest request)
{
  auto events = Drain(client, client.OpenSse(request), StreamEventKind::Closed);
  Require(events.size() == 4 && events[0].kind == StreamEventKind::Opened && events[0].http_status == 200,
      "SSE event order mismatch");
  Require(events[1].sse.data == "中\nsecond" && events[1].sse.id == "7" && events[1].sse.retry_ms == 50
      && events[1].sse.event == "text" && events[2].sse.data == "end", "SSE fragmented UTF-8 / multiline metadata mismatch");
}
HttpProxyConfig Proxy(const char *port)
{
  HttpProxyConfig proxy;
  proxy.mode = HttpProxyMode::Http;
  proxy.host = "127.0.0.1";
  proxy.port = static_cast<std::uint16_t>(std::stoi(port));
  proxy.username = "user";
  proxy.password = "proxy-fixture-secret";
  proxy.bypass_local = false;
  return proxy;
}
std::string ProxyUrl(std::string url)
{
  const auto begin = url.find("://") + 3;
  url.replace(begin, url.find(':', begin) - begin, "provider.invalid");
  return url;
}
void Dependencies()
{
#ifndef __APPLE__
  const auto *version = curl_version_info(CURLVERSION_NOW);
  std::set<std::string> protocols;
  for (auto protocol = version->protocols; *protocol; ++protocol) protocols.insert(*protocol);
  Require(protocols == std::set<std::string>{"http", "https", "ws", "wss"}, "libcurl protocol set is not minimal");
  Require(std::string(version->version) == "8.22.0" && (version->features & CURL_VERSION_ASYNCHDNS)
      && std::string(version->ssl_version).find("OpenSSL/3.") == 0, "embedded libcurl configuration mismatch");
#endif
  Require(std::string(sqlite3_libversion()) == "3.53.4" && sqlite3_threadsafe()
      && sqlite3_compileoption_used("OMIT_LOAD_EXTENSION"), "embedded SQLite configuration mismatch");
}
}

int main(int argc, char **argv)
{
  try
  {
    Require(argc == 8, "expected mode and local fixture endpoints");
    Dependencies();
    const std::string mode = argv[1], http = argv[2], https = argv[3], ws = argv[4], wss = argv[5];
    StreamClient client;
    if (mode == "system-proxy")
    {
      auto request = Request(http + "/events");
      request.proxy.mode = HttpProxyMode::System;
      Sse(client, request);
      request.url = ws + "/echo";
      Echo(client, request);
      return 0;
    }
    if (mode == "trusted")
    {
      Sse(client, Request(https + "/events"));
      Echo(client, Request(wss + "/echo"));
      auto request = Request(https + "/events");
      request.url = ProxyUrl(request.url);
      request.proxy = Proxy(argv[6]);
      Sse(client, request);
      request.url = ProxyUrl(wss + "/echo");
      Echo(client, request);
      request.proxy.mode = HttpProxyMode::Direct;
      request.url = wss + "/echo";
      request.url.replace(request.url.find("localhost"), 9, "127.0.0.1");
      Drain(client, client.OpenWebSocket(request), StreamEventKind::Error);
      return 0;
    }
    Sse(client, Request(http + "/events"));
    auto request = Request(http + "/post");
    request.method = HttpMethod::Post;
    request.body = "post-body";
    auto events = Drain(client, client.OpenSse(request), StreamEventKind::Closed);
    Require(events.size() == 3 && events[1].sse.data == "post-body", "SSE POST body mismatch");
    for (const auto *path : {"/status", "/wrong-type", "/redirect"})
    {
      events = Drain(client, client.OpenSse(Request(http + path)), StreamEventKind::Error);
      Require(events.back().http_status != 0, "SSE error lost HTTP status");
    }
    for (const auto *path : {"/idle-body", "/idle-headers"})
    {
      request = Request(http + path);
      request.idle_timeout_ms = 100;
      const auto start = Clock::now();
      events = Drain(client, client.OpenSse(request), StreamEventKind::Error);
      Require(Clock::now() - start < 1s, "SSE idle timeout was not enforced");
    }
    request = Request(http + "/heartbeat");
    // Test idle progress without an unrelated overall cap. The fixture lasts
    // three wall-clock seconds; total-deadline enforcement is checked below.
    request.idle_timeout_ms = 2000;
    request.overall_timeout_ms.reset();
    const auto heartbeat_start = Clock::now();
    Drain(client, client.OpenSse(request), StreamEventKind::Closed, 15s);
    Require(Clock::now() - heartbeat_start > 2s, "heartbeat fixture did not exceed the idle deadline");
    request.overall_timeout_ms = 150;
    events = Drain(client, client.OpenSse(request), StreamEventKind::Error);
    Require(events.back().message.find("overall") != std::string::npos, "SSE overall deadline not enforced");
    request = Request(http + "/large");
    request.max_event_bytes = 64;
    Drain(client, client.OpenSse(request), StreamEventKind::Error);
    request = Request(http + "/flood");
    auto id = client.OpenSse(request);
    std::this_thread::sleep_for(250ms);
    events = Drain(client, id, StreamEventKind::Error);
    Require(events.size() <= StreamHardMaxQueuedEvents, "SSE queue event bound exceeded");
    request = Request(http + "/byte-flood");
    request.max_event_bytes = request.max_queued_bytes = 32;
    id = client.OpenSse(request);
    std::this_thread::sleep_for(150ms);
    events = Drain(client, id, StreamEventKind::Error);
    Require(events.size() == 3, "SSE queue byte bound was not enforced");
    Drain(client, client.OpenSse(Request(http + "/truncated")), StreamEventKind::Error);
    request = Request(http + "/idle-body");
    id = client.OpenSse(request);
    Opened(client, id);
    auto start = Clock::now();
    client.Cancel(id);
    Drain(client, id, StreamEventKind::Cancelled);
    Require(Clock::now() - start < 500ms, "SSE cancel blocked");
    request = Request(http + "/upload-stall");
    request.method = HttpMethod::Post;
    request.body.assign(StreamHardMaxPayloadBytes, 'x');
    request.send_timeout_ms = 100;
    events = Drain(client, client.OpenSse(request), StreamEventKind::Error);
    Require(events.back().message.find("send timeout") != std::string::npos, "SSE upload deadline missing");
    std::cout << "SSE cases passed\n" << std::flush;

    Echo(client, Request(ws + "/echo"), true);
    Echo(client, Request(ws + "/ping-upload"), true);
    std::cout << "WS text / binary / empty / close passed\n" << std::flush;
    events = Drain(client, client.OpenWebSocket(Request(ws + "/fragment")), StreamEventKind::Closed);
    Require(events.size() == 5 && events[1].payload == "中text" && events[2].payload == std::string("\0\xff" "binary", 8)
        && events[3].payload == "pong-ok", "WS fragments / control frames mismatch");
    std::cout << "WS fragments / control frames passed\n" << std::flush;
    for (const auto *path : {"/invalid", "/abrupt"})
    {
      std::cout << "WS protocol case " << path << '\n' << std::flush;
      Drain(client, client.OpenWebSocket(Request(ws + path)), StreamEventKind::Error);
    }
    request = Request(ws + "/large");
    request.max_message_bytes = 64;
    Drain(client, client.OpenWebSocket(request), StreamEventKind::Error);
    const auto raw_ws = "ws" + http.substr(4);
    request = Request("wss://" + std::string(argv[7]) + "/");
    request.connect_timeout_ms = 100;
    start = Clock::now();
    events = Drain(client, client.OpenWebSocket(request), StreamEventKind::Error);
#ifdef __APPLE__
    Require(events.back().message.find("timeout") != std::string::npos, "WS connect failure was not a timeout");
#else
    Require(events.back().message.find("curl=28") != std::string::npos, "WS connect failure was not a timeout");
#endif
    Require(Clock::now() - start < 1s, "WS TLS connect timeout was not enforced");
    Drain(client, client.OpenWebSocket(Request(raw_ws + "/badaccept")), StreamEventKind::Error);
    std::cout << "WS handshake / TLS timeout / invalid messages passed\n" << std::flush;
    id = client.OpenWebSocket(Request(raw_ws + "/no-close"));
    Opened(client, id);
    client.Close(id);
#ifdef __APPLE__
    // NSURLSession reports local cancellation with the requested close code;
    // it does not expose a separate remote close acknowledgement.
    Require(Drain(client, id, StreamEventKind::Closed).back().close_code == 1000, "local close code lost");
#else
    events = Drain(client, id, StreamEventKind::Error);
    Require(events.back().message.find("close handshake") != std::string::npos, "missing close timeout");
#endif
    request = Request(ws + "/idle");
    request.idle_timeout_ms = 100;
    Drain(client, client.OpenWebSocket(request), StreamEventKind::Error);
    request = Request(ws + "/flood");
    request.max_message_bytes = request.max_queued_bytes = 16;
    id = client.OpenWebSocket(request);
    std::this_thread::sleep_for(250ms);
    events = Drain(client, id, StreamEventKind::Error);
    Require(events.size() <= 18, "WebSocket queue byte bound exceeded");
    request = Request(ws + "/idle");
    request.idle_timeout_ms = 2000;
    request.overall_timeout_ms = 100;
    events = Drain(client, client.OpenWebSocket(request), StreamEventKind::Error);
    Require(events.back().message.find("overall") != std::string::npos, "WS overall timeout missing");
    id = client.OpenWebSocket(Request(ws + "/idle"));
    Opened(client, id);
    client.Close(id, 1006);
    Drain(client, id, StreamEventKind::Error);
    id = client.OpenWebSocket(Request(ws + "/idle"));
    Opened(client, id);
    start = Clock::now();
    client.Cancel(id);
    Drain(client, id, StreamEventKind::Cancelled);
    Require(Clock::now() - start < 500ms, "WS cancel blocked");
    request = Request(raw_ws + "/no-read");
    request.max_message_bytes = StreamHardMaxPayloadBytes;
    request.max_queued_bytes = StreamHardMaxPayloadBytes;
    request.send_timeout_ms = 150;
    id = client.OpenWebSocket(request);
    Opened(client, id);
    Require(client.SendBinary(id, std::string(StreamHardMaxPayloadBytes, 'x')), "large queued send rejected");
    Require(!client.SendText(id, "extra"), "send queue byte bound exceeded");
    events = Drain(client, id, StreamEventKind::Error);
    if (events.back().message.find("send timeout") == std::string::npos)
      throw std::runtime_error("WS send deadline missing: " + events.back().message);
    std::cout << "WebSocket cases passed\n" << std::flush;

    request = Request(http + "/events");
    request.proxy = Proxy(argv[6]);
    request.url = ProxyUrl(request.url);
    Sse(client, request);
    request.url = ProxyUrl(ws + "/echo");
    Echo(client, request);
    Drain(client, client.OpenSse(Request(https + "/events")), StreamEventKind::Error);
    Drain(client, client.OpenWebSocket(Request(wss + "/echo")), StreamEventKind::Error);
    std::vector<StreamClient::StreamId> active;
    for (std::size_t i = 0; i < StreamMaxConcurrent; ++i)
    {
      id = client.OpenWebSocket(Request(ws + "/idle"));
      Opened(client, id);
      active.push_back(id);
    }
    Drain(client, client.OpenSse(Request(http + "/events")), StreamEventKind::Error);
    start = Clock::now();
    client.Shutdown();
    Require(Clock::now() - start < 500ms, "active stream shutdown blocked");
    for (auto value : active) Drain(client, value, StreamEventKind::Cancelled);
    std::cout << "proxy / TLS rejection / shutdown cases passed\n";
  }
  catch (const std::exception &error) { std::cerr << error.what() << '\n'; return 1; }
}
