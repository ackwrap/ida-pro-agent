#import <Foundation/Foundation.h>
#import <CFNetwork/CFNetwork.h>
#import <Security/Security.h>

#include "ai/macos_url_session.hpp"
#include "ai/utf8.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <cstdlib>
#include <deque>
#include <fstream>
#include <mutex>
#include <stdexcept>

extern "C" void ida_agent_configure_macos_proxy(void *, const char *, std::uint16_t, const char *, const char *);

namespace ida_agent::ai::mac_network
{
NSString *Text(std::string_view value)
{ return [[NSString alloc] initWithBytes:value.data() length:value.size() encoding:NSUTF8StringEncoding]; }

std::string Bytes(NSData *data)
{ return data.length ? std::string(static_cast<const char *>(data.bytes), data.length) : std::string(); }

struct State
{
  std::mutex mutex;
  std::deque<MacNetworkEvent> events;
  std::size_t queued_bytes = 0;
  std::size_t max_queued_bytes = 8 * 1024 * 1024;
  bool terminal = false;
  bool sending = false;
  bool websocket = false;
  HttpProxyConfig proxy;
  __strong NSArray *anchors = nil;

  bool Push(MacNetworkEvent event)
  {
    std::lock_guard<std::mutex> lock(mutex);
    if (terminal) return false;
    // Bound the delegate backlog independently of parsed stream-event limits.
    if (events.size() >= 1023 || event.data.size() > max_queued_bytes - queued_bytes)
      event = {MacNetworkEventKind::Error, "macOS network buffer limit reached."};
    terminal = event.kind == MacNetworkEventKind::Error || event.kind == MacNetworkEventKind::Complete
        || event.kind == MacNetworkEventKind::Closed;
    queued_bytes += event.data.size();
    events.push_back(std::move(event));
    return !terminal;
  }

  void Fail(NSError *error)
  {
    Push({MacNetworkEventKind::Error,
        "macOS network transfer failed (code=" + std::to_string(error.code) + ")."});
  }
};

NSArray *LoadAnchors()
{
  const char *path = std::getenv("SSL_CERT_FILE");
  if (!path || !*path) return nil;
  if (*path != '/') throw std::runtime_error("CA file must be absolute");
  std::ifstream input(path, std::ios::binary);
  std::string pem(1024 * 1024 + 1, '\0');
  input.read(pem.data(), pem.size());
  const auto count = input.gcount();
  if (count <= 0 || count > 1024 * 1024) throw std::runtime_error("CA file unavailable");
  pem.resize(static_cast<std::size_t>(count));
  NSMutableArray *anchors = [NSMutableArray array];
  constexpr std::string_view begin = "-----BEGIN CERTIFICATE-----", end = "-----END CERTIFICATE-----";
  std::size_t cursor = 0;
  while ((cursor = pem.find(begin, cursor)) != std::string::npos)
  {
    cursor += begin.size();
    const auto finish = pem.find(end, cursor);
    if (finish == std::string::npos) throw std::runtime_error("invalid CA file");
    NSData *der = [[NSData alloc] initWithBase64EncodedString:Text(std::string_view(pem).substr(cursor, finish - cursor))
        options:NSDataBase64DecodingIgnoreUnknownCharacters];
    if (!der.length) throw std::runtime_error("invalid CA certificate");
    SecCertificateRef certificate = SecCertificateCreateWithData(nullptr, (__bridge CFDataRef)der);
    if (!certificate) throw std::runtime_error("invalid CA certificate");
    [anchors addObject:CFBridgingRelease(certificate)];
    cursor = finish + end.size();
  }
  if (!anchors.count) throw std::runtime_error("CA file contains no certificates");
  return anchors;
}

bool NativeLocalAddress(NSString *host)
{
  NSString *name = host.lowercaseString;
  if ([name hasSuffix:@"."]) name = [name substringToIndex:name.length - 1];
  if ([name isEqualToString:@"localhost"] || [name hasSuffix:@".localhost"]) return true;
  if ([name hasPrefix:@"["] && [name hasSuffix:@"]"])
    name = [name substringWithRange:NSMakeRange(1, name.length - 2)];
  name = [name componentsSeparatedByString:@"%"].firstObject;
  in_addr ipv4{};
  const auto local4 = [](std::uint32_t value) {
    return value == 0 || (value >> 24) == 127 || (value >> 16) == 0xa9fe;
  };
  if (inet_aton(name.UTF8String, &ipv4)) return local4(ntohl(ipv4.s_addr));
  in6_addr ipv6{};
  if (inet_pton(AF_INET6, name.UTF8String, &ipv6) != 1) return false;
  if (IN6_IS_ADDR_LOOPBACK(&ipv6) || IN6_IS_ADDR_LINKLOCAL(&ipv6) || IN6_IS_ADDR_UNSPECIFIED(&ipv6)) return true;
  if (!IN6_IS_ADDR_V4MAPPED(&ipv6)) return false;
  const auto *bytes = ipv6.s6_addr + 12;
  return local4((std::uint32_t(bytes[0]) << 24) | (std::uint32_t(bytes[1]) << 16)
      | (std::uint32_t(bytes[2]) << 8) | bytes[3]);
}

bool ConfigureProxy(NSURLSessionConfiguration *config, const HttpProxyConfig &proxy, NSString *host)
{
  if (proxy.mode == HttpProxyMode::System) return true;
  const bool local = NativeLocalAddress(host);
  if (proxy.mode == HttpProxyMode::Direct || (proxy.bypass_local && local))
  { config.connectionProxyDictionary = @{}; return true; }
  // URLSession implicitly bypasses proxies for local addresses, even with
  // failover disabled. Reject this unsupported route before sending any data.
  if (local) return false;
  ida_agent_configure_macos_proxy((__bridge void *)config, proxy.host.c_str(), proxy.port,
      proxy.username.c_str(), proxy.password.c_str());
  return true;
}

void Receive(NSURLSessionWebSocketTask *task, std::shared_ptr<State> state)
{
  [task receiveMessageWithCompletionHandler:^(NSURLSessionWebSocketMessage *message, NSError *error) {
    @autoreleasepool {
      if (error)
      {
        // A receive cancellation is not itself a close event. Let the native
        // close delegate publish the result of a requested local close.
        if (task.closeCode == NSURLSessionWebSocketCloseCodeInvalid) state->Fail(error);
        return;
      }
      MacNetworkEvent event;
      event.kind = message.type == NSURLSessionWebSocketMessageTypeString
          ? MacNetworkEventKind::Text : MacNetworkEventKind::Binary;
      event.data = Bytes(message.type == NSURLSessionWebSocketMessageTypeString
          ? [message.string dataUsingEncoding:NSUTF8StringEncoding] : message.data);
      if (state->Push(std::move(event))) Receive(task, state);
      else [task cancel];
    }
  }];
}
}

using namespace ida_agent::ai;
using namespace ida_agent::ai::mac_network;

@interface IDAAgentURLDelegate : NSObject <NSURLSessionDataDelegate, NSURLSessionWebSocketDelegate>
{
@public
  std::shared_ptr<State> state;
}
@end

@implementation IDAAgentURLDelegate
- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)task
    didReceiveResponse:(NSURLResponse *)response completionHandler:(void (^)(NSURLSessionResponseDisposition))handler
{
  NSHTTPURLResponse *http = [response isKindOfClass:NSHTTPURLResponse.class] ? (NSHTTPURLResponse *)response : nil;
  std::size_t size = 0;
  for (id key in http.allHeaderFields)
    size += [[key description] lengthOfBytesUsingEncoding:NSUTF8StringEncoding]
        + [[http.allHeaderFields[key] description] lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
  if (!http || http.allHeaderFields.count > 256 || size > 256 * 1024)
  {
    state->Push({MacNetworkEventKind::Error, "HTTP response headers are invalid or too large."});
    handler(NSURLSessionResponseCancel);
    return;
  }
  MacNetworkEvent event{MacNetworkEventKind::Response};
  event.status = static_cast<std::uint32_t>(http.statusCode);
  event.data = Bytes([http.MIMEType.lowercaseString dataUsingEncoding:NSUTF8StringEncoding]);
  handler(state->Push(std::move(event)) ? NSURLSessionResponseAllow : NSURLSessionResponseCancel);
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)task didReceiveData:(NSData *)data
{
  if (!state->Push({MacNetworkEventKind::Data, Bytes(data)})) [task cancel];
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task
    didSendBodyData:(int64_t)bytesSent totalBytesSent:(int64_t)totalBytesSent totalBytesExpectedToSend:(int64_t)expected
{
  MacNetworkEvent event{MacNetworkEventKind::Sent};
  event.bytes_sent = static_cast<std::uint64_t>(std::max<int64_t>(0, totalBytesSent));
  state->Push(std::move(event));
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error
{
  if (state->websocket)
  {
    auto *socket = (NSURLSessionWebSocketTask *)task;
    if (socket.closeCode != NSURLSessionWebSocketCloseCodeInvalid)
      return; // Wait for the delegate close event or the worker's close timeout.
    else if (error) state->Fail(error);
    else state->Push({MacNetworkEventKind::Error, "WebSocket closed without a close frame."});
  }
  else if (error) state->Fail(error);
  else state->Push({MacNetworkEventKind::Complete});
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task
    willPerformHTTPRedirection:(NSHTTPURLResponse *)response newRequest:(NSURLRequest *)request
    completionHandler:(void (^)(NSURLRequest *))handler
{ handler(nil); }

- (void)handleChallenge:(NSURLAuthenticationChallenge *)challenge
    completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))handler
{
  NSURLProtectionSpace *space = challenge.protectionSpace;
  if ([space.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust])
  {
    if (!state->anchors) { handler(NSURLSessionAuthChallengePerformDefaultHandling, nil); return; }
    SecTrustRef trust = space.serverTrust;
    CFErrorRef trust_error = nullptr;
    // Keep the TLS hostname/validity policies supplied by URLSession and add only
    // the caller's explicit CA certificates, without modifying any keychain.
    if (trust && SecTrustSetAnchorCertificates(trust, (__bridge CFArrayRef)state->anchors) == errSecSuccess
        && SecTrustSetAnchorCertificatesOnly(trust, false) == errSecSuccess
        && SecTrustEvaluateWithError(trust, &trust_error))
      handler(NSURLSessionAuthChallengeUseCredential, [NSURLCredential credentialForTrust:trust]);
    else
    {
      state->Push({MacNetworkEventKind::Error, "TLS certificate verification failed (code="
          + std::to_string(trust_error ? CFErrorGetCode(trust_error) : 0) + ")."});
      handler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
    }
    if (trust_error) CFRelease(trust_error);
    return;
  }
  const auto &proxy = state->proxy;
  if (space.isProxy && proxy.mode == HttpProxyMode::Http && !proxy.username.empty()
      && challenge.previousFailureCount == 0 && space.port == proxy.port
      && [space.host caseInsensitiveCompare:Text(proxy.host)] == NSOrderedSame)
    handler(NSURLSessionAuthChallengeUseCredential,
        [NSURLCredential credentialWithUser:Text(proxy.username) password:Text(proxy.password)
            persistence:NSURLCredentialPersistenceNone]);
  else handler(NSURLSessionAuthChallengeRejectProtectionSpace, nil);
}

- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
    completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))handler
{ [self handleChallenge:challenge completionHandler:handler]; }

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task
    didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
    completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))handler
{ [self handleChallenge:challenge completionHandler:handler]; }

- (void)URLSession:(NSURLSession *)session webSocketTask:(NSURLSessionWebSocketTask *)task
    didOpenWithProtocol:(NSString *)protocol
{
  MacNetworkEvent event{MacNetworkEventKind::Response};
  event.status = 101;
  if (state->Push(std::move(event))) Receive(task, state);
  else [task cancel];
}

- (void)URLSession:(NSURLSession *)session webSocketTask:(NSURLSessionWebSocketTask *)task
    didCloseWithCode:(NSURLSessionWebSocketCloseCode)code reason:(NSData *)reason
{
  MacNetworkEvent event{MacNetworkEventKind::Closed};
  event.close_code = static_cast<std::uint16_t>(code);
  state->Push(std::move(event));
}
@end

namespace ida_agent::ai
{
bool ValidMacHttpUrl(std::string_view value)
{
  if (value.empty() || !ValidUtf8(value) || value.find_first_of("#\\") != std::string_view::npos
      || std::any_of(value.begin(), value.end(), [](unsigned char c) { return c <= 0x20 || c == 0x7f; })) return false;
  @autoreleasepool {
    NSURLComponents *url = [NSURLComponents componentsWithString:Text(value)];
    NSString *scheme = url.scheme.lowercaseString;
    return url.URL && url.host.length && !url.user && !url.password
        && (!url.port || (url.port.integerValue > 0 && url.port.integerValue <= 65535))
        && ([scheme isEqualToString:@"http"] || [scheme isEqualToString:@"https"]);
  }
}

struct MacUrlSession::Impl
{
  std::shared_ptr<State> state = std::make_shared<State>();
  __strong NSURLSession *session = nil;
  __strong NSURLSessionTask *task = nil;

  Impl(const HttpRequest &request, bool websocket, std::size_t max_message_bytes)
  {
    @autoreleasepool {
      state->proxy = request.proxy;
      state->websocket = websocket;
      if (websocket) state->max_queued_bytes = std::max(state->max_queued_bytes, max_message_bytes);
      state->anchors = LoadAnchors();
      NSURL *url = [NSURL URLWithString:Text(request.url)];
      if (!url) throw std::runtime_error("invalid URL");
      NSURLSessionConfiguration *config = NSURLSessionConfiguration.ephemeralSessionConfiguration;
      config.URLCache = nil;
      config.HTTPCookieStorage = nil;
      config.URLCredentialStorage = nil;
      config.HTTPShouldSetCookies = NO;
      config.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
      if (!ConfigureProxy(config, request.proxy, url.host))
      {
        state->Push({MacNetworkEventKind::Error,
            "macOS cannot proxy this local address. Enable local bypass or use Direct mode."});
        return;
      }
      // URLSession may coalesce delegate callbacks. Its native idle timer follows
      // received network data, so a slow but active download does not time out.
      config.timeoutIntervalForRequest = request.receive_timeout_ms / 1000.0;
      config.timeoutIntervalForResource = 7 * 24 * 60 * 60;
      NSMutableURLRequest *native = [NSMutableURLRequest requestWithURL:url];
      native.HTTPMethod = request.method == HttpMethod::Post ? @"POST" : @"GET";
      native.HTTPShouldHandleCookies = NO;
      [native setValue:Text(request.user_agent) forHTTPHeaderField:@"User-Agent"];
      for (const auto &header : request.headers)
        [native addValue:Text(header.value) forHTTPHeaderField:Text(header.name)];
      if (request.method == HttpMethod::Post)
        native.HTTPBody = [NSData dataWithBytes:request.body.data() length:request.body.size()];
      IDAAgentURLDelegate *delegate = [IDAAgentURLDelegate new];
      delegate->state = state;
      NSOperationQueue *queue = [NSOperationQueue new];
      queue.maxConcurrentOperationCount = 1;
      session = [NSURLSession sessionWithConfiguration:config delegate:delegate delegateQueue:queue];
      if (websocket)
      {
        NSURLSessionWebSocketTask *socket = [session webSocketTaskWithRequest:native];
        socket.maximumMessageSize = max_message_bytes;
        task = socket;
      }
      else task = [session dataTaskWithRequest:native];
      task.prefersIncrementalDelivery = YES;
      [task resume];
    }
  }

  ~Impl()
  {
    @autoreleasepool {
      { std::lock_guard<std::mutex> lock(state->mutex); state->terminal = true; }
      [session invalidateAndCancel];
    }
  }
};

MacUrlSession::MacUrlSession(const HttpRequest &request, bool websocket, std::size_t max_message_bytes)
    : impl_(std::make_unique<Impl>(request, websocket, max_message_bytes)) {}
MacUrlSession::~MacUrlSession() = default;

std::optional<MacNetworkEvent> MacUrlSession::Poll()
{
  std::lock_guard<std::mutex> lock(impl_->state->mutex);
  if (impl_->state->events.empty()) return std::nullopt;
  auto event = std::move(impl_->state->events.front());
  impl_->state->queued_bytes -= event.data.size();
  impl_->state->events.pop_front();
  return event;
}

bool MacUrlSession::Send(bool text, const std::string &payload)
{
  const auto state = impl_->state;
  { std::lock_guard<std::mutex> lock(state->mutex);
    if (!state->websocket || state->terminal || state->sending) return false;
    state->sending = true;
  }
  @autoreleasepool {
    NSURLSessionWebSocketMessage *message = text
        ? [[NSURLSessionWebSocketMessage alloc] initWithString:Text(payload)]
        : [[NSURLSessionWebSocketMessage alloc] initWithData:[NSData dataWithBytes:payload.data() length:payload.size()]];
    NSURLSessionWebSocketTask *socket = (NSURLSessionWebSocketTask *)impl_->task;
    [socket sendMessage:message completionHandler:^(NSError *error) {
      if (error)
      {
        { std::lock_guard<std::mutex> lock(state->mutex); state->sending = false; }
        if (socket.closeCode == NSURLSessionWebSocketCloseCodeInvalid) state->Fail(error);
        return;
      }
      // URLSession's send completion can mean "buffered", even when the peer
      // is not reading. A ping queued after the message bounds that backlog:
      // keep its bytes charged and its send deadline active until the pong.
      [socket sendPingWithPongReceiveHandler:^(NSError *ping_error) {
        { std::lock_guard<std::mutex> lock(state->mutex); state->sending = false; }
        if (ping_error)
        {
          if (socket.closeCode == NSURLSessionWebSocketCloseCodeInvalid) state->Fail(ping_error);
        }
        else state->Push({MacNetworkEventKind::Sent});
      }];
    }];
  }
  return true;
}

void MacUrlSession::Close(std::uint16_t code)
{
  @autoreleasepool {
    [(NSURLSessionWebSocketTask *)impl_->task cancelWithCloseCode:
        static_cast<NSURLSessionWebSocketCloseCode>(code) reason:nil];
  }
}

void MacUrlSession::Cancel()
{
  @autoreleasepool { [impl_->task cancel]; }
}
}
