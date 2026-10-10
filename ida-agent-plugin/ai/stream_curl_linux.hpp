#pragma once
#include "ai/stream_client.hpp"
#include <curl/curl.h>
#include <chrono>
#include <cstdlib>
#include <memory>
#include <stdexcept>

namespace ida_agent::ai::stream_client_linux_internal
{
using Clock = std::chrono::steady_clock;
template <typename T> void Set(CURL *easy, CURLoption option, T value)
{
  if (curl_easy_setopt(easy, option, value) != CURLE_OK)
    throw std::runtime_error("Stream transport option setup failed.");
}
class CurlStream final
{
public:
  explicit CurlStream(const StreamRequest &request, bool websocket = false)
  {
    struct Runtime
    {
      Runtime() : ready(curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK) {}
      ~Runtime() { if (ready) curl_global_cleanup(); }
      bool ready;
    };
    static Runtime runtime;
    if (!runtime.ready) throw std::runtime_error("Stream transport initialization failed.");
    easy.reset(curl_easy_init());
    multi.reset(curl_multi_init());
    if (!easy || !multi) throw std::bad_alloc();
    auto append = [&](const std::string &value)
    {
      auto *list = curl_slist_append(headers.get(), value.c_str());
      if (!list) throw std::bad_alloc();
      headers.release();
      headers.reset(list);
    };
    append("Expect:");
    for (const auto &header : request.headers)
      append(header.name + (header.value.empty() ? ";" : ": " + header.value));
    Set(easy.get(), CURLOPT_URL, request.url.c_str());
    Set(easy.get(), CURLOPT_PROTOCOLS_STR, websocket ? "ws,wss" : "http,https");
    Set(easy.get(), CURLOPT_USERAGENT, request.user_agent.c_str());
    Set(easy.get(), CURLOPT_HTTPHEADER, headers.get());
    Set(easy.get(), CURLOPT_NOSIGNAL, 1L);
    Set(easy.get(), CURLOPT_FOLLOWLOCATION, 0L);
    Set(easy.get(), CURLOPT_SSL_VERIFYPEER, 1L);
    Set(easy.get(), CURLOPT_SSL_VERIFYHOST, 2L);
    Set(easy.get(), CURLOPT_SUPPRESS_CONNECT_HEADERS, 1L);
    Set(easy.get(), CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(request.connect_timeout_ms));
    for (const auto &setting : {std::pair{"SSL_CERT_FILE", CURLOPT_CAINFO}, std::pair{"SSL_CERT_DIR", CURLOPT_CAPATH}})
    {
      if (const char *path = std::getenv(setting.first); path && *path)
      {
        if (*path != '/') throw std::runtime_error("Stream CA configuration is invalid.");
        Set(easy.get(), setting.second, path);
      }
    }
    if (request.method == HttpMethod::Post)
    {
      Set(easy.get(), CURLOPT_POST, 1L);
      Set(easy.get(), CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(request.body.size()));
      Set(easy.get(), CURLOPT_POSTFIELDS, request.body.data());
    }
    if (request.proxy.mode == HttpProxyMode::Direct) Set(easy.get(), CURLOPT_PROXY, "");
    else if (request.proxy.mode == HttpProxyMode::Http)
    {
      const auto &proxy = request.proxy;
      const auto endpoint = "http://" + (proxy.host.find(':') == std::string::npos ? proxy.host : "[" + proxy.host + "]")
          + ":" + std::to_string(proxy.port);
      Set(easy.get(), CURLOPT_PROXY, endpoint.c_str());
      Set(easy.get(), CURLOPT_NOPROXY, proxy.bypass_local ? "localhost,127.0.0.1,::1" : "");
      Set(easy.get(), CURLOPT_PROXYAUTH, static_cast<long>(CURLAUTH_BASIC | CURLAUTH_DIGEST | CURLAUTH_NTLM));
      Set(easy.get(), CURLOPT_PROXYUSERNAME, proxy.username.c_str());
      Set(easy.get(), CURLOPT_PROXYPASSWORD, proxy.password.c_str());
    }
  }
  ~CurlStream() { if (added) curl_multi_remove_handle(multi.get(), easy.get()); }
  void Start()
  {
    if (curl_multi_add_handle(multi.get(), easy.get()) != CURLM_OK)
      throw std::runtime_error("Stream transport start failed.");
    added = true;
  }
  // nullopt means active; the handle stays attached for CONNECT_ONLY WebSocket I/O.
  std::optional<CURLcode> Perform()
  {
    int running = 0, pending = 0;
    if (curl_multi_perform(multi.get(), &running) != CURLM_OK)
      throw std::runtime_error("Stream transport failed.");
    while (auto *message = curl_multi_info_read(multi.get(), &pending))
      if (message->msg == CURLMSG_DONE) return message->data.result;
    if (!running) throw std::runtime_error("Stream transport ended unexpectedly.");
    return std::nullopt;
  }
  void Poll()
  {
    if (curl_multi_poll(multi.get(), nullptr, 0, 50, nullptr) != CURLM_OK)
      throw std::runtime_error("Stream transport poll failed.");
  }
  std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> easy{nullptr, curl_easy_cleanup};
  std::unique_ptr<CURLM, decltype(&curl_multi_cleanup)> multi{nullptr, curl_multi_cleanup};
private:
  std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> headers{nullptr, curl_slist_free_all};
  bool added = false;
};
}
