#include "ai/http_client_internal.hpp"
#include <curl/curl.h>
#include <chrono>
#include <cstdlib>
#include <limits>
#include <memory>
#include <stdexcept>

namespace ida_agent::ai::http_detail
{
namespace
{
using Clock = std::chrono::steady_clock;
class CurlRuntime
{
public:
  CurlRuntime() : ready(curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK) {}
  ~CurlRuntime() { if (ready) curl_global_cleanup(); }
  const bool ready;
};
template <typename T> void Set(CURL *easy, CURLoption option, T value)
{
  if (curl_easy_setopt(easy, option, value) != CURLE_OK)
    throw std::runtime_error("HTTP transport option setup failed");
}
struct Transfer
{
  explicit Transfer(const HttpRequest &value) : request(value) {}
  const HttpRequest &request;
  std::string body;
  std::size_t header_bytes = 0;
  bool too_large = false;
  bool upload_complete = false;
  curl_off_t uploaded = 0;
  Clock::time_point last_receive = Clock::now();
  Clock::time_point send_started{};
};
std::size_t Write(char *data, std::size_t size, std::size_t count, void *context) noexcept
{
  auto &transfer = *static_cast<Transfer *>(context);
  try
  {
    if (size && count > std::numeric_limits<std::size_t>::max() / size) return 0;
    const auto bytes = size * count;
    if (bytes > transfer.request.max_response_bytes - transfer.body.size())
    {
      transfer.too_large = true;
      return 0;
    }
    transfer.body.append(data, bytes);
    transfer.last_receive = Clock::now();
    return bytes;
  }
  catch (...) { return 0; }
}
std::size_t Header(char *, std::size_t size, std::size_t count, void *context) noexcept
{
  auto &transfer = *static_cast<Transfer *>(context);
  if (size && count > std::numeric_limits<std::size_t>::max() / size) return 0;
  const auto bytes = size * count;
  if (bytes > 256 * 1024 - transfer.header_bytes) return 0;
  transfer.header_bytes += bytes;
  transfer.last_receive = Clock::now();
  return bytes;
}
int Progress(void *context, curl_off_t, curl_off_t, curl_off_t, curl_off_t uploaded) noexcept
{
  static_cast<Transfer *>(context)->uploaded = uploaded;
  return 0;
}
}

HttpResponse ExecuteCurlHttp(const HttpRequest &request, const std::function<bool()> &is_cancelled)
{
  if (is_cancelled()) return CancelledResponse();
  static CurlRuntime runtime;
  if (!runtime.ready) return NetworkError("initialization");
  // Asynchronous DNS is required so cancellation cannot get stuck in a resolver call.
  if (!(curl_version_info(CURLVERSION_NOW)->features & CURL_VERSION_ASYNCHDNS))
    return NetworkError("asynchronous DNS initialization");
  std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> easy(curl_easy_init(), curl_easy_cleanup);
  std::unique_ptr<CURLM, decltype(&curl_multi_cleanup)> multi(curl_multi_init(), curl_multi_cleanup);
  std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> headers(nullptr, curl_slist_free_all);
  if (!easy || !multi) return NetworkError("initialization");
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
  Transfer transfer(request);
  Set(easy.get(), CURLOPT_URL, request.url.c_str());
  Set(easy.get(), CURLOPT_USERAGENT, request.user_agent.c_str());
  Set(easy.get(), CURLOPT_HTTPHEADER, headers.get());
  Set(easy.get(), CURLOPT_NOSIGNAL, 1L);
  Set(easy.get(), CURLOPT_FOLLOWLOCATION, 0L);
  Set(easy.get(), CURLOPT_SSL_VERIFYPEER, 1L);
  Set(easy.get(), CURLOPT_SSL_VERIFYHOST, 2L);
  // Respect explicit Linux CA locations without weakening peer/host verification.
  for (const auto &setting : {std::pair{"SSL_CERT_FILE", CURLOPT_CAINFO}, std::pair{"SSL_CERT_DIR", CURLOPT_CAPATH}})
  {
    if (const char *path = std::getenv(setting.first); path && *path)
    {
      if (*path != '/') return NetworkError("CA configuration");
      Set(easy.get(), setting.second, path);
    }
  }
  // The embedded libcurl omits netrc support entirely.
  Set(easy.get(), CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(request.connect_timeout_ms));
  Set(easy.get(), CURLOPT_WRITEFUNCTION, &Write);
  Set(easy.get(), CURLOPT_WRITEDATA, &transfer);
  Set(easy.get(), CURLOPT_HEADERFUNCTION, &Header);
  Set(easy.get(), CURLOPT_HEADERDATA, &transfer);
  Set(easy.get(), CURLOPT_NOPROGRESS, 0L);
  Set(easy.get(), CURLOPT_XFERINFOFUNCTION, &Progress);
  Set(easy.get(), CURLOPT_XFERINFODATA, &transfer);
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
  if (curl_multi_add_handle(multi.get(), easy.get()) != CURLM_OK) return NetworkError("initialization");
  struct Remove
  {
    CURLM *multi; CURL *easy;
    ~Remove() { curl_multi_remove_handle(multi, easy); }
  } remove{multi.get(), easy.get()};
  while (true)
  {
    if (is_cancelled()) return CancelledResponse();
    int running = 0;
    if (curl_multi_perform(multi.get(), &running) != CURLM_OK) return NetworkError("transfer");
    int pending;
    while (auto *message = curl_multi_info_read(multi.get(), &pending))
    {
      if (message->msg != CURLMSG_DONE) continue;
      long status = 0;
      const auto status_result = curl_easy_getinfo(easy.get(), CURLINFO_RESPONSE_CODE, &status);
      if (transfer.too_large) return MakeResponse(HttpResponseStatus::ResponseTooLarge,
          "HTTP response exceeds the size limit.", static_cast<std::uint32_t>(status));
      if (message->data.result != CURLE_OK) return NetworkError("transfer");
      if (status_result != CURLE_OK || status == 0)
        return NetworkError("status read");
      auto response = MakeResponse(HttpResponseStatus::Success, "HTTP request completed.", static_cast<std::uint32_t>(status));
      response.body = std::move(transfer.body);
      return response;
    }
    curl_off_t pretransfer = 0;
    curl_easy_getinfo(easy.get(), CURLINFO_PRETRANSFER_TIME_T, &pretransfer);
    const auto now = Clock::now();
    if (pretransfer > 0)
    {
      if (transfer.send_started == Clock::time_point{}) transfer.send_started = now;
      if (!transfer.upload_complete && transfer.uploaded >= static_cast<curl_off_t>(request.body.size()))
      {
        transfer.upload_complete = true;
        transfer.last_receive = now;
      }
      if (transfer.upload_complete)
      {
        if (now - transfer.last_receive >= std::chrono::milliseconds(request.receive_timeout_ms))
          return NetworkError("receive timeout");
      }
      else if (now - transfer.send_started >= std::chrono::milliseconds(request.send_timeout_ms))
        return NetworkError("send timeout");
    }
    if (!running) return NetworkError("transfer completion");
    // A short bounded poll keeps Cancel/CancelAndForget/Shutdown responsive.
    if (curl_multi_poll(multi.get(), nullptr, 0, 50, nullptr) != CURLM_OK) return NetworkError("poll");
  }
}
}
