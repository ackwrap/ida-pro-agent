#include "ai/http_client_internal.hpp"
#include "ai/macos_url_session.hpp"
#include <chrono>
#include <thread>

namespace ida_agent::ai::http_detail
{
HttpResponse ExecuteMacHttp(const HttpRequest &request, const std::function<bool()> &is_cancelled)
{
  using Clock = std::chrono::steady_clock;
  MacUrlSession session(request, false);
  auto started = Clock::now(), activity = started, send_started = started;
  bool sending = !request.body.empty(), connected = false;
  auto response = MakeResponse(HttpResponseStatus::Success, "HTTP request completed.");
  for (;;)
  {
    if (is_cancelled()) return CancelledResponse();
    if (auto event = session.Poll())
    {
      activity = Clock::now();
      if (event->kind == MacNetworkEventKind::Response)
      { response.http_status = event->status; connected = true; sending = false; }
      else if (event->kind == MacNetworkEventKind::Sent)
      {
        if (!connected) send_started = activity;
        connected = true;
        sending = event->bytes_sent < request.body.size();
      }
      else if (event->kind == MacNetworkEventKind::Data)
      {
        if (event->data.size() > request.max_response_bytes - response.body.size())
          return MakeResponse(HttpResponseStatus::ResponseTooLarge, "HTTP response exceeds the size limit.", response.http_status);
        response.body += event->data;
      }
      else if (event->kind == MacNetworkEventKind::Error)
        return MakeResponse(HttpResponseStatus::NetworkError, event->data);
      else if (event->kind == MacNetworkEventKind::Complete)
        return response.http_status ? response : NetworkError("status read");
      continue;
    }
    const auto now = Clock::now();
    if (!connected && now - started >= std::chrono::milliseconds(request.connect_timeout_ms))
      return NetworkError("connection timeout");
    if (sending && now - send_started >= std::chrono::milliseconds(request.send_timeout_ms))
      return NetworkError("send timeout");
    // The native request idle timer observes data before callback coalescing.
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
}
}
