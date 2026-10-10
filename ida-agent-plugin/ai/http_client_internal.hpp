#pragma once
#include "http_client.hpp"
#include <functional>
namespace ida_agent::ai::http_detail
{
std::wstring Utf8ToWide(std::string_view value);
std::wstring FormatProxyEndpoint(const HttpProxyConfig &proxy);
HttpResponse MakeResponse(HttpResponseStatus status, std::string message, std::uint32_t http_status = 0);
HttpResponse CancelledResponse();
HttpResponse NetworkError(std::string_view operation);
HttpResponse ExecuteWinHttp(const HttpRequest &request, const std::function<bool()> &is_cancelled);
HttpResponse ExecuteCurlHttp(const HttpRequest &request, const std::function<bool()> &is_cancelled);
HttpResponse ExecuteMacHttp(const HttpRequest &request, const std::function<bool()> &is_cancelled);
}
