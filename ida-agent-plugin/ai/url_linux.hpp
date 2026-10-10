#pragma once
#include "ai/utf8.hpp"
#include <curl/curl.h>
#include <algorithm>
#include <memory>
#include <string>

namespace ida_agent::ai
{
inline bool ValidLinuxHttpUrl(std::string_view value)
{
  if (value.empty() || !ValidUtf8(value) || value.find_first_of("#\\") != std::string_view::npos
      || std::any_of(value.begin(), value.end(), [](unsigned char c) { return c <= 0x20 || c == 0x7f; })) return false;
  std::unique_ptr<CURLU, decltype(&curl_url_cleanup)> url(curl_url(), curl_url_cleanup);
  const std::string text(value);
  if (!url || curl_url_set(url.get(), CURLUPART_URL, text.c_str(), CURLU_DISALLOW_USER) != CURLUE_OK) return false;
  char *raw = nullptr;
  if (curl_url_get(url.get(), CURLUPART_SCHEME, &raw, 0) != CURLUE_OK) return false;
  std::unique_ptr<char, decltype(&curl_free)> scheme(raw, curl_free);
  return std::string_view(raw) == "http" || std::string_view(raw) == "https";
}
}
