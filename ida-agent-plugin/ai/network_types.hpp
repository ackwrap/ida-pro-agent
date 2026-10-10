#pragma once

#include <cstdint>
#include <string>

namespace ida_agent::ai
{

enum class HttpMethod
{
  Get,
  Post,
};

enum class HttpProxyMode
{
  System,
  Direct,
  Http,
};

struct HttpProxyConfig
{
  HttpProxyMode mode = HttpProxyMode::System;
  std::string host;
  std::uint16_t port = 0;
  std::string username;
  std::string password;
  bool bypass_local = true;
};

struct HttpHeader
{
  std::string name;
  std::string value;
};

} // namespace ida_agent::ai
