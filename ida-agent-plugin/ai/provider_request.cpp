#include "ai/provider_request.hpp"

#include <algorithm>
#include <array>
#include <string_view>
#include <unordered_set>

namespace ida_agent::ai
{
namespace
{

std::string LowerAscii(std::string_view value)
{
  std::string lowered(value);
  std::transform(
      lowered.begin(), lowered.end(), lowered.begin(),
      [](unsigned char character)
      {
        return character >= 'A' && character <= 'Z'
            ? static_cast<char>(character - 'A' + 'a')
            : static_cast<char>(character);
      });
  return lowered;
}

void TrimSpaces(std::string &value)
{
  const std::size_t first = value.find_first_not_of(' ');
  if ( first == std::string::npos )
  {
    value.clear();
    return;
  }
  const std::size_t last = value.find_last_not_of(' ');
  value = value.substr(first, last - first + 1);
}

bool HasControlCharacter(std::string_view value)
{
  return std::any_of(
      value.begin(), value.end(),
      [](unsigned char character)
      {
        return character < 0x20 || character == 0x7f;
      });
}

bool IsHttpToken(std::string_view value)
{
  if ( value.empty() )
    return false;
  return std::all_of(
      value.begin(), value.end(),
      [](unsigned char character)
      {
        const bool alpha_numeric = (character >= 'a' && character <= 'z')
            || (character >= 'A' && character <= 'Z')
            || (character >= '0' && character <= '9');
        constexpr std::string_view punctuation = "!#$%&'*+-.^_`|~";
        return alpha_numeric
            || punctuation.find(static_cast<char>(character)) != std::string_view::npos;
      });
}

bool IsForbiddenHeader(std::string_view lowered_name)
{
  constexpr std::array<std::string_view, 5> forbidden{{
      "host", "content-length", "transfer-encoding", "connection",
      "proxy-authorization",
  }};
  return std::find(forbidden.begin(), forbidden.end(), lowered_name) != forbidden.end();
}

} // namespace

std::optional<ProviderRequestParts> BuildProviderRequestParts(
    const ProviderProfileDraft &profile,
    bool require_json_content_type)
{
  ProviderRequestParts parts;
  parts.settings = profile.settings;
  parts.proxy = profile.proxy;
  NormalizeProviderProxyDraft(parts.proxy);
  TrimSpaces(parts.settings.base_url);
  while ( !parts.settings.base_url.empty()
      && parts.settings.base_url.back() == '/' )
  {
    parts.settings.base_url.pop_back();
  }
  if ( !IsValidDraft(parts.settings)
      || !IsValidProviderProxyDraft(parts.proxy) )
  {
    return std::nullopt;
  }

  parts.user_agent = std::string(DefaultBrowserUserAgent());
  std::unordered_set<std::string> included_names;
  for ( const ProviderHeaderDraft &header : profile.custom_headers )
  {
    if ( !header.enabled
        || !IsHttpToken(header.name)
        || HasControlCharacter(header.value) )
    {
      if ( header.enabled )
        return std::nullopt;
      continue;
    }

    const std::string lowered_name = LowerAscii(header.name);
    if ( IsForbiddenHeader(lowered_name) )
      return std::nullopt;
    if ( !included_names.insert(lowered_name).second )
      continue;
    if ( lowered_name == "user-agent" )
    {
      parts.user_agent = header.value;
      continue;
    }
    parts.headers.push_back(header);
  }

  if ( parts.user_agent.empty() || HasControlCharacter(parts.user_agent) )
    return std::nullopt;

  if ( require_json_content_type )
  {
    if ( included_names.find("content-type") == included_names.end() )
    {
      included_names.insert("content-type");
      parts.headers.push_back(
          ProviderHeaderDraft{"Content-Type", "application/json", true});
    }
    else
    {
      const auto content_type = std::find_if(
          parts.headers.begin(), parts.headers.end(),
          [](const ProviderHeaderDraft &header)
          {
            return LowerAscii(header.name) == "content-type";
          });
      if ( content_type == parts.headers.end()
          || LowerAscii(content_type->value) != "application/json" )
      {
        return std::nullopt;
      }
    }
  }

  if ( parts.settings.protocol == ProviderProtocol::OpenAI )
  {
    if ( !parts.settings.api_key.empty()
        && included_names.insert("authorization").second )
    {
      parts.headers.push_back(
          ProviderHeaderDraft{
              "Authorization", "Bearer " + parts.settings.api_key, true});
    }
  }
  else if ( parts.settings.protocol == ProviderProtocol::Claude )
  {
    const bool has_auth = included_names.find("authorization") != included_names.end()
        || included_names.find("x-api-key") != included_names.end();
    if ( !parts.settings.api_key.empty() && !has_auth )
    {
      included_names.insert("x-api-key");
      parts.headers.push_back(
          ProviderHeaderDraft{"x-api-key", parts.settings.api_key, true});
    }
    if ( included_names.insert("anthropic-version").second )
    {
      parts.headers.push_back(
          ProviderHeaderDraft{"anthropic-version", "2023-06-01", true});
    }
  }
  else
  {
    return std::nullopt;
  }
  return parts;
}

std::optional<HttpProxyConfig> BuildHttpProxyConfig(
    const ProviderProxyDraft &proxy)
{
  HttpProxyConfig result;
  switch ( proxy.mode )
  {
    case ProviderProxyMode::System:
      result.mode = HttpProxyMode::System;
      break;
    case ProviderProxyMode::Direct:
      result.mode = HttpProxyMode::Direct;
      break;
    case ProviderProxyMode::Http:
      result.mode = HttpProxyMode::Http;
      break;
    default:
      return std::nullopt;
  }
  result.host = proxy.host;
  result.port = proxy.port;
  result.username = proxy.username;
  result.password = proxy.password;
  result.bypass_local = proxy.bypass_local;
  return result;
}

} // namespace ida_agent::ai
