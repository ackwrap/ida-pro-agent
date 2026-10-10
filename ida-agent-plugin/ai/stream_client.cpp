#include "ai/stream_client.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <string_view>

namespace ida_agent::ai
{
namespace
{

std::string LowerAscii(std::string_view value)
{
  std::string lowered(value);
  std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char character)
  {
    return character >= 'A' && character <= 'Z'
        ? static_cast<char>(character - 'A' + 'a')
        : static_cast<char>(character);
  });
  return lowered;
}

bool HasControlCharacter(std::string_view value)
{
  return std::any_of(value.begin(), value.end(), [](unsigned char character)
  {
    return character < 0x20 || character == 0x7f;
  });
}

bool HasWhitespace(std::string_view value)
{
  return std::any_of(value.begin(), value.end(), [](unsigned char character)
  {
    return character == ' ' || character == '\t' || character == '\n'
        || character == '\r' || character == '\f' || character == '\v';
  });
}

bool IsValidUtf8(std::string_view value)
{
  std::size_t index = 0;
  while ( index < value.size() )
  {
    const unsigned char first = static_cast<unsigned char>(value[index]);
    if ( first <= 0x7f )
    {
      ++index;
      continue;
    }
    std::size_t continuation_count = 0;
    std::uint32_t code_point = 0;
    if ( first >= 0xc2 && first <= 0xdf )
    {
      continuation_count = 1;
      code_point = first & 0x1f;
    }
    else if ( first >= 0xe0 && first <= 0xef )
    {
      continuation_count = 2;
      code_point = first & 0x0f;
    }
    else if ( first >= 0xf0 && first <= 0xf4 )
    {
      continuation_count = 3;
      code_point = first & 0x07;
    }
    else
    {
      return false;
    }
    if ( continuation_count > value.size() - index - 1 )
      return false;
    for ( std::size_t offset = 1; offset <= continuation_count; ++offset )
    {
      const unsigned char continuation = static_cast<unsigned char>(value[index + offset]);
      if ( (continuation & 0xc0) != 0x80 )
        return false;
      code_point = (code_point << 6) | (continuation & 0x3f);
    }
    if ( (continuation_count == 2 && code_point < 0x800)
        || (continuation_count == 3 && code_point < 0x10000)
        || (code_point >= 0xd800 && code_point <= 0xdfff)
        || code_point > 0x10ffff )
    {
      return false;
    }
    index += continuation_count + 1;
  }
  return true;
}

bool IsValidPort(std::string_view value)
{
  if ( value.empty() || value.size() > 5 )
    return false;
  unsigned port = 0;
  for ( const char character : value )
  {
    if ( character < '0' || character > '9' )
      return false;
    port = port * 10 + static_cast<unsigned>(character - '0');
  }
  return port != 0 && port <= 65535;
}

bool IsHttpToken(std::string_view value)
{
  if ( value.empty() )
    return false;
  return std::all_of(value.begin(), value.end(), [](unsigned char character)
  {
    const bool alpha_numeric = (character >= 'a' && character <= 'z')
        || (character >= 'A' && character <= 'Z')
        || (character >= '0' && character <= '9');
    constexpr std::string_view punctuation = "!#$%&'*+-.^_`|~";
    return alpha_numeric
        || punctuation.find(static_cast<char>(character)) != std::string_view::npos;
  });
}

bool IsForbiddenHeader(std::string_view name)
{
  const std::string lowered = LowerAscii(name);
  constexpr std::array<std::string_view, 7> exact{{
      "host",
      "content-length",
      "transfer-encoding",
      "connection",
      "upgrade",
      "proxy-authorization",
      "sec-websocket-key",
  }};
  return std::find(exact.begin(), exact.end(), lowered) != exact.end()
      || lowered.rfind("sec-websocket-", 0) == 0;
}

bool IsValidProxyHost(std::string_view host)
{
  return !host.empty() && !HasControlCharacter(host) && !HasWhitespace(host)
      && host.find('/') == std::string_view::npos
      && host.find('\\') == std::string_view::npos
      && host.find('@') == std::string_view::npos
      && host.find('[') == std::string_view::npos
      && host.find(']') == std::string_view::npos;
}

struct ParsedUrl
{
  std::string scheme;
  std::string host;
};

std::optional<ParsedUrl> ParseUrl(std::string_view url)
{
  if ( url.empty() || url.find('#') != std::string_view::npos
      || HasControlCharacter(url) || HasWhitespace(url) || !IsValidUtf8(url) )
  {
    return std::nullopt;
  }
  const std::size_t separator = url.find("://");
  if ( separator == std::string_view::npos || separator == 0 )
    return std::nullopt;
  ParsedUrl parsed;
  parsed.scheme = LowerAscii(url.substr(0, separator));
  const std::size_t authority_start = separator + 3;
  const std::size_t authority_end = url.find_first_of("/?", authority_start);
  const std::string_view authority = url.substr(
      authority_start,
      authority_end == std::string_view::npos
          ? url.size() - authority_start
          : authority_end - authority_start);
  if ( authority.empty() || authority.find('@') != std::string_view::npos )
    return std::nullopt;
  if ( authority.front() == '[' )
  {
    const std::size_t closing = authority.find(']');
    if ( closing == std::string_view::npos || closing == 1 )
      return std::nullopt;
    if ( closing + 1 < authority.size()
        && (authority[closing + 1] != ':'
            || !IsValidPort(authority.substr(closing + 2))) )
    {
      return std::nullopt;
    }
    parsed.host = LowerAscii(authority.substr(1, closing - 1));
  }
  else
  {
    const std::size_t colon = authority.rfind(':');
    const std::string_view host = colon == std::string_view::npos
        ? authority
        : authority.substr(0, colon);
    if ( host.empty() || host.find(':') != std::string_view::npos
        || (colon != std::string_view::npos
            && !IsValidPort(authority.substr(colon + 1))) )
    {
      return std::nullopt;
    }
    parsed.host = LowerAscii(host);
  }
  return parsed;
}

} // namespace

std::optional<std::string> ValidateStreamRequest(
    StreamKind kind,
    const StreamRequest &request)
{
  if ( kind != StreamKind::Sse && kind != StreamKind::WebSocket )
    return "Stream kind is invalid.";
  if ( request.method != HttpMethod::Get && request.method != HttpMethod::Post )
    return "Stream request method is invalid.";
  if ( request.method == HttpMethod::Get && !request.body.empty() )
    return "Stream GET request body is invalid.";
  if ( kind == StreamKind::WebSocket
      && (request.method != HttpMethod::Get || !request.body.empty()) )
  {
    return "WebSocket request method is invalid.";
  }
  if ( request.body.size() > StreamHardMaxPayloadBytes )
    return "Stream request body is too large.";
  if ( request.user_agent.empty() || HasControlCharacter(request.user_agent)
      || !IsValidUtf8(request.user_agent) )
    return "Stream request user agent is invalid.";

  const std::optional<ParsedUrl> parsed = ParseUrl(request.url);
  if ( !parsed.has_value() )
    return "Stream request URL is invalid.";
  const bool valid_scheme = kind == StreamKind::Sse
      ? parsed->scheme == "http" || parsed->scheme == "https"
      : parsed->scheme == "ws" || parsed->scheme == "wss";
  if ( !valid_scheme )
    return "Stream request URL scheme is invalid.";
  if ( request.headers.size() > StreamHardMaxHeaders )
    return "Stream request has too many headers.";
  std::size_t header_bytes = 0;
  for ( const HttpHeader &header : request.headers )
  {
    if ( header.name.size() > StreamHardMaxHeaderNameBytes
        || header.value.size() > StreamHardMaxHeaderValueBytes
        || header.name.size() + header.value.size()
            > StreamHardMaxHeaderBytes - (std::min)(
                StreamHardMaxHeaderBytes,
                header_bytes)
        || !IsHttpToken(header.name) || IsForbiddenHeader(header.name)
        || HasControlCharacter(header.value) || !IsValidUtf8(header.value) )
    {
      return "Stream request headers are invalid.";
    }
    header_bytes += header.name.size() + header.value.size();
  }

  constexpr std::uint32_t MaxTimeoutMs = static_cast<std::uint32_t>((std::numeric_limits<int>::max)());
  if ( request.connect_timeout_ms == 0 || request.send_timeout_ms == 0
      || request.idle_timeout_ms == 0
      || request.connect_timeout_ms > MaxTimeoutMs
      || request.send_timeout_ms > MaxTimeoutMs
      || request.idle_timeout_ms > MaxTimeoutMs
      || (request.overall_timeout_ms.has_value()
          && (*request.overall_timeout_ms == 0
              || *request.overall_timeout_ms > MaxTimeoutMs)) )
  {
    return "Stream request timeout is invalid.";
  }
  if ( request.max_event_bytes == 0
      || request.max_event_bytes > StreamHardMaxPayloadBytes
      || request.max_message_bytes == 0
      || request.max_message_bytes > StreamHardMaxPayloadBytes
      || request.max_queued_bytes == 0
      || request.max_queued_bytes > StreamHardMaxQueuedBytes
      || (kind == StreamKind::Sse && request.max_queued_bytes < request.max_event_bytes)
      || (kind == StreamKind::WebSocket && request.max_queued_bytes < request.max_message_bytes) )
  {
    return "Stream size limit is invalid.";
  }

  if ( request.proxy.mode == HttpProxyMode::System
      || request.proxy.mode == HttpProxyMode::Direct )
  {
    if ( !request.proxy.host.empty() || request.proxy.port != 0
        || !request.proxy.username.empty() || !request.proxy.password.empty() )
    {
      return "Stream proxy configuration is invalid.";
    }
  }
  else if ( request.proxy.mode == HttpProxyMode::Http )
  {
    if ( !IsValidProxyHost(request.proxy.host) || !IsValidUtf8(request.proxy.host)
        || request.proxy.port == 0
        || (!request.proxy.password.empty() && request.proxy.username.empty())
        || HasControlCharacter(request.proxy.username)
        || HasControlCharacter(request.proxy.password)
        || !IsValidUtf8(request.proxy.username)
        || !IsValidUtf8(request.proxy.password) )
    {
      return "Stream proxy configuration is invalid.";
    }
  }
  else
  {
    return "Stream proxy configuration is invalid.";
  }

  return std::nullopt;
}

} // namespace ida_agent::ai
