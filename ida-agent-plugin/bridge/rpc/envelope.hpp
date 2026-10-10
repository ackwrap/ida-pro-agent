#pragma once

#include "error.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

namespace ida_agent::rpc
{

inline constexpr std::string_view ProtocolVersion = "ida-rpc/1";
inline constexpr std::size_t MaxMessageBytes = 1U << 20;
inline constexpr std::uint32_t MinTimeoutMs = 1;
inline constexpr std::uint32_t MaxTimeoutMs = 120000;

struct Request
{
  std::string protocol_version;
  std::string request_id;
  std::string session_id;
  std::string method;
  nlohmann::json params;
  std::uint32_t timeout_ms;
};

struct Response
{
  std::string protocol_version;
  std::string request_id;
  std::string session_id;
  std::optional<nlohmann::json> result;
  std::optional<RpcError> error;
};

struct RequestCorrelation
{
  std::string request_id;
  std::string session_id;
};

Request ParseRequest(std::string_view encoded);
RequestCorrelation ParseRequestCorrelation(std::string_view encoded);
Response ParseResponse(std::string_view encoded);
std::string SerializeResponse(const Response &response);

} // namespace ida_agent::rpc
