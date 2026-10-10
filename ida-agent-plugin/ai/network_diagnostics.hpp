#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace ida_agent::ai
{

enum class StreamKind;
struct StreamRequest;

bool AiNetworkDiagnosticsEnabled() noexcept;
bool AiNetworkRequestLoggingEnabled() noexcept;
void ConfigureAiLogging(
    bool debug_logging,
    bool network_logging) noexcept;
void LogAiNetworkDiagnostic(
    std::string_view phase,
    std::string_view detail = {},
    std::uint32_t http_status = 0,
    std::uint64_t stream_id = 0) noexcept;
void BeginAiNetworkExchangeLog(
    StreamKind kind,
    const StreamRequest &request,
    std::uint64_t stream_id) noexcept;
void LogAiNetworkResponseStatus(
    std::uint64_t stream_id,
    std::uint32_t http_status) noexcept;
void AppendAiNetworkResponseLog(
    std::uint64_t stream_id,
    std::string_view bytes) noexcept;
void EndAiNetworkExchangeLog(std::uint64_t stream_id) noexcept;
std::string SanitizeAiNetworkErrorBody(std::string_view body) noexcept;

} // namespace ida_agent::ai
