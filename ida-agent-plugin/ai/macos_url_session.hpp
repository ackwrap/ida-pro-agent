#pragma once

#include "ai/http_client.hpp"
#include <memory>
#include <optional>
#include <string_view>

namespace ida_agent::ai
{
bool ValidMacHttpUrl(std::string_view value);

enum class MacNetworkEventKind { Response, Data, Text, Binary, Sent, Closed, Complete, Error };

struct MacNetworkEvent
{
  MacNetworkEventKind kind = MacNetworkEventKind::Error;
  std::string data;
  std::uint32_t status = 0;
  std::uint16_t close_code = 0;
  std::uint64_t bytes_sent = 0;
};

// NSURLSession delegates retain only shared transport state, never an IDA/UI object.
// Callback delivery remains safe after Cancel and destruction of this wrapper.
class MacUrlSession final
{
public:
  MacUrlSession(const HttpRequest &request, bool websocket, std::size_t max_message_bytes = 0);
  ~MacUrlSession();
  MacUrlSession(const MacUrlSession &) = delete;
  MacUrlSession &operator=(const MacUrlSession &) = delete;
  std::optional<MacNetworkEvent> Poll();
  bool Send(bool text, const std::string &payload);
  void Close(std::uint16_t code);
  void Cancel();
private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
}
