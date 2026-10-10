#pragma once

#include "envelope.hpp"

#include <functional>
#include <string>
#include <unordered_map>
#include <variant>

namespace ida_agent::bridge
{

class Dispatcher
{
public:
  using MethodResult = std::variant<nlohmann::json, rpc::RpcError>;
  using MethodHandler = std::function<MethodResult(const rpc::Request &)>;
  using MethodHandlers = std::unordered_map<std::string, MethodHandler>;

  explicit Dispatcher(std::string session_id, MethodHandlers handlers = {});
  rpc::Response Dispatch(const rpc::Request &request) const;

private:
  std::string session_id_;
  MethodHandlers handlers_;
};

} // namespace ida_agent::bridge
