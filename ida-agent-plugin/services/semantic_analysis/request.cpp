#include "request.hpp"
#include "address.hpp"
#include <set>
#include <stdexcept>

namespace ida_agent::services::semantic
{
Request ParseRequest(const nlohmann::json &params)
{
  static const std::set<std::string> fields{"callAddress", "argumentIndex", "maxNodes", "maxWork", "maxGuards"};
  if (!params.is_object() || !params.contains("callAddress") || !params["callAddress"].is_string()
      || !params.contains("argumentIndex")) throw std::invalid_argument("callAddress and argumentIndex are required");
  for (auto it = params.begin(); it != params.end(); ++it)
    if (!fields.count(it.key())) throw std::invalid_argument("unknown analysis parameter");
  Request request;
  request.call_address = rpc::ParseAddress(params["callAddress"].get<std::string>());
  auto number = [&params](const char *name, std::uint32_t fallback) {
    if (!params.contains(name)) return fallback;
    const auto &value = params[name];
    if (!value.is_number_integer() || (value.is_number_integer() && !value.is_number_unsigned() && value.get<std::int64_t>() < 0)
        || value.get<std::uint64_t>() > 100000) throw std::invalid_argument("invalid analysis bound");
    return value.get<std::uint32_t>();
  };
  request.argument_index = number("argumentIndex", 0);
  request.max_nodes = number("maxNodes", request.max_nodes);
  request.max_work = number("maxWork", request.max_work);
  request.max_guards = number("maxGuards", request.max_guards);
  if (!ValidRequest(request)) throw std::invalid_argument("analysis bound is out of range");
  return request;
}
}
