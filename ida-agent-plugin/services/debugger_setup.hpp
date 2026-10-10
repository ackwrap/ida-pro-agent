#pragma once
#include <nlohmann/json.hpp>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace ida_agent::services
{
struct DebuggerSelectRequest { std::string name; bool remote = false; };
struct DebuggerConfigureRequest
{
  std::optional<std::string> path, arguments, directory, host, password;
  std::optional<int> port;
};

// Shared by the Pipe handlers and internal AI. Limits are UTF-8 byte limits;
// JSON schema maxLength is an additional character bound, not a replacement.
inline bool DebuggerSetupText(const nlohmann::json &value, std::size_t maximum, bool nonempty = false)
{
  if ( !value.is_string() ) return false;
  const auto &text = value.get_ref<const std::string &>();
  if ( (nonempty && text.empty()) || text.size() > maximum || text.find('\0') != std::string::npos ) return false;
  try { static_cast<void>(value.dump()); } catch ( ... ) { return false; }
  return true;
}
inline bool DebuggerSetupFields(const nlohmann::json &value, std::initializer_list<std::string_view> allowed)
{
  if ( !value.is_object() ) return false;
  for ( auto it = value.begin(); it != value.end(); ++it )
  {
    bool found = false;
    for ( const auto name : allowed ) if ( it.key() == name ) found = true;
    if ( !found ) return false;
  }
  return true;
}
inline bool DebuggerSetupInteger(const nlohmann::json &value, std::int64_t minimum, std::int64_t maximum)
{
  if ( value.is_number_unsigned() ) return value.get<std::uint64_t>() <= static_cast<std::uint64_t>(maximum)
      && (minimum <= 0 || value.get<std::uint64_t>() >= static_cast<std::uint64_t>(minimum));
  return value.is_number_integer() && value.get<std::int64_t>() >= minimum && value.get<std::int64_t>() <= maximum;
}
inline std::optional<DebuggerSelectRequest> ParseDebuggerSelect(const nlohmann::json &value)
{
  if ( !DebuggerSetupFields(value, {"name", "remote"}) || !value.contains("name")
    || !DebuggerSetupText(value["name"], 128, true)
    || (value.contains("remote") && !value["remote"].is_boolean()) ) return std::nullopt;
  return DebuggerSelectRequest{value["name"].get<std::string>(), value.value("remote", false)};
}
inline std::optional<DebuggerConfigureRequest> ParseDebuggerConfigure(const nlohmann::json &value)
{
  if ( !DebuggerSetupFields(value, {"path", "arguments", "directory", "host", "port", "password"}) || value.empty() ) return std::nullopt;
  DebuggerConfigureRequest result;
  const auto text = [&](const char *key, std::size_t maximum, std::optional<std::string> &out) {
    if ( !value.contains(key) ) return true;
    if ( !DebuggerSetupText(value[key], maximum) ) return false;
    out = value[key].get<std::string>(); return true;
  };
  if ( !text("path", 32768, result.path) || !text("arguments", 32768, result.arguments)
    || !text("directory", 32768, result.directory) || !text("host", 1024, result.host)
    || !text("password", 4096, result.password) ) return std::nullopt;
  if ( value.contains("port") )
  {
    if ( !DebuggerSetupInteger(value["port"], -1, 65535) || value["port"] == 0 ) return std::nullopt;
    result.port = value["port"].get<int>();
  }
  return result;
}
inline std::optional<int> ParseDebuggerAttach(const nlohmann::json &value)
{
  if ( !DebuggerSetupFields(value, {"pid"}) || !value.contains("pid")
    || !DebuggerSetupInteger(value["pid"], 1, 2147483647) ) return std::nullopt;
  return value["pid"].get<int>();
}
inline std::optional<std::uint32_t> ParseDebuggerProcesses(const nlohmann::json &value)
{
  if ( !DebuggerSetupFields(value, {"limit"}) ) return std::nullopt;
  if ( !value.contains("limit") ) return 100;
  if ( !DebuggerSetupInteger(value["limit"], 1, 1000) ) return std::nullopt;
  return value["limit"].get<std::uint32_t>();
}
// Kept independent of SDK constants so state requirements can be tested.
inline bool DebuggerSetupStateAllows(std::string_view action, bool active, bool suspended)
{
  if ( action == "suspend" ) return active && !suspended;
  if ( action == "detach" ) return active && suspended;
  return !active; // select/configure/process listing/attach require an idle debugger.
}
} // namespace ida_agent::services
