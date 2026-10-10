#include "debugger_service.hpp"
#include "debugger_internal.hpp"
#include <dbg.hpp>
#include <loader.hpp>
#include <algorithm>

namespace ida_agent::services
{
namespace
{
bool Allows(const char *action)
{
  const auto state = get_process_state();
  return DebuggerSetupStateAllows(action, state != DSTATE_NOTASK, state == DSTATE_SUSP);
}
const char *Option(const std::optional<std::string> &value)
{
  return value ? value->c_str() : nullptr;
}
}
DebuggerSetupOutcome DebuggerService::Backends() const
{
  if ( !Allows("backends") ) return {DebuggerStatus::AlreadyRunning, std::nullopt};
  const dbg_info_t *plugins = nullptr;
  const auto count = get_debugger_plugins(&plugins);
  if ( count > 256 || (count != 0 && plugins == nullptr) ) return {DebuggerStatus::OutputLimit, std::nullopt};
  auto items = nlohmann::json::array();
  for ( std::size_t i = 0; i < count; ++i )
  {
    const auto *backend = plugins[i].dbg;
    if ( backend == nullptr || backend->name == nullptr ) continue;
    items.push_back({{"name", backend->name}, {"remote", backend->is_remote()}});
  }
  return {DebuggerStatus::Success, nlohmann::json{{"items", std::move(items)},
      {"current", dbg != nullptr && dbg->name != nullptr ? dbg->name : ""}, {"remote", dbg != nullptr && dbg->is_remote()}}};
}
DebuggerActionOutcome DebuggerService::Select(const DebuggerSelectRequest &request) const
{
  if ( !Allows("select") ) return {DebuggerStatus::AlreadyRunning, std::nullopt};
  const auto available = Backends();
  if ( available.status != DebuggerStatus::Success || !available.result ) return {available.status, std::nullopt};
  bool found = false;
  for ( const auto &item : (*available.result)["items"] )
    if ( item["name"] == request.name && item["remote"] == request.remote ) found = true;
  if ( !found ) return {DebuggerStatus::NotFound, std::nullopt};
  if ( !load_debugger(request.name.c_str(), request.remote) ) return {DebuggerStatus::Failed, std::nullopt};
  if ( dbg == nullptr || dbg->name == nullptr || request.name != dbg->name || request.remote != dbg->is_remote() )
    return {DebuggerStatus::StateUncertain, std::nullopt};
  return detail::Action(true);
}
DebuggerSetupOutcome DebuggerService::Configuration() const
{
  qstring path, args, directory, host, password;
  int port = -1;
  get_process_options(&path, &args, nullptr, &directory, &host, &password, &port);
  return {DebuggerStatus::Success, nlohmann::json{{"path", path.c_str()}, {"arguments", args.c_str()},
      {"directory", directory.c_str()}, {"host", host.c_str()}, {"port", port}, {"hasPassword", !password.empty()}}};
}
DebuggerActionOutcome DebuggerService::Configure(const DebuggerConfigureRequest &request) const
{
  if ( !Allows("configure") ) return {DebuggerStatus::AlreadyRunning, std::nullopt};
  if ( !request.path && !request.arguments && !request.directory && !request.host && !request.password && !request.port )
    return {DebuggerStatus::InvalidArgument, std::nullopt};
  int port = -1;
  get_process_options(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &port);
  set_process_options(Option(request.path), Option(request.arguments), nullptr, Option(request.directory),
      Option(request.host), Option(request.password), request.port.value_or(port));
  return detail::Action(true);
}
DebuggerSetupOutcome DebuggerService::Processes(std::uint32_t limit) const
{
  if ( !detail::Available() ) return {DebuggerStatus::Unavailable, std::nullopt};
  if ( !Allows("processes") ) return {DebuggerStatus::AlreadyRunning, std::nullopt};
  if ( limit == 0 || limit > 1000 ) return {DebuggerStatus::InvalidArgument, std::nullopt};
  procinfo_vec_t processes;
  if ( get_processes(&processes) < 0 ) return {DebuggerStatus::Failed, std::nullopt};
  auto items = nlohmann::json::array();
  std::size_t bytes = 0;
  for ( const auto &process : processes )
  {
    if ( items.size() >= limit ) break;
    if ( process.pid <= 0 ) continue;
    const std::string name = process.name.c_str();
    if ( name.size() > 32768 || bytes + name.size() > 128 * 1024 ) break;
    items.push_back({{"pid", process.pid}, {"name", name}}); bytes += name.size();
  }
  return {DebuggerStatus::Success, nlohmann::json{{"total", processes.size()},
      {"truncated", items.size() < processes.size()}, {"items", std::move(items)}}};
}
DebuggerActionOutcome DebuggerService::Attach(int pid) const
{
  if ( !detail::Available() ) return {DebuggerStatus::Unavailable, std::nullopt};
  if ( !Allows("attach") ) return {DebuggerStatus::AlreadyRunning, std::nullopt};
  if ( pid <= 0 ) return {DebuggerStatus::InvalidArgument, std::nullopt};
  const int accepted = attach_process(pid, -1);
  if ( accepted == -2 ) return {DebuggerStatus::NotFound, std::nullopt};
  if ( accepted == -3 || accepted == -4 ) return {DebuggerStatus::Unavailable, std::nullopt};
  return detail::Action(accepted == 1);
}
DebuggerActionOutcome DebuggerService::Detach() const
{
  if ( !detail::Available() ) return {DebuggerStatus::Unavailable, std::nullopt};
  if ( get_process_state() == DSTATE_NOTASK ) return {DebuggerStatus::NotRunning, std::nullopt};
  if ( !Allows("detach") ) return {DebuggerStatus::NotSuspended, std::nullopt};
  return detail::Action(detach_process());
}
DebuggerActionOutcome DebuggerService::Suspend() const
{
  if ( !detail::Available() ) return {DebuggerStatus::Unavailable, std::nullopt};
  if ( get_process_state() != DSTATE_RUN ) return {DebuggerStatus::NotRunning, std::nullopt};
  return detail::Action(suspend_process());
}
} // namespace ida_agent::services
