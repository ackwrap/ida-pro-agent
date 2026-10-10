// Test-only entry point loaded in an isolated idat process. This target is
// built only with integration tests enabled and is never packaged/deployed.
// Production Pipe consent is verified independently by run_plugin_lifecycle.
#include "bridge/debugger_handlers.hpp"
#include "bridge/ida_executor.hpp"
#include "services/debugger_service.hpp"
#include <idp.hpp>
#include <loader.hpp>
#include <cstring>
#include <string>

#ifdef _WIN32
#define TEST_EXPORT __declspec(dllexport)
#else
#define TEST_EXPORT __attribute__((visibility("default")))
#endif
extern "C" TEST_EXPORT int ida_debugger_integration_call(
    const char *method, const char *params, char *output, std::size_t capacity)
{
  using namespace ida_agent;
  if ( !is_main_thread() || method == nullptr || params == nullptr || output == nullptr ) return -1;
  try
  {
    bridge::IdaExecutor executor;
    const services::DebuggerService service;
    const auto handlers = bridge::BuildDebuggerHandlers(executor, service);
    const auto found = handlers.find(method);
    if ( found == handlers.end() ) return -2;
    const rpc::Request request{std::string(rpc::ProtocolVersion), "test", "isolated-idat",
        method, nlohmann::json::parse(params), 10000};
    const auto response = found->second(request);
    nlohmann::json wire;
    if ( const auto *error = std::get_if<rpc::RpcError>(&response) )
      wire = {{"error", {{"code", rpc::ToString(error->code)}, {"message", error->message}}}};
    else wire = {{"result", std::get<nlohmann::json>(response)}};
    const std::string encoded = wire.dump();
    if ( encoded.size() + 1 > capacity ) return -3;
    std::memcpy(output, encoded.c_str(), encoded.size() + 1);
    return 0;
  }
  catch ( ... ) { return -4; }
}

plugin_t PLUGIN = {
  IDP_INTERFACE_VERSION, PLUGIN_HIDE | PLUGIN_MULTI, nullptr, nullptr, nullptr,
  "Isolated debugger integration test driver", nullptr, "IDA debugger integration test", nullptr,
};
