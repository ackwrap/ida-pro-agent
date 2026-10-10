#if IDA_AGENT_ENABLE_AI
#include "ai/ai_menu.hpp"
#include "ai/agent_tool_registry.hpp"
#include "ai/agent_effect_service.hpp"
#include "ai/agent_file_service.hpp"
#endif
#include "bridge/bridge.hpp"
#include "bridge/ida_executor.hpp"
#include "bridge/changeset_handlers.hpp"
#include "bridge/debugger_handlers.hpp"
#include "bridge/debugger_consent.hpp"
#include "bridge/read_handlers.hpp"
#include "bridge/readonly_analysis_handlers.hpp"
#include "bridge/source_info_handlers.hpp"
#include "bridge/annotation_handlers.hpp"
#include "bridge/symbol_handlers.hpp"
#include "bridge/decompiler_inspection_handlers.hpp"
#include "bridge/semantic_analysis_handlers.hpp"
#include "bridge/script_handlers.hpp"
#include "bridge/workflow_handlers.hpp"
#include "services/database_service.hpp"
#include "services/changeset_service.hpp"
#include "services/decompiler_service.hpp"
#include "services/debugger_service.hpp"
#include "services/function_service.hpp"
#include "services/memory_service.hpp"
#include "services/readonly_analysis_service.hpp"
#include "services/source_info_service.hpp"
#include "services/annotation_service.hpp"
#include "services/decompiler_inspection_service.hpp"
#include "services/semantic_analysis/service.hpp"
#include "services/search_service.hpp"
#include "services/script_service.hpp"
#include "services/string_service.hpp"
#include "services/symbol_service.hpp"
#include "services/type_service.hpp"
#include "services/xref_service.hpp"

#include <ida.hpp>
#include <idp.hpp>
#include <hexrays.hpp>
#include <dbg.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <nalt.hpp>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

extern plugin_t PLUGIN;

namespace
{

class IdaAgentPlugin final : public plugmod_t
{
public:
  IdaAgentPlugin()
#if IDA_AGENT_ENABLE_AI
      : file_service_([this]()
        {
          return executor_.ReadFor(std::chrono::seconds(12), []()
          {
            const char *path = get_path(PATH_TYPE_IDB);
            return path == nullptr ? std::string() : std::string(path);
          });
        }),
        agent_tools_(
            executor_,
            symbol_service_,
            string_service_,
            function_service_,
            decompiler_service_,
            xref_service_,
            memory_service_,
            database_service_,
            readonly_analysis_service_,
            search_service_,
            type_service_,
            source_info_service_,
            annotation_service_,
            decompiler_inspection_service_,
            semantic_analysis_service_,
            debugger_service_,
            changeset_service_,
            file_service_),
        agent_effects_(
            executor_,
            changeset_service_,
            database_service_,
            readonly_analysis_service_,
            debugger_service_,
            script_service_,
            file_service_),
        ai_menu_(&PLUGIN, agent_tools_, agent_effects_),
        listener_(*this)
#else
      : listener_(*this)
#endif
  {
    InitializeShutdownLog();
    TraceShutdown("plugin.construct.begin");
#if IDA_AGENT_ENABLE_AI
    ai_menu_.SetLifecycleTrace(
        [this](const char *phase) { TraceShutdown(phase); });
    ai_menu_.Start();
#endif
    if ( !hook_event_listener(HT_UI, &listener_) )
      throw std::runtime_error("failed to register IDA UI listener");
    TraceShutdown("plugin.construct.end");
  }

  ~IdaAgentPlugin() override
  {
    close_in_progress_ = true;
    TraceShutdown("plugin.destruct.begin");
    ::unhook_event_listener(HT_UI, &listener_);
    TraceShutdown("plugin.destruct.ai.stop.begin");
#if IDA_AGENT_ENABLE_AI
    ai_menu_.Stop();
#endif
    TraceShutdown("plugin.destruct.ai.stop.end");
    StopBridge();
    if ( decompiler_available_ )
    {
      TraceShutdown("plugin.destruct.hexrays.term.begin");
      term_hexrays_plugin();
      TraceShutdown("plugin.destruct.hexrays.term.end");
    }
    TraceShutdown("plugin.destruct.end");
#ifdef _WIN32
    if ( shutdown_log_ != INVALID_HANDLE_VALUE )
    {
      CloseHandle(shutdown_log_);
      shutdown_log_ = INVALID_HANDLE_VALUE;
    }
#endif
  }

  bool idaapi run(size_t) override
  {
    if ( !bridge_.Running() && !StartBridge() )
      return false;
#if IDA_AGENT_ENABLE_AI
    if ( is_idaq() )
      ai_menu_.ShowProviderSettings();
#endif
    msg("[ida-agent] plugin is active\n");
    return true;
  }

private:
  void SetAgentAvailable(bool available) noexcept
  {
#if IDA_AGENT_ENABLE_AI
    agent_tools_.SetAvailable(available);
#else
    static_cast<void>(available);
#endif
  }

  class DatabaseListener final : public event_listener_t
  {
  public:
    explicit DatabaseListener(IdaAgentPlugin &plugin) : plugin_(plugin) {}

    ssize_t idaapi on_event(ssize_t code, va_list args) override
    {
      if ( code == ui_preprocess_action )
      {
        const char *name = va_arg(args, const char *);
        if ( name != nullptr
            && (std::string_view(name) == "CloseBase"
                || std::string_view(name) == "QuitIDA") )
        {
          plugin_.close_in_progress_ = true;
          plugin_.TraceShutdown(
              std::string("ui.preprocess_action.") + name);
        }
      }
      else if ( code == ui_about_to_exit )
      {
        plugin_.close_in_progress_ = true;
        plugin_.TraceShutdown("ui.about_to_exit");
        plugin_.TraceShutdown("ui.about_to_exit.ai.stop.begin");
#if IDA_AGENT_ENABLE_AI
        plugin_.ai_menu_.Stop(false);
#endif
        plugin_.TraceShutdown("ui.about_to_exit.ai.stop.end");
      }
      else if ( code == ui_saving )
      {
        plugin_.TraceShutdown("ui.saving");
      }
      else if ( code == ui_saved )
      {
        plugin_.TraceShutdown("ui.saved");
      }
      else if ( code == ui_ready_to_run )
      {
#if IDA_AGENT_ENABLE_AI
        plugin_.ai_menu_.UiReady();
#endif
      }
      else if ( code == ui_database_inited )
      {
        plugin_.changeset_service_.Reset();
#if IDA_AGENT_ENABLE_AI
        plugin_.ai_menu_.DatabaseInitialized();
#endif
        plugin_.StartBridge();
      }
      else if ( code == ui_database_closed )
      {
        plugin_.close_in_progress_ = true;
        plugin_.TraceShutdown("ui.database_closed.begin");
        plugin_.TraceShutdown("ui.database_closed.ai.stop.begin");
#if IDA_AGENT_ENABLE_AI
        plugin_.ai_menu_.Stop();
#endif
        plugin_.TraceShutdown("ui.database_closed.ai.stop.end");
        plugin_.StopBridge();
        plugin_.TraceShutdown("ui.database_closed.changeset_reset.begin");
        plugin_.changeset_service_.Reset();
        plugin_.TraceShutdown("ui.database_closed.end");
      }
      return 0;
    }

  private:
    IdaAgentPlugin &plugin_;
  };

  bool StartBridge() noexcept
  {
    SetAgentAvailable(false);
    if ( bridge_.Running() )
    {
      SetAgentAvailable(true);
      return true;
    }
    executor_.Shutdown();
    bridge_.Stop();
    executor_.Start();
    try
    {
      const ida_agent::bridge::DatabaseMetadata metadata = executor_.Read([]()
      {
        const char *database_path = get_path(PATH_TYPE_IDB);
        char input_file[QMAXPATH]{};
        if ( get_root_filename(input_file, sizeof(input_file)) <= 0 )
          ::qstrncpy(input_file, "untitled", sizeof(input_file));
        char ida_version[64]{};
        if ( get_kernel_version(ida_version, sizeof(ida_version)) <= 0 )
          throw std::runtime_error("IDA version is unavailable");
        const qstring processor = inf_get_procname();
        if ( processor.empty() )
          throw std::runtime_error("processor is unavailable");
        const std::uint32_t address_bits = inf_get_app_bitness();
        return ida_agent::bridge::DatabaseMetadata{
            database_path,
            input_file,
            ida_version,
            processor.c_str(),
            ida_agent::services::ArchitectureName(processor.c_str(), address_bits),
            static_cast<std::uint8_t>(address_bits),
            false,
            dbg != nullptr,
            false,
        };
      });
      if ( !decompiler_checked_ )
      {
        decompiler_available_ = executor_.Read([]() { return init_hexrays_plugin(0); });
        decompiler_checked_ = true;
        decompiler_service_.SetAvailable(decompiler_available_);
        decompiler_inspection_service_.SetDecompilerAvailable(decompiler_available_);
        semantic_analysis_service_.SetDecompilerAvailable(decompiler_available_);
        changeset_service_.SetDecompilerAvailable(decompiler_available_);
      }
      ida_agent::bridge::DatabaseMetadata effective_metadata = metadata;
      effective_metadata.decompiler = decompiler_available_;
      auto handlers = ida_agent::bridge::BuildReadHandlers(
          executor_,
          database_service_,
          function_service_,
          xref_service_,
          memory_service_,
          decompiler_service_,
          search_service_,
          string_service_,
          symbol_service_,
          type_service_);
      auto changeset_handlers = ida_agent::bridge::BuildChangeSetHandlers(executor_, changeset_service_);
      handlers.merge(changeset_handlers);
      auto readonly_analysis_handlers = ida_agent::bridge::BuildReadonlyAnalysisHandlers(
          executor_, readonly_analysis_service_);
      handlers.merge(readonly_analysis_handlers);
      handlers.merge(ida_agent::bridge::BuildSourceInfoHandlers(executor_, source_info_service_));
      handlers.merge(ida_agent::bridge::BuildAnnotationHandlers(executor_, annotation_service_));
      handlers.merge(ida_agent::bridge::BuildSymbolHandlers(executor_, symbol_service_));
      handlers.merge(ida_agent::bridge::BuildDecompilerInspectionHandlers(executor_, decompiler_inspection_service_));
      auto semantic_handlers = ida_agent::bridge::BuildSemanticAnalysisHandlers(executor_, semantic_analysis_service_);
      handlers.merge(semantic_handlers);
      auto debugger_handlers = ida_agent::bridge::BuildDebuggerHandlers(executor_, debugger_service_);
      handlers.merge(debugger_handlers);
      auto script_handlers = ida_agent::bridge::BuildScriptHandlers(executor_, script_service_);
      handlers.merge(script_handlers);
      auto workflow_handlers = ida_agent::bridge::BuildWorkflowHandlers(
          executor_, database_service_, decompiler_service_, changeset_service_);
      handlers.merge(workflow_handlers);
      ida_agent::bridge::AddDebuggerConsent(handlers, executor_);
      std::vector<std::string> method_names;
      method_names.reserve(handlers.size() + 2);
      for ( const auto &handler : handlers )
        method_names.push_back(handler.first);
      method_names.push_back("system.methods");
      std::sort(method_names.begin(), method_names.end());
      handlers.emplace(
          "system.methods",
          [method_names = std::move(method_names)](const ida_agent::rpc::Request &request)
              -> ida_agent::bridge::Dispatcher::MethodResult
          {
            if ( !request.params.empty() )
            {
              return ida_agent::rpc::RpcError{
                  ida_agent::rpc::ErrorCode::InvalidArgument,
                  "system.methods params must be empty",
                  false,
              };
            }
            return nlohmann::json{{"methods", method_names}};
          });
      const ida_agent::rpc::Capabilities initial_capabilities{
          effective_metadata.decompiler, effective_metadata.debugger,
          effective_metadata.ui, effective_metadata.address_bits};
      bridge_.Start(
          std::move(effective_metadata),
          std::move(handlers),
          [this]()
          {
            SetAgentAvailable(false);
            executor_.Shutdown();
          }, {}, [this, initial_capabilities](std::uint32_t timeout)
          {
            return executor_.UiFor(std::chrono::milliseconds(timeout), [initial_capabilities]()
            {
              auto current = initial_capabilities;
              current.debugger = dbg != nullptr;
              return current;
            });
          });
      SetAgentAvailable(true);
      msg("[ida-agent] plugin loaded; endpoint=%s\n", bridge_.EndpointAddress().c_str());
      return true;
    }
    catch ( const std::exception &error )
    {
      SetAgentAvailable(false);
      executor_.Shutdown();
      msg("[ida-agent] plugin startup failed\n");
      if ( qgetenv("IDA_AGENT_TEST_DIAGNOSTICS", nullptr) )
        msg("[ida-agent-test] startup error: %s\n", error.what());
      return false;
    }
  }

  void StopBridge() noexcept
  {
    SetAgentAvailable(false);
    const bool was_running = bridge_.Running();
    const auto started_at = std::chrono::steady_clock::now();
    if ( close_in_progress_ )
      TraceShutdown("bridge.executor.shutdown.begin");
    executor_.Shutdown();
    const auto executor_stopped_at = std::chrono::steady_clock::now();
    if ( close_in_progress_ )
      TraceShutdown("bridge.executor.shutdown.end");
    if ( close_in_progress_ )
      TraceShutdown("bridge.stop.begin");
    if ( close_in_progress_ )
      bridge_.Stop([this](const char *phase) { TraceShutdown(phase); });
    else
      bridge_.Stop();
    const auto bridge_stopped_at = std::chrono::steady_clock::now();
    if ( close_in_progress_ )
      TraceShutdown("bridge.stop.end");
    const auto total = std::chrono::duration_cast<std::chrono::milliseconds>(
        bridge_stopped_at - started_at);
    if ( total > std::chrono::milliseconds(100) )
    {
      const auto executor = std::chrono::duration_cast<std::chrono::milliseconds>(
          executor_stopped_at - started_at);
      const auto bridge = std::chrono::duration_cast<std::chrono::milliseconds>(
          bridge_stopped_at - executor_stopped_at);
      msg(
          "[ida-agent] slow Bridge shutdown: executor=%lldms bridge=%lldms total=%lldms\n",
          static_cast<long long>(executor.count()),
          static_cast<long long>(bridge.count()),
          static_cast<long long>(total.count()));
    }
    if ( was_running )
      msg("[ida-agent] plugin unloaded\n");
  }

  void InitializeShutdownLog() noexcept
  {
#ifdef _WIN32
    try
    {
      const wchar_t *local_app_data = _wgetenv(L"LOCALAPPDATA");
      if ( local_app_data == nullptr || *local_app_data == L'\0' )
        return;
      const std::filesystem::path directory =
          std::filesystem::path(local_app_data) / L"ida-agent" / L"diagnostics";
      std::filesystem::create_directories(directory);
      const HANDLE file = CreateFileW(
          (directory / L"shutdown.log").c_str(),
          FILE_APPEND_DATA,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
          nullptr,
          OPEN_ALWAYS,
          FILE_ATTRIBUTE_NORMAL,
          nullptr);
      if ( file == INVALID_HANDLE_VALUE )
        return;
      shutdown_log_ = file;
    }
    catch ( ... )
    {
    }
#endif
  }

  void TraceShutdown(std::string_view phase) noexcept
  {
#ifdef _WIN32
    if ( shutdown_log_ == INVALID_HANDLE_VALUE )
      return;
    const auto wall_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - plugin_started_at_).count();
    const std::string line = std::to_string(wall_ms)
        + " elapsed=" + std::to_string(elapsed_ms) + "ms "
        + std::string(phase) + "\r\n";
    DWORD written = 0;
    WriteFile(
        shutdown_log_,
        line.data(),
        static_cast<DWORD>(line.size()),
        &written,
        nullptr);
#else
    msg("[ida-agent] %.*s\n", static_cast<int>(phase.size()), phase.data());
#endif
  }

  const std::chrono::steady_clock::time_point plugin_started_at_ =
      std::chrono::steady_clock::now();
#ifdef _WIN32
  HANDLE shutdown_log_ = INVALID_HANDLE_VALUE;
#endif
  ida_agent::bridge::IdaExecutor executor_;
#if IDA_AGENT_ENABLE_AI
  ida_agent::ai::AgentFileService file_service_;
#endif
  ida_agent::services::DatabaseService database_service_;
  ida_agent::services::ChangeSetService changeset_service_;
  ida_agent::services::DecompilerService decompiler_service_;
  ida_agent::services::DebuggerService debugger_service_;
  ida_agent::services::FunctionService function_service_;
  ida_agent::services::MemoryService memory_service_;
  ida_agent::services::ReadonlyAnalysisService readonly_analysis_service_;
  ida_agent::services::SourceInfoService source_info_service_;
  ida_agent::services::AnnotationService annotation_service_;
  ida_agent::services::DecompilerInspectionService decompiler_inspection_service_;
  ida_agent::services::SemanticAnalysisService semantic_analysis_service_;
  ida_agent::services::SearchService search_service_;
  ida_agent::services::ScriptService script_service_;
  ida_agent::services::StringService string_service_;
  ida_agent::services::SymbolService symbol_service_;
  ida_agent::services::TypeService type_service_;
  ida_agent::services::XrefService xref_service_;
#if IDA_AGENT_ENABLE_AI
  ida_agent::ai::AgentToolRegistry agent_tools_;
  ida_agent::ai::AgentEffectService agent_effects_;
#endif
  ida_agent::bridge::Bridge bridge_;
#if IDA_AGENT_ENABLE_AI
  ida_agent::ai::AiMenuController ai_menu_;
#endif
  DatabaseListener listener_;
  bool close_in_progress_ = false;
  bool decompiler_checked_ = false;
  bool decompiler_available_ = false;
};

plugmod_t *idaapi init()
{
  try
  {
    return new IdaAgentPlugin();
  }
  catch ( const std::exception &error )
  {
    msg("[ida-agent] plugin startup failed\n");
    if ( qgetenv("IDA_AGENT_TEST_DIAGNOSTICS", nullptr) )
      msg("[ida-agent-test] startup error: %s\n", error.what());
    return nullptr;
  }
}

} // namespace

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_FIX | PLUGIN_MULTI | PLUGIN_HIDE,
  init,
  nullptr,
  nullptr,
  "IDA analysis with a built-in AI agent and a local MCP bridge.",
  nullptr,
  "IDA Agent",
  nullptr,
};
