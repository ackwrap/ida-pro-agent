#include "ai/ai_menu_registry.hpp"

#include "ai/ai_menu.hpp"
#include "ai/ai_menu_selection.hpp"
#include "ai/chat_history_store.hpp"
#include "ai/network_diagnostics.hpp"
#include "ai/plugin_settings.hpp"
#include "ai/provider_client.hpp"
#include "ai/provider_settings_dialog.hpp"
#include "ai/provider_settings_store.hpp"
#include "ai/stream_client.hpp"
#include "ai/update_controller.hpp"

#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>

#include <array>
#include <exception>
#include <map>
#include <utility>

namespace ida_agent::ai
{
namespace
{

constexpr const char *MenuName = "ida-agent-menu";
constexpr const char *MenuPath = "Edit/Plugins/IDA Agent/";

enum class ActionKind
{
  OpenChat,
  ProviderSettings,
  PluginSettings,
  CheckUpdates,
  TestProvider,
  NewConversation,
  CancelRequest,
  SendDisassembly,
  SendPseudocode,
};

struct ActionDefinition
{
  const char *name;
  const char *label;
  const char *tooltip;
  ActionKind kind;
  bool popup_only;
};

constexpr std::array<ActionDefinition, 9> Actions{{
    {"ida-agent:ai:open", "Open AI Chat", "Open the IDA Agent AI chat panel", ActionKind::OpenChat, false},
    {"ida-agent:ai:providers", "Provider Settings...", "Configure OpenAI or Claude providers", ActionKind::ProviderSettings, false},
    {"ida-agent:settings", "Settings...", "Configure IDA Agent plugin behavior", ActionKind::PluginSettings, false},
    {"ida-agent:updates", "Check for Updates...", "Check the public stable release", ActionKind::CheckUpdates, false},
    {"ida-agent:ai:test-provider", "Test Active Provider", "Test the active AI provider", ActionKind::TestProvider, false},
    {"ida-agent:ai:new", "New Conversation", "Start a new AI conversation", ActionKind::NewConversation, false},
    {"ida-agent:ai:cancel", "Cancel Request", "Cancel the active AI request", ActionKind::CancelRequest, false},
    {"ida-agent:ai:send-disasm", "Send to AI", "Send the selected disassembly lines with addresses to the AI chat input", ActionKind::SendDisassembly, true},
    {"ida-agent:ai:send-pseudo", "Send to AI", "Send the pseudocode window contents with its address to the AI chat input", ActionKind::SendPseudocode, true},
}};

bool IsPopupAction(ActionKind kind) noexcept
{
  return kind == ActionKind::SendDisassembly || kind == ActionKind::SendPseudocode;
}

class AiActionHandler final : public action_handler_t
{
public:
  explicit AiActionHandler(ActionKind kind) : kind_(kind) {}
  int idaapi activate(action_activation_ctx_t *) override;
  action_state_t idaapi update(action_update_ctx_t *) override;

private:
  ActionKind kind_;
};

} // namespace

struct ProviderSettingsSnapshot::Impl
{
  ProviderManagerDraft manager;
  std::uint64_t revision = 0;
};

ProviderSettingsSnapshot::ProviderSettingsSnapshot(
    ProviderManagerDraft manager,
    std::uint64_t revision)
    : impl_(std::make_unique<Impl>(Impl{std::move(manager), revision}))
{
}

ProviderSettingsSnapshot::ProviderSettingsSnapshot(
    const ProviderSettingsSnapshot &other)
    : impl_(std::make_unique<Impl>(*other.impl_))
{
}

ProviderSettingsSnapshot::ProviderSettingsSnapshot(
    ProviderSettingsSnapshot &&other) noexcept = default;

ProviderSettingsSnapshot::~ProviderSettingsSnapshot() = default;

ProviderSettingsSnapshot &ProviderSettingsSnapshot::operator=(
    const ProviderSettingsSnapshot &other)
{
  if ( this != &other )
    impl_ = std::make_unique<Impl>(*other.impl_);
  return *this;
}

ProviderSettingsSnapshot &ProviderSettingsSnapshot::operator=(
    ProviderSettingsSnapshot &&other) noexcept = default;

ProviderManagerDraft &ProviderSettingsSnapshot::Manager() noexcept
{
  return impl_->manager;
}

const ProviderManagerDraft &ProviderSettingsSnapshot::Manager() const noexcept
{
  return impl_->manager;
}

std::uint64_t &ProviderSettingsSnapshot::Revision() noexcept
{
  return impl_->revision;
}

std::uint64_t ProviderSettingsSnapshot::Revision() const noexcept
{
  return impl_->revision;
}

struct AiMenuRegistry::Impl
{
  class PopupListener final : public event_listener_t
  {
  public:
    explicit PopupListener(Impl *host) : host_(host) {}

    ssize_t idaapi on_event(ssize_t code, va_list args) override
    {
      if ( code != ui_finish_populating_widget_popup || host_ == nullptr )
        return 0;
      try
      {
        TWidget *widget = va_arg(args, TWidget *);
        TPopupMenu *popup_handle = va_arg(args, TPopupMenu *);
        (void)va_arg(args, const action_activation_ctx_t *);
        if ( widget != nullptr && popup_handle != nullptr )
          host_->AttachPopupAction(widget, popup_handle);
      }
      catch ( ... )
      {
      }
      return 0;
    }

  private:
    Impl *host_;
  };

  bool HookPopupMenus()
  {
    if ( popup_listener != nullptr ) return true;
    auto listener = std::make_unique<PopupListener>(this);
    if ( !hook_event_listener(HT_UI, listener.get(), nullptr) ) return false;
    popup_listener = std::move(listener);
    return true;
  }

  void UnhookPopupMenus() noexcept
  {
    if ( popup_listener == nullptr ) return;
    unhook_event_listener(HT_UI, popup_listener.get());
    popup_listener.reset();
  }

  void AttachPopupAction(TWidget *widget, TPopupMenu *popup_handle) noexcept
  {
    if ( !ui_registered ) return;
    const int type = get_widget_type(widget);
    if ( type == BWN_DISASM )
      attach_action_to_popup(widget, popup_handle,
          "ida-agent:ai:send-disasm", nullptr, SETMENU_APP);
    else if ( type == BWN_PSEUDOCODE )
      attach_action_to_popup(widget, popup_handle,
          "ida-agent:ai:send-pseudo", nullptr, SETMENU_APP);
  }

  bool Add(
      std::ptrdiff_t context_id,
      AiMenuController *controller,
      const void *action_owner)
  {
    if ( controller == nullptr || context_id < 0 || action_owner == nullptr )
      return false;
    const auto existing = controllers.find(context_id);
    if ( existing != controllers.end() )
      return existing->second == controller;
    if ( !controllers.empty() && action_owner != action_owner_ )
      return false;
    if ( controllers.empty() )
      action_owner_ = action_owner;
    const bool register_ui = controllers.empty() && ui_ready;
    if ( register_ui && !RegisterUi() )
      return false;
    try
    {
      controllers.emplace(context_id, controller);
    }
    catch ( ... )
    {
      if ( register_ui )
        UnregisterUi();
      throw;
    }
    return true;
  }

  void Remove(
      std::ptrdiff_t context_id,
      AiMenuController *controller,
      bool unregister_actions,
      const std::function<void(const char *)> &trace) noexcept
  {
    const auto existing = controllers.find(context_id);
    if ( existing == controllers.end() || existing->second != controller )
      return;
    controllers.erase(existing);
    if ( controllers.empty() )
    {
      updates.Stop();
      if ( stream_client != nullptr )
      {
        if ( trace ) trace("ai.stop.stream.shutdown.begin");
        stream_client->Shutdown();
        stream_client.reset();
        if ( trace ) trace("ai.stop.stream.shutdown.end");
      }
      UnregisterUi(unregister_actions, trace);
    }
  }

  AiMenuController *Current() const
  {
    const std::ptrdiff_t context_id = get_dbctx_id();
    const auto controller = controllers.find(context_id);
    return controller == controllers.end() ? nullptr : controller->second;
  }

  bool SetUiReady()
  {
    ui_ready = true;
    if ( controllers.empty() || ui_registered || !is_idaq() )
      return true;
    return RegisterUi();
  }

  void EnsureSettingsLoaded()
  {
    if ( plugin_settings_loaded )
      return;
    const PluginSettingsLoadResult loaded = settings_store.Load();
    settings = loaded.settings;
    ConfigureAiLogging(settings.debug_logging, settings.network_logging);
    plugin_settings_loaded = true;
    if ( loaded.status == PluginSettingsLoadStatus::Invalid )
      msg("[ida-agent] plugin settings are invalid; defaults are active\n");
    else if ( loaded.status == PluginSettingsLoadStatus::Unavailable )
      msg("[ida-agent] plugin settings are unavailable; defaults are active\n");
  }

  void EnsureProviderSettingsLoaded()
  {
    if ( provider_settings_loaded )
      return;
    ProviderSettingsLoadResult loaded = provider_settings_store.Load();
    if ( loaded.status == ProviderSettingsLoadStatus::Loaded )
    {
      provider_settings = std::move(loaded.manager);
    }
    else
    {
      provider_settings = CreateProviderManagerDraft();
      if ( loaded.status == ProviderSettingsLoadStatus::Missing )
        msg("[ida-agent] provider settings are missing; defaults are active\n");
      else if ( loaded.status == ProviderSettingsLoadStatus::Invalid )
        msg("[ida-agent] provider settings are invalid; defaults are active\n");
      else
        msg("[ida-agent] provider settings are unavailable; defaults are active\n");
    }
    provider_settings_loaded = true;
  }

  bool RegisterUi()
  {
    if ( !is_idaq() )
      return true;

    std::size_t registered = 0;
    for ( std::size_t index = 0; index < Actions.size(); ++index )
    {
      const ActionDefinition &definition = Actions[index];
      const action_desc_t descriptor{
          sizeof(action_desc_t),
          definition.name,
          definition.label,
          &handlers[index],
          action_owner_,
          nullptr,
          definition.tooltip,
          -1,
          ADF_NO_UNDO | ADF_GLOBAL | ADF_OT_PLUGIN,
      };
      if ( !register_action(descriptor) )
      {
        while ( registered > 0 )
          unregister_action(Actions[--registered].name);
        return false;
      }
      ++registered;
    }

    if ( !create_menu(MenuName, "IDA Agent", "Edit/Plugins/") )
    {
      while ( registered > 0 )
        unregister_action(Actions[--registered].name);
      return false;
    }

    for ( std::size_t index = 0; index < Actions.size(); ++index )
    {
      const ActionDefinition &definition = Actions[index];
      if ( definition.popup_only ) continue;
      int flags = SETMENU_APP;
      if ( definition.kind == ActionKind::ProviderSettings
          || definition.kind == ActionKind::CancelRequest )
      {
        flags |= SETMENU_ENSURE_SEP;
      }
      if ( !attach_action_to_menu(MenuPath, definition.name, flags) )
      {
        for ( std::size_t rollback = 0; rollback < index; ++rollback )
          if ( !Actions[rollback].popup_only )
            detach_action_from_menu(MenuPath, Actions[rollback].name);
        delete_menu(MenuName);
        while ( registered > 0 )
          unregister_action(Actions[--registered].name);
        return false;
      }
    }

    if ( !HookPopupMenus() )
      msg("[ida-agent] failed to hook AI viewer popup menus\n");
    ui_registered = true;
    updates.Start();
    return true;
  }

  void UnregisterUi(
      bool unregister_actions = true,
      const std::function<void(const char *)> &trace = {}) noexcept
  {
    if ( !ui_registered )
      return;
    if ( trace ) trace("ai.stop.registry.detach.begin");
    for ( auto action = Actions.rbegin(); action != Actions.rend(); ++action )
      if ( !action->popup_only )
        detach_action_from_menu(MenuPath, action->name);
    if ( trace ) trace("ai.stop.registry.detach.end");
    UnhookPopupMenus();
    if ( trace ) trace("ai.stop.registry.delete_menu.begin");
    delete_menu(MenuName);
    if ( trace ) trace("ai.stop.registry.delete_menu.end");
    if ( unregister_actions )
    {
      if ( trace ) trace("ai.stop.registry.unregister_actions.begin");
      for ( auto action = Actions.rbegin(); action != Actions.rend(); ++action )
        unregister_action(action->name);
      if ( trace ) trace("ai.stop.registry.unregister_actions.end");
      action_owner_ = nullptr;
    }
    else if ( trace )
    {
      trace("ai.stop.registry.unregister_actions.deferred");
    }
    ui_registered = false;
  }

  std::map<std::ptrdiff_t, AiMenuController *> controllers;
  std::array<AiActionHandler, Actions.size()> handlers{{
      AiActionHandler(ActionKind::OpenChat),
      AiActionHandler(ActionKind::ProviderSettings),
      AiActionHandler(ActionKind::PluginSettings),
      AiActionHandler(ActionKind::CheckUpdates),
      AiActionHandler(ActionKind::TestProvider),
      AiActionHandler(ActionKind::NewConversation),
      AiActionHandler(ActionKind::CancelRequest),
      AiActionHandler(ActionKind::SendDisassembly),
      AiActionHandler(ActionKind::SendPseudocode),
  }};
  PluginSettingsStore settings_store;
  PluginSettings settings;
  UpdateController updates;
  ProviderSettingsStore provider_settings_store;
  ProviderManagerDraft provider_settings;
  std::uint64_t provider_revision = 1;
  bool provider_settings_loaded = false;
  HttpClient http_client;
  // Member destruction is reverse declaration order: provider_client is
  // destroyed before the transport it references.
  ProviderClient provider_client{http_client};
  // Controllers are removed before the process-level transport is reset.
  // Keeping this last also destroys it before stores and provider clients.
  std::unique_ptr<StreamClient> stream_client;
  std::unique_ptr<PopupListener> popup_listener;
  const void *action_owner_ = nullptr;
  bool ui_registered = false;
  bool ui_ready = false;
  bool plugin_settings_loaded = false;
};

AiMenuRegistry &AiMenuRegistry::Instance()
{
  static AiMenuRegistry registry;
  return registry;
}

AiMenuRegistry::AiMenuRegistry() : impl_(std::make_unique<Impl>()) {}

AiMenuRegistry::~AiMenuRegistry()
{
  impl_->updates.Stop();
  if ( impl_->stream_client != nullptr )
  {
    impl_->stream_client->Shutdown();
    impl_->stream_client.reset();
  }
  impl_->UnhookPopupMenus();
  ConfigureAiLogging(false, false);
}

bool AiMenuRegistry::Add(
    std::ptrdiff_t context_id,
    AiMenuController *controller,
    const void *action_owner)
{
  return impl_->Add(context_id, controller, action_owner);
}

void AiMenuRegistry::Remove(
    std::ptrdiff_t context_id,
    AiMenuController *controller,
    bool unregister_actions,
    const std::function<void(const char *)> &trace) noexcept
{
  impl_->Remove(context_id, controller, unregister_actions, trace);
}

AiMenuController *AiMenuRegistry::Current() const
{
  return impl_->Current();
}

void AiMenuRegistry::RefreshRequestActions()
{
  if ( !impl_->ui_registered ) return;
  const auto *controller = Current();
  const auto desired = controller != nullptr && controller->HasActiveRequest()
      ? AST_ENABLE : AST_DISABLE;
  action_state_t current;
  // Qt timers and synthetic input do not necessarily invalidate IDA's cached
  // action state. Publish request transitions without waiting for a menu visit.
  if ( get_action_state("ida-agent:ai:cancel", &current) && current != desired )
    update_action_state("ida-agent:ai:cancel", desired);
}

bool AiMenuRegistry::SetUiReady()
{
  return impl_->SetUiReady();
}

bool AiMenuRegistry::IsUiReady() const noexcept
{
  return impl_->ui_ready;
}

PluginSettings AiMenuRegistry::Settings()
{
  impl_->EnsureSettingsLoaded();
  return impl_->settings;
}

bool AiMenuRegistry::SaveSettings(const PluginSettings &settings)
{
  impl_->EnsureSettingsLoaded();
  if ( !impl_->settings_store.Save(settings) )
    return false;
  impl_->settings = settings;
  ConfigureAiLogging(settings.debug_logging, settings.network_logging);
  return true;
}

bool AiMenuRegistry::ClearAllChatHistory()
{
  for ( const auto &[context_id, controller] : impl_->controllers )
  {
    (void)context_id;
    if ( controller != nullptr && controller->HasActiveRequest() )
      return false;
  }
  ChatHistoryStore store;
  for ( const auto &[context_id, controller] : impl_->controllers )
  {
    (void)context_id;
    if ( controller != nullptr ) controller->history_writer_.Drain();
  }
  if ( !store.ClearAll() )
    return false;
  for ( const auto &[context_id, controller] : impl_->controllers )
  {
    (void)context_id;
    if ( controller != nullptr )
      controller->OnAllHistoryCleared();
  }
  return true;
}

ProviderSettingsSnapshot AiMenuRegistry::ProviderSettings()
{
  impl_->EnsureProviderSettingsLoaded();
  return ProviderSettingsSnapshot{
      impl_->provider_settings,
      impl_->provider_revision};
}

ProviderSettingsCommitResult AiMenuRegistry::ApplyProviderSettings(
    const ProviderManagerDraft &manager,
    std::uint64_t expected_revision)
{
  impl_->EnsureProviderSettingsLoaded();
  const std::uint64_t original_revision = impl_->provider_revision;
  ProviderManagerDraft normalized = manager;
  NormalizeProviderManagerDraft(normalized);
  if ( !IsValidManagerDraft(normalized) )
    return {ProviderSettingsCommitStatus::Failed, original_revision};
  if ( expected_revision != impl_->provider_revision )
    return {ProviderSettingsCommitStatus::Conflict, impl_->provider_revision};
  if ( !impl_->provider_settings_store.Save(normalized) )
    return {ProviderSettingsCommitStatus::Failed, original_revision};
  impl_->provider_settings = std::move(normalized);
  ++impl_->provider_revision;
  return {ProviderSettingsCommitStatus::Saved, impl_->provider_revision};
}

ProviderClient &AiMenuRegistry::ProviderClientInstance() noexcept
{
  return impl_->provider_client;
}

StreamClient &AiMenuRegistry::StreamClientInstance()
{
  impl_->EnsureSettingsLoaded();
  if ( impl_->stream_client == nullptr )
    impl_->stream_client = std::make_unique<StreamClient>();
  return *impl_->stream_client;
}

UpdateController &AiMenuRegistry::Updates() { return impl_->updates; }

namespace
{

int idaapi AiActionHandler::activate(action_activation_ctx_t *ctx)
{
  try
  {
    AiMenuController *controller = AiMenuRegistry::Instance().Current();
    if ( controller == nullptr )
      return 0;
    switch ( kind_ )
    {
      case ActionKind::ProviderSettings:
        controller->ShowProviderSettings();
        break;
      case ActionKind::PluginSettings:
        controller->ShowPluginSettings();
        break;
      case ActionKind::CheckUpdates:
        AiMenuRegistry::Instance().Updates().CheckNow();
        controller->ShowPluginSettings();
        break;
      case ActionKind::OpenChat:
        controller->OpenChat();
        break;
      case ActionKind::NewConversation:
        controller->NewConversation();
        break;
      case ActionKind::TestProvider:
        break;
      case ActionKind::CancelRequest:
        controller->CancelRequest();
        break;
      case ActionKind::SendDisassembly:
      case ActionKind::SendPseudocode:
      {
        const std::string text = kind_ == ActionKind::SendDisassembly
            ? CaptureDisassemblySelection(
                  ctx == nullptr ? nullptr : ctx->widget,
                  ctx == nullptr ? BADADDR : ctx->cur_ea)
            : CapturePseudocodeText(ctx == nullptr ? nullptr : ctx->widget);
        if ( text.empty() )
        {
          msg("[ida-agent] no code selection was available to send to the AI chat\n");
          break;
        }
        controller->OpenChat();
        controller->SetChatInputText(std::move(text));
        break;
      }
    }
  }
  catch ( const std::exception &error )
  {
    msg("[ida-agent] AI action failed: %s\n", error.what());
  }
  catch ( ... )
  {
    msg("[ida-agent] AI action failed\n");
  }
  return 0;
}

action_state_t idaapi AiActionHandler::update(action_update_ctx_t *)
{
  AiMenuController *controller = AiMenuRegistry::Instance().Current();
  if ( controller == nullptr )
    return AST_DISABLE_FOR_IDB;
  if ( kind_ == ActionKind::OpenChat
      || kind_ == ActionKind::ProviderSettings
      || kind_ == ActionKind::PluginSettings
      || kind_ == ActionKind::CheckUpdates
      || kind_ == ActionKind::NewConversation
      || kind_ == ActionKind::SendDisassembly
      || kind_ == ActionKind::SendPseudocode )
    return AST_ENABLE_FOR_IDB;
  // Request activity changes within the same database. Caching this state
  // until the next IDB switch leaves Cancel disabled after an idle menu visit.
  if ( kind_ == ActionKind::CancelRequest )
    return controller->HasActiveRequest() ? AST_ENABLE : AST_DISABLE;
  return AST_DISABLE_FOR_IDB;
}

} // namespace
} // namespace ida_agent::ai
