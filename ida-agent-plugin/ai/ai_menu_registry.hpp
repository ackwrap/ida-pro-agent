#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>

namespace ida_agent::ai
{

class AiMenuController;
class ProviderClient;
class StreamClient;
class UpdateController;
struct PluginSettings;
struct ProviderManagerDraft;
struct ProviderSettingsCommitResult;

class ProviderSettingsSnapshot final
{
public:
  ProviderSettingsSnapshot(const ProviderSettingsSnapshot &other);
  ProviderSettingsSnapshot(ProviderSettingsSnapshot &&other) noexcept;
  ~ProviderSettingsSnapshot();

  ProviderSettingsSnapshot &operator=(const ProviderSettingsSnapshot &other);
  ProviderSettingsSnapshot &operator=(ProviderSettingsSnapshot &&other) noexcept;

  ProviderManagerDraft &Manager() noexcept;
  const ProviderManagerDraft &Manager() const noexcept;
  std::uint64_t &Revision() noexcept;
  std::uint64_t Revision() const noexcept;

private:
  friend class AiMenuRegistry;

  ProviderSettingsSnapshot(
      ProviderManagerDraft manager,
      std::uint64_t revision);

  struct Impl;
  std::unique_ptr<Impl> impl_;
};

class AiMenuRegistry final
{
public:
  static AiMenuRegistry &Instance();

  bool Add(
      std::ptrdiff_t context_id,
      AiMenuController *controller,
      const void *action_owner);
  void Remove(
      std::ptrdiff_t context_id,
      AiMenuController *controller,
      bool unregister_actions,
      const std::function<void(const char *)> &trace = {}) noexcept;
  AiMenuController *Current() const;
  void RefreshRequestActions();

  bool SetUiReady();
  bool IsUiReady() const noexcept;

  PluginSettings Settings();
  bool SaveSettings(const PluginSettings &settings);
  bool ClearAllChatHistory();
  ProviderSettingsSnapshot ProviderSettings();
  ProviderSettingsCommitResult ApplyProviderSettings(
      const ProviderManagerDraft &manager,
      std::uint64_t expected_revision);
  ProviderClient &ProviderClientInstance() noexcept;
  StreamClient &StreamClientInstance();
  UpdateController &Updates();

private:
  AiMenuRegistry();
  ~AiMenuRegistry();

  AiMenuRegistry(const AiMenuRegistry &) = delete;
  AiMenuRegistry &operator=(const AiMenuRegistry &) = delete;

  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace ida_agent::ai
