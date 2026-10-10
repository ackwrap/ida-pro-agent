#pragma once

#include "ai/provider_settings_model.hpp"

#include <filesystem>

namespace ida_agent::ai
{

enum class ProviderSettingsLoadStatus
{
  Missing,
  Loaded,
  Invalid,
  Unavailable,
};

struct ProviderSettingsLoadResult
{
  ProviderSettingsLoadStatus status;
  ProviderManagerDraft manager;
};

class ProviderSettingsStore final
{
public:
  explicit ProviderSettingsStore(std::filesystem::path path = {});

  ProviderSettingsLoadResult Load();
  bool Save(const ProviderManagerDraft &manager);

private:
  bool ResolvePath();

  std::filesystem::path path_;
};

} // namespace ida_agent::ai
