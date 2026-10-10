#pragma once

#include "ai/provider_client.hpp"

#include <cstdint>
#include <functional>

namespace ida_agent::ai
{

enum class ProviderSettingsCommitStatus
{
  Saved,
  Conflict,
  Failed,
};

struct ProviderSettingsCommitResult
{
  ProviderSettingsCommitStatus status = ProviderSettingsCommitStatus::Failed;
  std::uint64_t revision = 0;
};

using ProviderSettingsCommitCallback = std::function<ProviderSettingsCommitResult(
    const ProviderManagerDraft &,
    std::uint64_t expected_revision)>;

bool ShowProviderSettingsDialog(
    ProviderManagerDraft &draft,
    std::uint64_t &revision,
    ProviderClient &client,
    const ProviderSettingsCommitCallback &commit);

} // namespace ida_agent::ai
