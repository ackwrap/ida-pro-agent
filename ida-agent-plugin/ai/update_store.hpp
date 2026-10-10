#pragma once

#include "ai/update_check.hpp"

#include <filesystem>

namespace ida_agent::ai
{

// Separate files prevent a background result from overwriting an opt-out saved
// by the other application. Both the plugin and Web manager use this schema.
class UpdateStore final
{
public:
  explicit UpdateStore(std::filesystem::path directory = {});
  bool Automatic();
  bool SaveAutomatic(bool automatic);
  UpdateCache LoadCache();
  bool SaveCache(const UpdateCache &cache);

private:
  bool ResolveDirectory();
  std::filesystem::path directory_;
};

} // namespace ida_agent::ai
