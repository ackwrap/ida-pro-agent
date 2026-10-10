#pragma once

#include <filesystem>

namespace ida_agent::bridge
{
// Creates missing components as 0700 and rejects symlinks and unsafe ancestors.
void EnsurePrivateDirectory(const std::filesystem::path &directory);
}
