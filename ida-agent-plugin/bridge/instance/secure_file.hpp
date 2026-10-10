#pragma once

#include <filesystem>
#include <string_view>

namespace ida_agent::bridge
{

void EnsureCurrentUserOnlyDirectory(const std::filesystem::path &directory);
void ApplyCurrentUserOnlyFileAcl(const std::filesystem::path &path);
void AtomicWriteCurrentUserOnlyFile(
    const std::filesystem::path &target,
    std::string_view contents);

} // namespace ida_agent::bridge
