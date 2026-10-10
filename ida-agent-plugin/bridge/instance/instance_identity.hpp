#pragma once

#include <cstdint>
#include <string>

namespace ida_agent::bridge
{

std::string GenerateInstanceId();
std::wstring BuildPipeName(std::uint32_t pid, const std::string &instance_id);

} // namespace ida_agent::bridge
