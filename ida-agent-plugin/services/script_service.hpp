#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace ida_agent::services
{
enum class ScriptStatus { Success, Unavailable, InvalidArgument, Failed };

struct ScriptExecution
{
  std::string language;
  bool success;
  std::optional<std::string> result;
  std::string stdout_text;
  std::string stderr_text;
  bool truncated;
  std::uint64_t original_size;
};

struct ScriptExecutionOutcome
{
  ScriptStatus status;
  std::optional<ScriptExecution> result;
};

class ScriptService
{
public:
  ScriptExecutionOutcome Execute(std::string_view language, std::string_view code) const;
};

nlohmann::json ToJson(const ScriptExecution &result);
} // namespace ida_agent::services
