#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace ida_agent::ai
{

enum class CliCommandKind
{
  Empty,
  Message,
  Help,
  NewConversation,
  ClearConversation,
  Compact,
  Cancel,
  AllowSessionEffects,
  DenySessionEffects,
  Provider,
  Providers,
  Model,
  Models,
  Status,
  History,
  SelectSession,
  Context,
  Unknown,
};

struct CliCommand
{
  CliCommandKind kind;
  std::string text;
};

struct CliCommandDefinition
{
  std::string_view command;
  std::string_view description;
  CliCommandKind kind;
};

const std::vector<CliCommandDefinition> &AvailableCliCommands() noexcept;
CliCommand ParseCliCommand(std::string_view line);

} // namespace ida_agent::ai
