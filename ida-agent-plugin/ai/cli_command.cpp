#include "ai/cli_command.hpp"

#include <cctype>

namespace ida_agent::ai
{
namespace
{

const std::vector<CliCommandDefinition> Commands{
    {"/help", "Show available commands", CliCommandKind::Help},
    {"/new", "Start a new conversation", CliCommandKind::NewConversation},
    {"/clear", "Clear the current conversation", CliCommandKind::ClearConversation},
    {"/compact", "Summarize older context now", CliCommandKind::Compact},
    {"/cancel", "Cancel the active request", CliCommandKind::Cancel},
    {"/y", "Allow all side effects for this conversation session", CliCommandKind::AllowSessionEffects},
    {"/n", "Deny all side effects for this conversation session", CliCommandKind::DenySessionEffects},
    {"/provider", "Show the current provider", CliCommandKind::Provider},
    {"/providers", "Open Provider Manager", CliCommandKind::Providers},
    {"/config", "Open Provider Manager", CliCommandKind::Providers},
    {"/model", "Show the current model", CliCommandKind::Model},
    {"/models", "List configured models", CliCommandKind::Models},
    {"/status", "Show session and context token status", CliCommandKind::Status},
    {"/history", "Show local history status", CliCommandKind::History},
    {"/session", "Switch conversation by list number or ID", CliCommandKind::SelectSession},
    {"/ctx", "Show detailed model context usage", CliCommandKind::Context},
    {"/context", "Show detailed model context usage", CliCommandKind::Context},
};

std::string_view Trim(std::string_view value)
{
  while ( !value.empty() && std::isspace(static_cast<unsigned char>(value.front())) )
    value.remove_prefix(1);
  while ( !value.empty() && std::isspace(static_cast<unsigned char>(value.back())) )
    value.remove_suffix(1);
  return value;
}

} // namespace

const std::vector<CliCommandDefinition> &AvailableCliCommands() noexcept
{
  return Commands;
}

CliCommand ParseCliCommand(std::string_view line)
{
  line = Trim(line);
  if ( line.empty() )
    return {CliCommandKind::Empty, {}};
  if ( line.front() != '/' )
    return {CliCommandKind::Message, std::string(line)};
  for ( const CliCommandDefinition &command : Commands )
  {
    if ( line == command.command )
      return {command.kind, {}};
    if ( command.kind == CliCommandKind::SelectSession
        && line.size() > command.command.size()
        && line.substr(0, command.command.size()) == command.command
        && std::isspace(
            static_cast<unsigned char>(line[command.command.size()])) )
    {
      return {command.kind, std::string(Trim(line.substr(command.command.size()))) };
    }
  }
  return {CliCommandKind::Unknown, std::string(line)};
}

} // namespace ida_agent::ai
