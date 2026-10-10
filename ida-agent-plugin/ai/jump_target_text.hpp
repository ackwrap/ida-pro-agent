#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace ida_agent::ai
{

struct JumpTargetText
{
  bool is_address = false;
  std::uint64_t address = 0;
  std::string name;
};

// Parses the plain text selected in the AI chat output and picks a single jump
// candidate: the first 0x-prefixed hex address token, otherwise the first
// IDA-symbol-looking token. Returns std::nullopt when neither is present.
// Purely textual; whether the token is a real, loadable address or a known
// symbol is checked by the caller against the current database.
std::optional<JumpTargetText> ExtractJumpTarget(const std::string &selected);

} // namespace ida_agent::ai
