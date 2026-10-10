#pragma once

#include <stdexcept>

namespace ida_agent::ai
{

class AgentToolSafeError final : public std::runtime_error
{
public:
  using std::runtime_error::runtime_error;
};

} // namespace ida_agent::ai
