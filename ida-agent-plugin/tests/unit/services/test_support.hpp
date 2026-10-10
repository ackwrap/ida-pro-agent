#pragma once

#include <stdexcept>
#include <string>
#include <string_view>

inline void Require(bool condition, std::string_view message)
{
  if ( !condition )
    throw std::runtime_error(std::string(message));
}
