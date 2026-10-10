#pragma once
#include "model.hpp"

namespace ida_agent::services::semantic
{
Request ParseRequest(const nlohmann::json &params);
}
