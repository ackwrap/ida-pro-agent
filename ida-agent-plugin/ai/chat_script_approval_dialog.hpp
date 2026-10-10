#pragma once

#include "ai/chat_script_approval.hpp"

#include <vector>

namespace ida_agent::ai
{

ChatScriptApprovalDecision ShowChatScriptApprovalDialog(
    void *parent,
    const std::vector<ChatScriptSource> &sources);

} // namespace ida_agent::ai
