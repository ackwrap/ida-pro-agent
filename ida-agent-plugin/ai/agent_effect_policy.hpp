#pragma once

#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace ida_agent::ai
{

enum class AgentEffectApprovalPolicy
{
  Ask,
  Allow,
  Deny,
};

class AgentEffectSessionPolicies final
{
public:
  AgentEffectApprovalPolicy Get(std::string_view session_id) const
  {
    const auto found = policies_.find(std::string(session_id));
    return found == policies_.end()
        ? AgentEffectApprovalPolicy::Ask
        : found->second;
  }

  void Set(std::string session_id, AgentEffectApprovalPolicy policy)
  {
    policies_[std::move(session_id)] = policy;
  }

  void Move(std::string_view old_session_id, std::string new_session_id)
  {
    if ( old_session_id == new_session_id )
      return;
    const auto found = policies_.find(std::string(old_session_id));
    if ( found == policies_.end() )
      return;
    policies_[std::move(new_session_id)] = found->second;
    policies_.erase(found);
  }

private:
  std::unordered_map<std::string, AgentEffectApprovalPolicy> policies_;
};

} // namespace ida_agent::ai
