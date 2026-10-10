#include "ai/agent_loop.hpp"

#include <algorithm>
#include <utility>

namespace ida_agent::ai
{
namespace
{

AgentLoopStep Failure(std::string_view message)
{
  AgentLoopStep step;
  step.error = true;
  step.safe_message = message;
  return step;
}

std::optional<std::size_t> ResultBytes(const AgentToolResult &result) noexcept
{
  return AgentToolResultContentBytes(result);
}

} // namespace

AgentLoopStep AgentLoop::Begin(
    ProviderProfileDraft profile,
    std::vector<ProviderChatMessage> messages,
    std::string system_prompt,
    std::vector<AgentToolDefinition> tools)
{
  Reset();
  profile_ = std::move(profile);
  messages_ = std::move(messages);
  options_.system_prompt = std::move(system_prompt);
  tool_catalog_.Begin(std::move(tools));
  options_.tools = tool_catalog_.ActiveDefinitions();
  deadline_ = std::chrono::steady_clock::now() + std::chrono::minutes(10);
  return BuildNext();
}

AgentLoopStep AgentLoop::BeginToolRound(
    std::vector<AgentToolCall> calls,
    std::string assistant_text)
{
  if ( state_ != AgentLoopState::Streaming
      || calls.empty()
      || std::chrono::steady_clock::now() >= deadline_ )
  {
    Reset();
    return Failure(AgentLoopLimitMessage);
  }
  if ( std::any_of(
           calls.begin(), calls.end(),
           [this](const AgentToolCall &call)
           {
             return !tool_catalog_.IsActive(call.name);
           }) )
  {
    Reset();
    return Failure(AgentLoopBuildMessage);
  }

  state_ = AgentLoopState::ExecutingTools;
  pending_exchange_ = {};
  pending_exchange_.assistant_text = std::move(assistant_text);
  pending_exchange_.calls = std::move(calls);
  return {};
}

std::optional<AgentToolResult> AgentLoop::InvokeCatalogTool(
    const AgentToolCall &call)
{
  if ( state_ != AgentLoopState::ExecutingTools )
    return std::nullopt;
  return tool_catalog_.Invoke(call);
}

AgentLoopStep AgentLoop::CompleteToolRound(
    std::vector<AgentToolResult> results)
{
  if ( state_ != AgentLoopState::ExecutingTools
      || results.size() != pending_exchange_.calls.size()
      || std::chrono::steady_clock::now() >= deadline_ )
  {
    Reset();
    return Failure(AgentLoopLimitMessage);
  }
  std::size_t added_bytes = 0;
  for ( std::size_t index = 0; index < results.size(); ++index )
  {
    AgentToolResult &result = results[index];
    const AgentToolCall &call = pending_exchange_.calls[index];
    if ( result.call_id != call.id || result.name != call.name )
    {
      Reset();
      return Failure(AgentLoopBuildMessage);
    }
    const std::optional<std::size_t> current = ResultBytes(result);
    if ( !current.has_value()
        || result_bytes_ > MaxProviderAgentResultBytes
        || added_bytes > MaxProviderAgentResultBytes - result_bytes_ )
    {
      Reset();
      return Failure(AgentLoopLimitMessage);
    }
    const std::size_t consumed = result_bytes_ + added_bytes;
    if ( *current > MaxProviderAgentResultBytes - consumed )
    {
      Reset();
      return Failure(AgentLoopLimitMessage);
    }
    added_bytes += *current;
  }
  result_bytes_ += added_bytes;
  pending_exchange_.results = std::move(results);
  options_.exchanges.push_back(std::move(pending_exchange_));
  options_.tools = tool_catalog_.ActiveDefinitions();
  pending_exchange_ = {};
  return BuildNext();
}

void AgentLoop::Complete() noexcept
{
  Reset();
}

void AgentLoop::Reset() noexcept
{
  profile_ = {};
  messages_.clear();
  options_ = {};
  deadline_ = {};
  result_bytes_ = 0;
  pending_exchange_ = {};
  tool_catalog_.Reset();
  deadline_paused_at_ = {};
  state_ = AgentLoopState::Idle;
}

void AgentLoop::PauseDeadline() noexcept
{
  if ( state_ != AgentLoopState::Idle
      && deadline_paused_at_ == std::chrono::steady_clock::time_point{} )
  {
    deadline_paused_at_ = std::chrono::steady_clock::now();
  }
}

void AgentLoop::ResumeDeadline() noexcept
{
  if ( deadline_paused_at_ == std::chrono::steady_clock::time_point{} )
    return;
  deadline_ += std::chrono::steady_clock::now() - deadline_paused_at_;
  deadline_paused_at_ = {};
}

AgentLoopState AgentLoop::State() const noexcept
{
  return state_;
}

bool AgentLoop::Active() const noexcept
{
  return state_ != AgentLoopState::Idle;
}

bool AgentLoop::DeadlineExpired() const noexcept
{
  return state_ != AgentLoopState::Idle
      && deadline_paused_at_ == std::chrono::steady_clock::time_point{}
      && deadline_ != std::chrono::steady_clock::time_point{}
      && std::chrono::steady_clock::now() >= deadline_;
}

AgentLoopStep AgentLoop::BuildNext()
{
  ResumeDeadline();
  if ( std::chrono::steady_clock::now() >= deadline_ )
  {
    Reset();
    return Failure(AgentLoopLimitMessage);
  }
  AgentLoopStep step;
  step.build = BuildProviderAgentRequest(profile_, messages_, options_);
  if ( step.build.error )
  {
    step.error = true;
    step.safe_message = step.build.safe_message.empty()
        ? std::string(AgentLoopBuildMessage)
        : step.build.safe_message;
    Reset();
    return step;
  }
  state_ = AgentLoopState::Streaming;
  return step;
}

} // namespace ida_agent::ai
