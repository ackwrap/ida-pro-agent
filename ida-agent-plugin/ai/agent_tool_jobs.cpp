#include "ai/agent_tool_registry.hpp"
#include "ai/provider_agent_protocol.hpp"

#include <mutex>
#include <thread>
#include <unordered_map>
#include <utility>

namespace ida_agent::ai
{
namespace
{

std::optional<std::size_t> ResultBytes(const AgentToolResult &result) noexcept
{
  return AgentToolResultContentBytes(result);
}

} // namespace

struct AgentToolRegistry::Jobs
{
  struct Job
  {
    std::mutex mutex;
    std::thread worker;
    std::vector<AgentToolResult> results;
    std::atomic<bool> cancelled{false};
    std::atomic<bool> abandoned{false};
    bool done = false;
  };

  std::mutex mutex;
  std::unordered_map<JobId, std::shared_ptr<Job>> active;
  JobId next_id = 1;
  bool stopping = false;
};

AgentToolRegistry::AgentToolRegistry(
    ExportInvoker exports,
    StringInvoker strings,
    FunctionInvoker function_get,
    DecompileInvoker decompile,
    XrefInvoker xrefs,
    MemoryInvoker memory,
    int)
    : exports_(std::move(exports)), strings_(std::move(strings)),
      function_get_(std::move(function_get)), decompile_(std::move(decompile)),
      xrefs_(std::move(xrefs)), memory_(std::move(memory)),
      jobs_(std::make_unique<Jobs>())
{
}

AgentToolRegistry::~AgentToolRegistry()
{
  SetAvailable(false);
  std::vector<std::shared_ptr<Jobs::Job>> jobs;
  {
    std::lock_guard<std::mutex> lock(jobs_->mutex);
    jobs_->stopping = true;
    for ( const auto &entry : jobs_->active )
    {
      entry.second->cancelled.store(true, std::memory_order_release);
      jobs.push_back(entry.second);
    }
  }
  for ( const auto &job : jobs )
  {
    if ( job->worker.joinable() )
      job->worker.join();
  }
}

AgentToolRegistry::JobId AgentToolRegistry::Submit(
    std::vector<AgentToolCall> calls)
{
  if ( !Available() || calls.empty() )
    return 0;

  std::vector<std::shared_ptr<Jobs::Job>> reaped;
  JobId id = 0;
  bool blocked = false;
  auto job = std::make_shared<Jobs::Job>();
  {
    std::lock_guard<std::mutex> lock(jobs_->mutex);
    for ( auto entry = jobs_->active.begin(); entry != jobs_->active.end(); )
    {
      bool done = false;
      {
        std::lock_guard<std::mutex> job_lock(entry->second->mutex);
        done = entry->second->done
            && entry->second->abandoned.load(std::memory_order_acquire);
      }
      if ( done )
      {
        reaped.push_back(entry->second);
        entry = jobs_->active.erase(entry);
      }
      else
      {
        ++entry;
      }
    }
    blocked = jobs_->stopping || jobs_->active.size() >= 8;
    if ( !blocked )
    {
      id = jobs_->next_id++;
      if ( id == 0 )
        id = jobs_->next_id++;
      jobs_->active.emplace(id, job);
    }
  }
  for ( const auto &finished : reaped )
  {
    if ( finished->worker.joinable() )
      finished->worker.join();
  }
  if ( blocked )
    return 0;

  try
  {
    job->worker = std::thread([this, job, calls = std::move(calls)]()
    {
      std::vector<AgentToolResult> results;
      std::size_t result_bytes = 0;
      for ( const AgentToolCall &call : calls )
      {
        if ( job->cancelled.load(std::memory_order_acquire) )
          break;
        AgentToolResult result = Invoke(call);
        if ( job->cancelled.load(std::memory_order_acquire) )
          break;
        const std::optional<std::size_t> current = ResultBytes(result);
        if ( !current.has_value()
            || result_bytes > MaxProviderAgentResultBytes
            || *current > MaxProviderAgentResultBytes - result_bytes )
        {
          break;
        }
        result_bytes += *current;
        results.push_back(std::move(result));
      }
      std::lock_guard<std::mutex> lock(job->mutex);
      if ( !job->abandoned.load(std::memory_order_acquire) )
        job->results = std::move(results);
      job->done = true;
    });
  }
  catch ( ... )
  {
    std::lock_guard<std::mutex> lock(jobs_->mutex);
    jobs_->active.erase(id);
    return 0;
  }
  return id;
}

std::optional<std::vector<AgentToolResult>> AgentToolRegistry::TryTake(
    JobId job_id)
{
  std::shared_ptr<Jobs::Job> job;
  {
    std::lock_guard<std::mutex> lock(jobs_->mutex);
    const auto found = jobs_->active.find(job_id);
    if ( found == jobs_->active.end() )
      return std::vector<AgentToolResult>{};
    job = found->second;
  }
  std::vector<AgentToolResult> results;
  {
    std::lock_guard<std::mutex> lock(job->mutex);
    if ( !job->done )
      return std::nullopt;
    results = std::move(job->results);
  }
  if ( job->worker.joinable() )
    job->worker.join();
  {
    std::lock_guard<std::mutex> lock(jobs_->mutex);
    const auto found = jobs_->active.find(job_id);
    if ( found != jobs_->active.end() && found->second == job )
      jobs_->active.erase(found);
  }
  return results;
}

void AgentToolRegistry::CancelAndForget(JobId job_id) noexcept
{
  try
  {
    std::shared_ptr<Jobs::Job> job;
    {
      std::lock_guard<std::mutex> lock(jobs_->mutex);
      const auto found = jobs_->active.find(job_id);
      if ( found == jobs_->active.end() )
        return;
      job = found->second;
    }
    job->abandoned.store(true, std::memory_order_release);
    job->cancelled.store(true, std::memory_order_release);
  }
  catch ( ... )
  {
  }
}

} // namespace ida_agent::ai
