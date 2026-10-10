#pragma once
#include "model.hpp"
#include "services/query_result.hpp"
#include <functional>
#include <memory>

namespace ida_agent::services::semantic
{
struct CallersRequest
{
  std::uint64_t call_address = 0;
  std::uint32_t argument_index = 0;
  std::uint32_t max_depth = 2;
  std::uint32_t max_contexts = 16;
  std::uint32_t max_callers = 8;
  std::uint32_t max_nodes = 1000;
  std::uint32_t max_work = 100000;
};
struct SnapshotResult
{
  QueryStatus status = QueryStatus::Success;
  std::shared_ptr<Snapshot> snapshot;
  std::uint32_t work = 0;
};
struct CallerSites
{
  std::vector<std::uint64_t> addresses;
  std::uint32_t work = 0;
  bool truncated = false;
  bool unsupported = false;
};
struct CallersProvider
{
  std::function<SnapshotResult(std::uint64_t, std::uint32_t)> load;
  std::function<CallerSites(std::uint64_t, std::uint32_t, std::uint32_t)> callers;
};
bool ValidCallersRequest(const CallersRequest &request);
CallersRequest ParseCallersRequest(const nlohmann::json &params);
QueryResult TraceCallers(const CallersRequest &request, const CallersProvider &provider);
SnapshotResult LoadMicrocodeSnapshot(std::uint64_t call_address, std::uint32_t max_work);
}
