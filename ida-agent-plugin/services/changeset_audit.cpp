#include "changeset_service.hpp"

#include "address.hpp"

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace ida_agent::services
{
namespace
{
constexpr std::size_t MaxAuditEntries = 4096;

std::string Redact(std::string_view value)
{
  std::uint64_t hash = 1469598103934665603ULL;
  for ( unsigned char character : value ) { hash ^= character; hash *= 1099511628211ULL; }
  std::ostringstream output;
  output << "len=" << value.size() << ",fnv64=" << std::hex << std::setw(16) << std::setfill('0') << hash;
  return output.str();
}
}

void ChangeSetService::RecordAudit(
    std::string_view change_id, std::string_view session_id, std::string_view operation,
    std::uint64_t address, std::string_view before, std::string_view after, bool success)
{
  if ( audit_.size() >= MaxAuditEntries ) audit_.erase(audit_.begin());
  const auto timestamp = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count());
  audit_.push_back({std::string(change_id), Redact(session_id), std::string(operation), address,
      Redact(before), Redact(after), success, timestamp});
}

AuditOutcome ChangeSetService::Audit(std::uint32_t offset, std::uint32_t limit) const
{
  std::vector<AuditEntry> result;
  const std::size_t begin = (std::min)(static_cast<std::size_t>(offset), audit_.size());
  const std::size_t end = (std::min)(begin + limit, audit_.size());
  result.insert(result.end(), audit_.begin() + begin, audit_.begin() + end);
  return {ChangeStatus::Success, std::move(result)};
}

nlohmann::json ToJson(const ChangePreview &result) { nlohmann::json items = nlohmann::json::array(); for ( const auto &item : result.items ) items.push_back({{"index", item.index}, {"before", item.before}, {"after", item.after}, {"conflict", item.conflict}}); return {{"previewId", result.preview_id}, {"items", std::move(items)}, {"applicable", result.applicable}}; }
nlohmann::json ToJson(const ChangeApplyResult &result) { nlohmann::json items = nlohmann::json::array(); for ( const auto &item : result.items ) items.push_back({{"index", item.index}, {"applied", item.applied}, {"error", item.error ? nlohmann::json(*item.error) : nlohmann::json(nullptr)}}); return {{"changeId", result.change_id}, {"items", std::move(items)}, {"applied", result.applied}}; }
nlohmann::json ToJson(const std::vector<AuditEntry> &result) { nlohmann::json items = nlohmann::json::array(); for ( const auto &item : result ) items.push_back({{"changeId", item.change_id}, {"sessionId", item.session_id}, {"operation", item.operation}, {"address", rpc::FormatAddress(item.address)}, {"before", item.before}, {"after", item.after}, {"success", item.success}, {"timestampMs", item.timestamp_ms}}); return {{"items", std::move(items)}}; }

} // namespace ida_agent::services
