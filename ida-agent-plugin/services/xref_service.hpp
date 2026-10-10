#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ida_agent::services
{

enum class XrefDirection
{
  Incoming,
  Outgoing,
};

enum class XrefCategory
{
  All,
  Code,
  Data,
};

struct XrefQuery
{
  std::uint64_t address;
  XrefDirection direction;
  XrefCategory category;
  bool include_flow;
  std::uint32_t limit;
  std::optional<std::string> cursor;
};

struct XrefInfo
{
  std::uint64_t from;
  std::uint64_t to;
  std::string type;
  bool code;
  bool user_defined;
};

struct XrefQueryResult
{
  std::vector<XrefInfo> items;
  std::optional<std::string> next_cursor;
  bool has_more = false;
};

enum class XrefQueryStatus
{
  Success,
  InvalidAddress,
  InvalidCursor,
  OutputLimit,
};

struct XrefQueryOutcome
{
  XrefQueryStatus status;
  std::optional<XrefQueryResult> result;
};

class XrefService
{
public:
  // The caller must run this read operation through IdaExecutor.
  XrefQueryOutcome Query(const XrefQuery &query) const;
};

nlohmann::json ToJson(const XrefQueryResult &result);

} // namespace ida_agent::services
