#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>

namespace ida_agent::services
{

enum class MemoryFormat
{
  Bytes,
  String,
  Integer,
  Pointer,
};

struct MemoryReadQuery
{
  std::uint64_t address;
  MemoryFormat format;
  std::uint32_t length = 0;
  std::uint32_t width_bits = 0;
};

struct MemoryReadResult
{
  std::uint64_t address;
  MemoryFormat format;
  std::uint32_t bytes_read;
  std::string value;
  std::optional<std::uint32_t> width_bits;
  std::optional<std::string> byte_order;
  std::optional<bool> terminated;
};

enum class MemoryReadStatus
{
  Success,
  InvalidAddress,
  Unreadable,
  UnsupportedProcessor,
  InvalidEncoding,
};

struct MemoryReadOutcome
{
  MemoryReadStatus status;
  std::optional<MemoryReadResult> result;
};

class MemoryService
{
public:
  // The caller must run this read operation through IdaExecutor.
  MemoryReadOutcome Read(const MemoryReadQuery &query) const;
};

nlohmann::json ToJson(const MemoryReadResult &result);

} // namespace ida_agent::services
