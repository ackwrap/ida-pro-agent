#pragma once
#include "query_result.hpp"
#include <cstdint>
#include <optional>
#include <string>

namespace ida_agent::services
{
class DecompilerInspectionService
{
public:
  // Callers execute all inspection operations through IdaExecutor.
  void SetDecompilerAvailable(bool available) noexcept { decompiler_available_ = available; }
  QueryResult DecompilerLocals(std::uint64_t address, std::uint32_t max_items) const;
  QueryResult DecompilerCtree(
      std::uint64_t address,
      std::uint32_t max_depth,
      std::uint32_t max_nodes) const;
  QueryResult DecompilerLocalXrefs(
      std::uint64_t address,
      std::uint32_t local_index,
      std::uint32_t max_depth,
      std::uint32_t max_nodes,
      std::uint32_t max_items) const;
private:
  bool decompiler_available_ = false;
};
}
