#pragma once
#include "ai/analysis_memory/model.hpp"
#include <filesystem>
#include <memory>

namespace ida_agent::ai::analysis_memory
{
struct Search
{
  std::string text;
  std::uint32_t limit = 20;
  std::optional<std::uint64_t> anchor_rva;
  bool include_rejected = false;
  bool global_only = false;
};

// IDA-independent storage. Callers own the immutable binary/revision snapshot.
class Store final
{
public:
  explicit Store(std::filesystem::path path = {}, bool enable_fts = true);
  ~Store();
  Store(const Store &) = delete;
  Store &operator=(const Store &) = delete;
  bool Open(BinaryContext context) noexcept;
  void Close() noexcept;
  const BinaryContext &Context() const noexcept { return context_; }
  bool UsesFts() const noexcept;
  std::vector<Fact> Find(const Search &query);
  std::optional<Fact> Get(std::int64_t id);
  Fact Save(Fact fact);
  bool Forget(std::int64_t id);
  void Clear();
private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
  std::filesystem::path path_;
  bool enable_fts_;
  BinaryContext context_;
};
} // namespace ida_agent::ai::analysis_memory
