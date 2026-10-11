#pragma once

#include <nlohmann/json.hpp>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ida_agent::ai::analysis_memory
{
inline constexpr std::size_t MaxFactBytes = 4096;
inline constexpr std::size_t MaxEvidence = 8;
inline constexpr std::size_t MaxContextBytes = 8192;

struct BinaryContext
{
  std::string key;
  std::string revision;
  std::uint64_t image_base = 0;
  std::optional<std::uint64_t> cursor_rva;
  std::optional<std::uint64_t> function_rva;
};

struct Evidence
{
  std::optional<std::uint64_t> rva;
  std::string tool;
  std::string call_id;
  std::string result_sha256;
  std::string revision;
};

struct Fact
{
  std::int64_t id = 0;
  std::string text;
  std::string kind = "note";
  std::string status = "active";
  std::optional<std::uint64_t> anchor_rva;
  std::vector<Evidence> evidence;
  std::string source = "user";
  std::string session;
  std::string revision;
  std::int64_t created_at = 0;
  std::int64_t updated_at = 0;
};

bool ValidText(std::string_view text, std::size_t limit, bool empty = false);
bool ValidContext(const BinaryContext &context);
bool ValidFact(const Fact &fact);
std::string BinaryKey(std::string_view sha256, std::string_view normalized_idb);
std::string DatabaseRevision(std::string_view normalized_idb, std::uint32_t change_count);
std::string Hex(std::uint64_t value);
std::optional<std::uint64_t> ParseHex(std::string_view value);
nlohmann::json EncodeFact(const Fact &fact);
std::optional<Fact> DecodeFact(const nlohmann::json &value);
nlohmann::json PresentFact(const Fact &fact, const BinaryContext &context);
std::string BuildMemoryContext(const std::vector<Fact> &facts,
    const BinaryContext &context, std::size_t budget = MaxContextBytes);
} // namespace ida_agent::ai::analysis_memory
