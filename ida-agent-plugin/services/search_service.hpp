#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ida_agent::services
{

enum class SearchStatus
{
  Success,
  InvalidAddress,
  InvalidCursor,
  InvalidPattern,
  NotFound,
  OutputLimit,
};

enum class SignatureMode
{
  Address,
  Function,
  Range,
};

enum class SignatureFormat
{
  Ida,
  X64Dbg,
  Mask,
  Bitmask,
};

struct AddressSearchResult
{
  std::vector<std::uint64_t> items;
  std::optional<std::uint64_t> next_address;
  bool has_more = false;
};

struct InstructionSearchItem
{
  std::uint64_t address;
  std::string bytes;
  std::uint32_t size;
  std::string text;
  std::string mnemonic;
  std::vector<std::string> operands;
};

struct InstructionSearchResult
{
  std::vector<InstructionSearchItem> items;
  std::optional<std::string> next_cursor;
  bool has_more = false;
};

struct ListingSearchItem
{
  std::uint64_t address;
  std::string source;
  std::string text;
};

struct ListingSearchResult
{
  std::vector<ListingSearchItem> items;
  std::optional<std::string> next_cursor;
  bool has_more = false;
};

struct SignatureResult
{
  std::string mode;
  std::uint64_t address;
  std::optional<std::uint64_t> end_address;
  std::string signature;
  std::string format;
  std::uint32_t length;
  bool unique;
};

struct XrefSignatureItem
{
  std::uint64_t xref_address;
  std::string signature;
  std::uint32_t length;
};

struct XrefSignatureResult
{
  std::uint64_t address;
  std::vector<XrefSignatureItem> items;
  std::uint32_t total_xrefs;
  bool truncated;
};

struct AssemblyInstructionResult
{
  std::uint64_t start_address;
  std::uint64_t end_address;
  std::uint32_t offset;
  std::uint32_t size;
};

struct AssemblyResult
{
  std::uint64_t address;
  std::string bytes;
  std::uint32_t size;
  std::vector<AssemblyInstructionResult> instructions;
};

template <typename Result>
struct SearchOutcome
{
  SearchStatus status;
  std::optional<Result> result;
};

using AddressSearchOutcome = SearchOutcome<AddressSearchResult>;
using InstructionSearchOutcome = SearchOutcome<InstructionSearchResult>;
using ListingSearchOutcome = SearchOutcome<ListingSearchResult>;
using SignatureOutcome = SearchOutcome<SignatureResult>;
using XrefSignatureOutcome = SearchOutcome<XrefSignatureResult>;
using AssemblyOutcome = SearchOutcome<AssemblyResult>;

class SearchService
{
public:
  AddressSearchOutcome Bytes(
      std::string_view pattern,
      std::uint64_t start,
      std::uint64_t end,
      std::uint32_t limit) const;
  InstructionSearchOutcome Instructions(
      std::uint64_t start,
      std::uint64_t end,
      std::string_view mnemonic,
      std::string_view operand,
      std::uint32_t limit,
      const std::optional<std::string> &cursor) const;
  ListingSearchOutcome Listing(
      std::uint64_t start,
      std::uint64_t end,
      std::string_view pattern,
      bool regular_expression,
      bool include_disassembly,
      bool include_comments,
      std::uint32_t limit,
      const std::optional<std::string> &cursor) const;
  SignatureOutcome MakeSignature(
      SignatureMode mode,
      std::uint64_t address,
      std::optional<std::uint64_t> end,
      SignatureFormat format,
      bool wildcard_operands,
      std::uint32_t max_length) const;
  XrefSignatureOutcome XrefSignatures(
      std::uint64_t address,
      SignatureFormat format,
      bool wildcard_operands,
      std::uint32_t max_length,
      std::uint32_t top) const;
  AssemblyOutcome Assemble(std::uint64_t address, std::string_view instruction) const;
};

nlohmann::json ToJson(const AddressSearchResult &result);
nlohmann::json ToJson(const InstructionSearchResult &result);
nlohmann::json ToJson(const ListingSearchResult &result);
nlohmann::json ToJson(const SignatureResult &result);
nlohmann::json ToJson(const XrefSignatureResult &result);
nlohmann::json ToJson(const AssemblyResult &result);

} // namespace ida_agent::services
