#pragma once
#include "query_result.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ida_agent::services
{

enum class TypeStatus { Success, InvalidAddress, InvalidArgument, NotFound, OutputLimit };

struct TypeSummary { std::uint32_t ordinal; std::string name; std::string kind; std::uint64_t size; };
struct TypeMember { std::string name; std::string declaration; std::uint64_t bit_offset; std::uint64_t bit_size; };
struct EnumMember { std::string name; std::uint64_t value; };
struct TypeDetails
{
  TypeSummary summary;
  std::string declaration;
  std::uint64_t declaration_original_size = 0;
  bool declaration_truncated = false;
  std::vector<TypeMember> members;
  std::uint64_t member_count = 0;
  bool members_truncated = false;
  std::vector<EnumMember> enum_members;
  std::uint64_t enum_member_count = 0;
  bool enum_members_truncated = false;
  std::vector<std::string> related_types;
  std::uint64_t related_type_count = 0;
  bool related_types_truncated = false;
};
struct TypeSearchResult { std::vector<TypeDetails> items; std::optional<std::uint32_t> next_ordinal; bool has_more = false; };
struct TypedFieldValue
{
  std::string name;
  std::string declaration;
  std::uint64_t byte_offset;
  std::uint64_t size;
  std::string format;
  std::string value;
  bool truncated = false;
};
struct TypedValueResult
{
  std::uint64_t address;
  TypeDetails type;
  std::string bytes;
  std::uint64_t bytes_read = 0;
  std::uint64_t original_size = 0;
  bool truncated = false;
  std::vector<TypedFieldValue> fields;
  bool fields_truncated = false;
};
struct GlobalValueResult
{
  std::uint64_t address;
  std::optional<std::string> symbol;
  std::optional<std::string> declaration;
  std::uint64_t size;
  std::uint64_t bytes_read;
  std::string format;
  std::string value;
  bool truncated = false;
};
struct StackVariable { std::string name; std::string declaration; std::int64_t bit_offset; std::uint64_t bit_size; std::string role; };
struct StackFrameResult { std::uint64_t entry_address; std::uint64_t size; std::vector<StackVariable> variables; };
struct TypeInferenceResult { std::uint64_t address; std::string declaration; std::string source; };
struct StructFieldXrefResult { std::vector<std::uint64_t> items; bool truncated = false; };

template <typename Result> struct TypeOutcome { TypeStatus status; std::optional<Result> result; };
using TypeSearchOutcome = TypeOutcome<TypeSearchResult>;
using TypeDetailsOutcome = TypeOutcome<TypeDetails>;
using TypedValueOutcome = TypeOutcome<TypedValueResult>;
using GlobalValueOutcome = TypeOutcome<GlobalValueResult>;
using StackFrameOutcome = TypeOutcome<StackFrameResult>;
using TypeInferenceOutcome = TypeOutcome<TypeInferenceResult>;
using StructFieldXrefOutcome = TypeOutcome<StructFieldXrefResult>;

class TypeService
{
public:
  QueryResult TypeXrefs(
      const std::string &name,
      std::uint32_t limit,
      std::uint32_t cursor) const;
  TypeSearchOutcome Search(std::string_view name, std::string_view kind, std::uint32_t ordinal, std::uint32_t limit) const;
  TypeDetailsOutcome Get(std::string_view name) const;
  TypedValueOutcome ReadValue(std::uint64_t address, std::string_view name, std::uint32_t max_bytes) const;
  TypedValueOutcome ReadStruct(std::uint64_t address, std::string_view name, std::uint32_t max_bytes) const;
  GlobalValueOutcome GlobalValue(
      const std::optional<std::uint64_t> &address,
      const std::optional<std::string> &symbol,
      std::uint32_t max_bytes) const;
  StackFrameOutcome StackFrame(std::uint64_t address) const;
  TypeInferenceOutcome Infer(std::uint64_t address) const;
  StructFieldXrefOutcome FieldXrefs(std::string_view type_name, std::string_view field_name, std::uint32_t limit) const;
};

nlohmann::json ToJson(const TypeSearchResult &result);
nlohmann::json ToJson(const TypeDetails &result);
nlohmann::json ToJson(const TypedValueResult &result);
nlohmann::json ToJson(const GlobalValueResult &result);
nlohmann::json ToJson(const StackFrameResult &result);
nlohmann::json ToJson(const TypeInferenceResult &result);
nlohmann::json ToJson(const StructFieldXrefResult &result);

} // namespace ida_agent::services
