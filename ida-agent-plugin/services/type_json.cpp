#include "type_service.hpp"

#include "address.hpp"

#include <iomanip>
#include <sstream>
#include <utility>

namespace ida_agent::services
{
namespace
{

std::string HexUnsigned(std::uint64_t value)
{
  std::ostringstream output;
  output << "0x" << std::hex << value;
  return output.str();
}

nlohmann::json ToJson(const TypeSummary &item)
{
  return {{"ordinal", item.ordinal}, {"name", item.name}, {"kind", item.kind}, {"size", item.size}};
}

} // namespace

nlohmann::json ToJson(const TypeDetails &result)
{
  nlohmann::json members = nlohmann::json::array();
  for ( const auto &member : result.members )
  {
    members.push_back({
        {"name", member.name}, {"declaration", member.declaration},
        {"bitOffset", member.bit_offset}, {"bitSize", member.bit_size}});
  }
  nlohmann::json enum_members = nlohmann::json::array();
  for ( const auto &member : result.enum_members )
    enum_members.push_back({{"name", member.name}, {"value", HexUnsigned(member.value)}});
  nlohmann::json related = nlohmann::json::array();
  for ( const std::string &name : result.related_types ) related.push_back(name);
  auto output = ToJson(result.summary);
  output["declaration"] = result.declaration;
  output["declarationOriginalSize"] = result.declaration_original_size;
  output["declarationTruncated"] = result.declaration_truncated;
  output["members"] = std::move(members);
  output["memberCount"] = result.member_count;
  output["membersTruncated"] = result.members_truncated;
  output["enumMembers"] = std::move(enum_members);
  output["enumMemberCount"] = result.enum_member_count;
  output["enumMembersTruncated"] = result.enum_members_truncated;
  output["relatedTypes"] = std::move(related);
  output["relatedTypeCount"] = result.related_type_count;
  output["relatedTypesTruncated"] = result.related_types_truncated;
  return output;
}

nlohmann::json ToJson(const TypeSearchResult &result)
{
  nlohmann::json items = nlohmann::json::array();
  for ( const auto &item : result.items ) items.push_back(ToJson(item));
  return {
      {"items", std::move(items)},
      {"nextOrdinal", result.next_ordinal ? nlohmann::json(*result.next_ordinal) : nlohmann::json(nullptr)},
      {"hasMore", result.has_more},
  };
}

nlohmann::json ToJson(const TypedValueResult &result)
{
  nlohmann::json fields = nlohmann::json::array();
  for ( const auto &field : result.fields )
  {
    fields.push_back({
        {"name", field.name}, {"declaration", field.declaration},
        {"byteOffset", field.byte_offset}, {"size", field.size},
        {"format", field.format}, {"value", field.value}, {"truncated", field.truncated}});
  }
  return {
      {"address", rpc::FormatAddress(result.address)}, {"type", ToJson(result.type)},
      {"bytes", result.bytes}, {"bytesRead", result.bytes_read},
      {"originalSize", result.original_size}, {"truncated", result.truncated},
      {"fields", std::move(fields)}, {"fieldsTruncated", result.fields_truncated},
  };
}

nlohmann::json ToJson(const GlobalValueResult &result)
{
  return {
      {"address", rpc::FormatAddress(result.address)},
      {"symbol", result.symbol ? nlohmann::json(*result.symbol) : nlohmann::json(nullptr)},
      {"declaration", result.declaration ? nlohmann::json(*result.declaration) : nlohmann::json(nullptr)},
      {"size", result.size}, {"bytesRead", result.bytes_read}, {"format", result.format},
      {"value", result.value}, {"truncated", result.truncated},
  };
}

nlohmann::json ToJson(const StackFrameResult &result)
{
  nlohmann::json variables = nlohmann::json::array();
  for ( const auto &item : result.variables )
  {
    variables.push_back({
        {"name", item.name}, {"declaration", item.declaration},
        {"bitOffset", item.bit_offset}, {"bitSize", item.bit_size}, {"role", item.role}});
  }
  return {{"entryAddress", rpc::FormatAddress(result.entry_address)}, {"size", result.size}, {"variables", std::move(variables)}};
}

nlohmann::json ToJson(const TypeInferenceResult &result)
{
  return {{"address", rpc::FormatAddress(result.address)}, {"declaration", result.declaration}, {"source", result.source}};
}

nlohmann::json ToJson(const StructFieldXrefResult &result)
{
  nlohmann::json items = nlohmann::json::array();
  for ( auto ea : result.items ) items.push_back(rpc::FormatAddress(ea));
  return {{"items", std::move(items)}, {"truncated", result.truncated}};
}

} // namespace ida_agent::services
