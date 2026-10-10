#include "search_service.hpp"

#include "address.hpp"

#include <utility>

namespace ida_agent::services
{

nlohmann::json ToJson(const AddressSearchResult &result)
{
  nlohmann::json items = nlohmann::json::array();
  for ( auto address : result.items ) items.push_back(rpc::FormatAddress(address));
  return {{"items", std::move(items)}, {"nextAddress", result.next_address ? nlohmann::json(rpc::FormatAddress(*result.next_address)) : nlohmann::json(nullptr)}, {"hasMore", result.has_more}};
}

nlohmann::json ToJson(const InstructionSearchResult &result)
{
  nlohmann::json items = nlohmann::json::array();
  for ( const auto &item : result.items ) items.push_back({
      {"address", rpc::FormatAddress(item.address)}, {"bytes", item.bytes}, {"size", item.size},
      {"text", item.text}, {"mnemonic", item.mnemonic}, {"operands", item.operands}});
  return {{"items", std::move(items)}, {"nextCursor", result.next_cursor ? nlohmann::json(*result.next_cursor) : nlohmann::json(nullptr)}, {"hasMore", result.has_more}};
}

nlohmann::json ToJson(const ListingSearchResult &result)
{
  nlohmann::json items = nlohmann::json::array();
  for ( const auto &item : result.items ) items.push_back({{"address", rpc::FormatAddress(item.address)}, {"source", item.source}, {"text", item.text}});
  return {{"items", std::move(items)}, {"nextCursor", result.next_cursor ? nlohmann::json(*result.next_cursor) : nlohmann::json(nullptr)}, {"hasMore", result.has_more}};
}

nlohmann::json ToJson(const SignatureResult &result)
{
  return {
      {"mode", result.mode},
      {"address", rpc::FormatAddress(result.address)},
      {"endAddress", result.end_address ? nlohmann::json(rpc::FormatAddress(*result.end_address)) : nlohmann::json(nullptr)},
      {"signature", result.signature},
      {"format", result.format},
      {"length", result.length},
      {"unique", result.unique},
  };
}

nlohmann::json ToJson(const XrefSignatureResult &result)
{
  nlohmann::json items = nlohmann::json::array();
  for ( const auto &item : result.items )
  {
    items.push_back({
        {"xrefAddress", rpc::FormatAddress(item.xref_address)},
        {"signature", item.signature},
        {"length", item.length},
    });
  }
  return {
      {"address", rpc::FormatAddress(result.address)},
      {"items", std::move(items)},
      {"totalXrefs", result.total_xrefs},
      {"truncated", result.truncated},
  };
}

nlohmann::json ToJson(const AssemblyResult &result)
{
  nlohmann::json instructions = nlohmann::json::array();
  for ( const auto &item : result.instructions )
  {
    instructions.push_back({
        {"startAddress", rpc::FormatAddress(item.start_address)},
        {"endAddress", rpc::FormatAddress(item.end_address)},
        {"offset", item.offset},
        {"size", item.size},
    });
  }
  return {
      {"address", rpc::FormatAddress(result.address)},
      {"bytes", result.bytes},
      {"size", result.size},
      {"instructions", std::move(instructions)},
  };
}

} // namespace ida_agent::services
