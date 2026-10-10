#include "annotation_service.hpp"
#include "query_helpers.hpp"
#include "address.hpp"
#include <bytes.hpp>
#include <funcs.hpp>
#include <kernwin.hpp>
#include <moves.hpp>
#include <lines.hpp>
#include <algorithm>
#include <limits>

namespace ida_agent::services
{
using namespace query;
namespace
{
constexpr std::uint32_t MaxTextBytes = 16 * 1024;
}

QueryResult AnnotationService::CommentGet(
    std::uint64_t address,
    const std::string &scope,
    bool repeatable) const
{
  ea_t ea = BADADDR;
  if ( !StableAddress(address, &ea) || !is_mapped(ea) )
    return {QueryStatus::InvalidAddress, {}};
  ea_t result_address = ea;
  qstring comment;
  ssize_t length = -1;
  if ( scope == "function" )
  {
    result_address = get_func_start(ea);
    if ( result_address == BADADDR ) return {QueryStatus::NotFound, {}};
    length = get_func_cmt_ea(&comment, result_address, repeatable);
  }
  else
  {
    length = get_cmt(&comment, ea, repeatable);
  }
  if ( length <= 0 ) return {QueryStatus::NotFound, {}};
  qstring plain;
  if ( tag_remove(&plain, comment) < 0 ) return {QueryStatus::OutputLimit, {}};
  std::string text(plain.c_str(), plain.length());
  if ( !BoundedUtf8(text, MaxTextBytes) ) return {QueryStatus::OutputLimit, {}};
  return {QueryStatus::Success, {
      {"address", rpc::FormatAddress(result_address)},
      {"scope", scope}, {"repeatable", repeatable}, {"text", std::move(text)},
  }};
}

QueryResult AnnotationService::BookmarkList(std::uint32_t limit, std::uint32_t cursor) const
{
  nlohmann::json items = nlohmann::json::array();
  std::uint32_t position = cursor;
  while ( position < MAX_MARK_SLOT && items.size() < limit )
  {
    const std::uint32_t slot = position++;
    idaplace_t place(0, 0);
    renderer_info_t renderer(TCCRT_FLAT, 0, 0);
    lochist_entry_t entry(&place, renderer);
    qstring description;
    std::uint32_t index = slot;
    if ( !bookmarks_t::get(&entry, &description, &index, nullptr) || index != slot
      || entry.renderer_info().rtype != TCCRT_FLAT || entry.place() == nullptr
      || entry.place()->id() != place.id() )
      continue;
    const auto *ida_place = static_cast<const idaplace_t *>(entry.place());
    if ( ida_place->ea == BADADDR ) continue;
    std::string text(description.c_str(), description.length());
    if ( !BoundedUtf8(text, MaxTextBytes) ) return {QueryStatus::OutputLimit, {}};
    items.push_back({
        {"slot", slot}, {"address", rpc::FormatAddress(ida_place->ea)},
        {"line", (std::max)(ida_place->lnnum, 0)}, {"description", std::move(text)},
    });
  }
  const bool more = position < MAX_MARK_SLOT;
  return {QueryStatus::Success, {
      {"items", std::move(items)},
      {"nextCursor", more ? nlohmann::json(position) : nlohmann::json(nullptr)},
      {"hasMore", more},
  }};
}
}
