#include "changeset_annotations.hpp"

#include <ida.hpp>
#include <funcs.hpp>
#include <hexrays.hpp>
#include <kernwin.hpp>
#include <moves.hpp>

namespace ida_agent::services::detail
{
namespace
{
lochist_entry_t BookmarkLocation(ea_t ea)
{
  idaplace_t place(ea, 0);
  renderer_info_t renderer;
  renderer.rtype = TCCRT_FLAT;
  return lochist_entry_t(&place, renderer);
}
} // namespace

std::optional<std::string> CurrentPseudocodeComment(std::uint64_t address)
{
  const ea_t ea = static_cast<ea_t>(address);
  try
  {
    cfuncptr_t function = decompile(ea);
    if ( function == nullptr ) return std::nullopt;
    if ( ea == function->entry_ea )
    {
      qstring comment;
      const func_t *target = get_func(ea);
      if ( target == nullptr ) return std::nullopt;
      get_func_cmt(&comment, target, true);
      return std::string(comment.c_str(), comment.length());
    }
    auto &map = function->get_eamap();
    auto found = map.find(ea);
    if ( found == map.end() || found->second.empty() || found->second.front() == nullptr ) return std::nullopt;
    const ea_t location = found->second.front()->ea;
    for ( int precise = ITP_SEMI; precise < ITP_COLON; ++precise )
    {
      const treeloc_t tree_location{location, static_cast<item_preciser_t>(precise)};
      const char *comment = function->get_user_cmt(tree_location, RETRIEVE_ALWAYS);
      if ( comment != nullptr ) return std::string(comment);
    }
    return std::string{};
  }
  catch ( const hexrays_failure_t & ) { return std::nullopt; }
}

bool ApplyPseudocodeComment(std::uint64_t address, const std::string &comment)
{
  const ea_t ea = static_cast<ea_t>(address);
  try
  {
    cfuncptr_t function = decompile(ea);
    if ( function == nullptr ) return false;
    if ( ea == function->entry_ea )
    {
      const func_t *target = get_func(ea);
      if ( target == nullptr || !set_func_cmt(target, comment.c_str(), true) ) return false;
      function->refresh_func_ctext();
      return true;
    }
    auto &map = function->get_eamap();
    auto found = map.find(ea);
    if ( found == map.end() || found->second.empty() || found->second.front() == nullptr ) return false;
    const ea_t location = found->second.front()->ea;
    if ( function->has_orphan_cmts() )
    {
      function->del_orphan_cmts();
      function->save_user_cmts();
    }
    for ( int precise = ITP_SEMI; precise < ITP_COLON; ++precise )
    {
      const treeloc_t tree_location{location, static_cast<item_preciser_t>(precise)};
      function->set_user_cmt(tree_location, comment.c_str());
      function->save_user_cmts();
      if ( !function->has_orphan_cmts() ) { function->refresh_func_ctext(); return true; }
      function->del_orphan_cmts();
      function->save_user_cmts();
    }
    return false;
  }
  catch ( const hexrays_failure_t & ) { return false; }
}

std::optional<std::string> CurrentBookmark(std::uint64_t address)
{
  const lochist_entry_t location = BookmarkLocation(static_cast<ea_t>(address));
  const uint32 index = bookmarks_t::find_index(location, nullptr);
  if ( index == BOOKMARKS_BAD_INDEX ) return std::string{};
  qstring description;
  return bookmarks_t::get_desc(&description, location, index, nullptr)
      ? std::optional<std::string>(std::string(description.c_str(), description.length()))
      : std::optional<std::string>(std::string{});
}

bool ApplyBookmark(std::uint64_t address, const std::string &description)
{
  const lochist_entry_t location = BookmarkLocation(static_cast<ea_t>(address));
  uint32 index = bookmarks_t::find_index(location, nullptr);
  if ( index == BOOKMARKS_BAD_INDEX ) index = bookmarks_t::size(location, nullptr);
  if ( index >= MAX_MARK_SLOT ) return false;
  return bookmarks_t::mark(location, index, nullptr, description.c_str(), nullptr) != BOOKMARKS_BAD_INDEX;
}

} // namespace ida_agent::services::detail
