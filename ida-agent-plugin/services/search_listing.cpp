#include "search_service.hpp"

#include "search_internal.hpp"
#include "safe_regex.hpp"

#include "list_cursor.hpp"

#include <bytes.hpp>
#include <lines.hpp>

#include <optional>
#include <regex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace ida_agent::services
{

ListingSearchOutcome SearchService::Listing(
    std::uint64_t start,
    std::uint64_t end,
    std::string_view pattern,
    bool regular_expression,
    bool include_disassembly,
    bool include_comments,
    std::uint32_t limit,
    const std::optional<std::string> &cursor) const
{
  ea_t current = BADADDR;
  ea_t last = BADADDR;
  if ( !search_detail::Range(start, end, &current, &last) )
    return {SearchStatus::InvalidAddress, std::nullopt};
  if ( pattern.empty() || (!include_disassembly && !include_comments) )
    return {SearchStatus::InvalidPattern, std::nullopt};
  const std::string filter = search_detail::Lower(pattern);
  std::optional<std::regex> expression;
  if ( regular_expression )
  {
    if ( !IsSafeRegex(pattern) )
      return {SearchStatus::InvalidPattern, std::nullopt};
    try
    {
      expression.emplace(std::string(pattern), std::regex::ECMAScript | std::regex::icase);
    }
    catch ( const std::regex_error & )
    {
      return {SearchStatus::InvalidPattern, std::nullopt};
    }
  }
  const std::string identity = search_detail::SearchIdentity(start, end, {
      pattern,
      regular_expression ? "regex" : "query",
      include_disassembly ? "disassembly" : "",
      include_comments ? "comments" : "",
  });
  if ( cursor )
  {
    try
    {
      const std::uint64_t decoded = rpc::DecodeListCursor("lt1", *cursor, identity);
      current = static_cast<ea_t>(decoded);
      if ( static_cast<std::uint64_t>(current) != decoded || current == BADADDR
        || current < static_cast<ea_t>(start) || current >= last
        || get_item_head(current) != current )
      {
        return {SearchStatus::InvalidCursor, std::nullopt};
      }
    }
    catch ( const std::invalid_argument & )
    {
      return {SearchStatus::InvalidCursor, std::nullopt};
    }
  }
  ListingSearchResult result;
  std::size_t scanned = 0;
  if ( !cursor )
  {
    current = get_item_head(current);
    if ( current != BADADDR && current < static_cast<ea_t>(start) )
      current = next_head(current, last);
  }
  const auto matches = [&filter, &expression](const std::string &text)
  {
    return expression
        ? std::regex_search(text, *expression)
        : search_detail::Lower(text).find(filter) != std::string::npos;
  };
  while ( current != BADADDR && current < last && scanned++ < search_detail::MaxSearchScan )
  {
    std::string matched_text;
    const char *source = nullptr;
    if ( include_disassembly )
    {
      qstring generated;
      const std::string text = generate_disasm_line(&generated, current, GENDSM_REMOVE_TAGS)
          ? search_detail::Untag(generated)
          : std::string{};
      if ( !text.empty() && matches(text) )
      {
        matched_text = text;
        source = "disassembly";
      }
    }
    if ( source == nullptr && include_comments )
    {
      qstring regular, repeatable;
      std::string text;
      if ( get_cmt(&regular, current, false) > 0 ) text = search_detail::Untag(regular);
      if ( get_cmt(&repeatable, current, true) > 0 )
      {
        const std::string repeated = search_detail::Untag(repeatable);
        if ( !text.empty() && !repeated.empty() ) text.push_back('\n');
        text += repeated;
      }
      if ( text.size() > search_detail::MaxTextBytes ) return {SearchStatus::OutputLimit, std::nullopt};
      if ( !text.empty() && matches(text) )
      {
        matched_text = std::move(text);
        source = "comment";
      }
    }
    if ( source != nullptr )
    {
      if ( result.items.size() == limit )
      {
        result.has_more = true;
        result.next_cursor = rpc::EncodeListCursor("lt1", identity, current);
        break;
      }
      result.items.push_back({current, source, std::move(matched_text)});
    }
    current = next_head(current, last);
  }
  if ( !result.has_more && scanned == search_detail::MaxSearchScan && current != BADADDR && current < last )
  {
    result.has_more = true;
    result.next_cursor = rpc::EncodeListCursor("lt1", identity, current);
  }
  return {SearchStatus::Success, std::move(result)};
}

} // namespace ida_agent::services
