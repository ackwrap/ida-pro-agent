#include "ai/agent_tool_catalog.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <string>
#include <utility>

namespace ida_agent::ai
{
namespace
{

using Json = nlohmann::json;

constexpr std::size_t MaxSearchQueryBytes = 256;
constexpr std::uint32_t DefaultSearchResults = 6;
constexpr std::uint32_t MaxSearchResults = 12;
constexpr std::array<std::string_view, 9> CoreToolNames{{
    "ida_database_info",
    "ida_ui_cursor",
    "ida_ui_selection",
    "ida_ui_highlight",
    "ida_ui_view",
    "ida_address_boundaries",
    "ida_function_get",
    "ida_decompile",
    "ida_xref_query",
}};

struct Match
{
  const AgentToolDefinition *definition = nullptr;
  int score = 0;
  std::size_t index = 0;
};

std::string LowerAscii(std::string_view value)
{
  std::string result(value);
  std::transform(
      result.begin(), result.end(), result.begin(),
      [](unsigned char character)
      {
        return character < 0x80
            ? static_cast<char>(std::tolower(character))
            : static_cast<char>(character);
      });
  return result;
}

bool IsStopWord(std::string_view value) noexcept
{
  constexpr std::array<std::string_view, 22> words{{
      "a", "an", "and", "for", "find", "get", "ida", "in",
      "list", "need", "of", "on", "or", "read", "search", "show",
      "the", "to", "tool", "tools", "use", "want",
  }};
  return std::find(words.begin(), words.end(), value) != words.end();
}

std::vector<std::string> SearchTerms(std::string_view query)
{
  std::vector<std::string> terms;
  std::string term;
  const auto flush = [&terms, &term]()
  {
    if ( !term.empty() && !IsStopWord(term)
        && std::find(terms.begin(), terms.end(), term) == terms.end() )
    {
      terms.push_back(term);
    }
    term.clear();
  };
  for ( const unsigned char character : query )
  {
    if ( character < 0x80 && std::isalnum(character) != 0 )
      term.push_back(static_cast<char>(std::tolower(character)));
    else
      flush();
  }
  flush();
  return terms;
}

bool ValidSearchText(std::string_view value) noexcept
{
  if ( value.empty() || value.size() > MaxSearchQueryBytes )
    return false;
  for ( const unsigned char character : value )
    if ( character < 0x20 || character == 0x7F )
      return false;
  return true;
}

bool ValidCallId(std::string_view value) noexcept
{
  if ( value.empty() || value.size() > MaxAgentToolCallIdBytes )
    return false;
  std::size_t offset = 0;
  while ( offset < value.size() )
  {
    const unsigned char first = static_cast<unsigned char>(value[offset]);
    std::uint32_t point = 0;
    std::size_t width = 0;
    if ( first < 0x80 ) { point = first; width = 1; }
    else if ( first >= 0xC2 && first <= 0xDF ) { point = first & 0x1F; width = 2; }
    else if ( first >= 0xE0 && first <= 0xEF ) { point = first & 0x0F; width = 3; }
    else if ( first >= 0xF0 && first <= 0xF4 ) { point = first & 7; width = 4; }
    else return false;
    if ( offset + width > value.size() )
      return false;
    for ( std::size_t index = 1; index < width; ++index )
    {
      const unsigned char continuation =
          static_cast<unsigned char>(value[offset + index]);
      if ( (continuation & 0xC0) != 0x80 )
        return false;
      point = (point << 6) | (continuation & 0x3F);
    }
    if ( (width == 2 && point < 0x80)
        || (width == 3 && point < 0x800)
        || (width == 4 && point < 0x10000)
        || (point >= 0xD800 && point <= 0xDFFF)
        || point > 0x10FFFF || point < 0x20
        || (point >= 0x7F && point <= 0x9F) )
    {
      return false;
    }
    offset += width;
  }
  return true;
}

std::optional<std::uint32_t> SearchLimit(const Json &arguments)
{
  const auto found = arguments.find("limit");
  if ( found == arguments.end() )
    return DefaultSearchResults;
  if ( !found->is_number_integer() && !found->is_number_unsigned() )
  {
    return std::nullopt;
  }
  std::uint64_t value = 0;
  if ( found->is_number_unsigned() )
  {
    value = found->get<std::uint64_t>();
  }
  else
  {
    const std::int64_t signed_value = found->get<std::int64_t>();
    if ( signed_value < 1 )
      return std::nullopt;
    value = static_cast<std::uint64_t>(signed_value);
  }
  return value >= 1 && value <= MaxSearchResults
      ? std::optional<std::uint32_t>(static_cast<std::uint32_t>(value))
      : std::nullopt;
}

int MatchScore(
    const AgentToolDefinition &definition,
    std::string_view lowered_query,
    const std::vector<std::string> &terms)
{
  const std::string name = LowerAscii(definition.name);
  const std::string description = LowerAscii(definition.description);
  const std::string parameters = LowerAscii(definition.parameters.dump());
  int score = 0;
  if ( name == lowered_query )
    score += 10000;
  if ( name.size() > 4 && name.substr(4) == lowered_query )
    score += 8000;
  if ( !lowered_query.empty() && name.find(lowered_query) != std::string::npos )
    score += 1000;
  std::size_t matched_terms = 0;
  for ( const std::string &term : terms )
  {
    const std::size_t name_offset = name.find(term);
    if ( name_offset != std::string::npos )
    {
      score += 200 + (name_offset == 4 ? 50 : 0);
      ++matched_terms;
    }
    else if ( description.find(term) != std::string::npos )
    {
      score += 40;
      ++matched_terms;
    }
    else if ( parameters.find(term) != std::string::npos )
    {
      score += 20;
      ++matched_terms;
    }
  }
  if ( !terms.empty() && matched_terms == terms.size() )
    score += 500;
  return score;
}

AgentToolResult SearchFailure(const AgentToolCall &call)
{
  return {
      ValidCallId(call.id) ? call.id : std::string(),
      call.name == AgentToolSearchName ? call.name : std::string(),
      false,
      {},
      "Tool search call is invalid.",
  };
}

} // namespace

const AgentToolDefinition &AgentToolSearchDefinition()
{
  static const AgentToolDefinition definition{
      std::string(AgentToolSearchName),
      "Search the unloaded IDA tool catalog by capability. Matching tools are loaded for the next Agent turn.",
      Json{
          {"type", "object"},
          {"properties", {
              {"query", {
                  {"type", "string"},
                  {"description", "Concise capability terms, for example: decompiler locals or rename function."},
                  {"minLength", 1},
                  {"maxLength", MaxSearchQueryBytes}}},
              {"limit", {
                  {"type", "integer"},
                  {"minimum", 1},
                  {"maximum", MaxSearchResults},
                  {"default", DefaultSearchResults}}},
          }},
          {"required", Json::array({"query", "limit"})},
          {"additionalProperties", false},
      },
  };
  return definition;
}

std::vector<AgentToolDefinition> InitialAgentToolDefinitions(
    const std::vector<AgentToolDefinition> &catalog)
{
  std::vector<AgentToolDefinition> result{AgentToolSearchDefinition()};
  for ( const std::string_view name : CoreToolNames )
  {
    const auto found = std::find_if(
        catalog.begin(), catalog.end(),
        [name](const AgentToolDefinition &definition)
        {
          return definition.name == name;
        });
    if ( found != catalog.end() )
      result.push_back(*found);
  }
  return result;
}

void AgentToolCatalogSession::Begin(std::vector<AgentToolDefinition> catalog)
{
  Reset();
  catalog_ = std::move(catalog);
  active_ = InitialAgentToolDefinitions(catalog_);
}

void AgentToolCatalogSession::Reset() noexcept
{
  catalog_.clear();
  active_.clear();
}

bool AgentToolCatalogSession::IsActive(std::string_view name) const noexcept
{
  return std::any_of(
      active_.begin(), active_.end(),
      [name](const AgentToolDefinition &definition)
      {
        return definition.name == name;
      });
}

const std::vector<AgentToolDefinition> &
AgentToolCatalogSession::ActiveDefinitions() const noexcept
{
  return active_;
}

std::optional<AgentToolResult> AgentToolCatalogSession::Invoke(
    const AgentToolCall &call)
{
  if ( call.name != AgentToolSearchName )
    return std::nullopt;
  if ( !ValidCallId(call.id)
      || call.arguments_json.size() > MaxAgentToolArgumentsBytes )
    return SearchFailure(call);

  const Json arguments = Json::parse(
      call.arguments_json.begin(), call.arguments_json.end(), nullptr, false);
  if ( !arguments.is_object() || arguments.empty() || arguments.size() > 2
      || !arguments.contains("query") || !arguments["query"].is_string()
      || (arguments.size() == 2 && !arguments.contains("limit")) )
  {
    return SearchFailure(call);
  }
  const std::string query = arguments["query"].get<std::string>();
  const std::optional<std::uint32_t> limit = SearchLimit(arguments);
  if ( !ValidSearchText(query) || !limit.has_value() )
    return SearchFailure(call);

  const std::string lowered_query = LowerAscii(query);
  const std::vector<std::string> terms = SearchTerms(query);
  std::vector<Match> matches;
  matches.reserve(catalog_.size());
  for ( std::size_t index = 0; index < catalog_.size(); ++index )
  {
    const AgentToolDefinition &definition = catalog_[index];
    if ( IsActive(definition.name) )
      continue;
    const int score = MatchScore(definition, lowered_query, terms);
    if ( score != 0 )
      matches.push_back({&definition, score, index});
  }
  std::stable_sort(
      matches.begin(), matches.end(),
      [](const Match &left, const Match &right)
      {
        return left.score > right.score
            || (left.score == right.score && left.index < right.index);
      });
  if ( matches.size() > *limit )
    matches.resize(*limit);

  Json tools = Json::array();
  std::vector<const AgentToolDefinition *> to_load;
  to_load.reserve(matches.size());
  for ( const Match &match : matches )
  {
    tools.push_back({
        {"name", match.definition->name},
        {"description", match.definition->description},
    });
    to_load.push_back(match.definition);
  }

  Json output{
      {"tools", std::move(tools)},
      {"newlyLoaded", to_load.size()},
      {"activeTools", active_.size() + to_load.size()},
      {"catalogTools", catalog_.size()},
  };
  const std::string encoded = output.dump();
  if ( encoded.size() > MaxAgentToolResultBytes )
    return SearchFailure(call);
  for ( const AgentToolDefinition *definition : to_load )
    active_.push_back(*definition);
  return AgentToolResult{call.id, call.name, true, encoded, {}};
}

} // namespace ida_agent::ai
