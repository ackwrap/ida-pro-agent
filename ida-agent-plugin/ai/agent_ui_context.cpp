#include "ai/agent_ui_context.hpp"

#include "ai/agent_tool_registry.hpp"

#include "address.hpp"
#include "bridge/ida_executor.hpp"

#include <bytes.hpp>
#include <funcs.hpp>
#include <gdl.hpp>
#include <ida.hpp>
#include <kernwin.hpp>
#include <range.hpp>
#include <segment.hpp>
#include <ua.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace ida_agent::ai
{
namespace
{
using Json = nlohmann::json;

constexpr std::size_t MaxFunctionChunks = 1024;
constexpr std::uint64_t MaxFunctionAnalysisBytes = 1024 * 1024;
constexpr std::size_t MaxSegmentNameBytes = 256;
constexpr std::size_t MaxWidgetTitleBytes = 256;
constexpr std::size_t MaxHighlightBytes = 4096;

std::string TextPrefix(std::string_view source, std::size_t maximum)
{
  if ( source.size() <= maximum ) return std::string(source);
  std::size_t end = maximum;
  while ( end > 0 && (static_cast<unsigned char>(source[end]) & 0xC0) == 0x80 )
    --end;
  return std::string(source.substr(0, end));
}

Json RangeJson(ea_t start, ea_t end)
{
  return Json{
      {"start", rpc::FormatAddress(static_cast<std::uint64_t>(start))},
      {"end", rpc::FormatAddress(static_cast<std::uint64_t>(end))}};
}

Json UiCursor()
{
  const ea_t address = get_screen_ea();
  if ( address == BADADDR )
    return Json{{"address", nullptr}, {"operand", nullptr}};
  const int operand = get_opnum();
  return Json{
      {"address", rpc::FormatAddress(static_cast<std::uint64_t>(address))},
      {"operand", operand < 0 ? Json(nullptr) : Json(operand)}};
}

Json UiSelection()
{
  ea_t first = BADADDR, last = BADADDR;
  if ( !read_range_selection(nullptr, &first, &last) || first == BADADDR || last == BADADDR )
    return Json{{"active", false}, {"start", nullptr}, {"end", nullptr}};
  return Json{
      {"active", true},
      {"start", rpc::FormatAddress(static_cast<std::uint64_t>(first))},
      {"end", rpc::FormatAddress(static_cast<std::uint64_t>(last))}};
}

Json UiHighlight()
{
  TWidget *viewer = get_current_viewer();
  qstring identifier;
  uint32 flags = 0;
  if ( viewer == nullptr
    || !get_highlight(&identifier, viewer, &flags) || identifier.empty() )
    return Json{{"active", false}, {"text", nullptr}, {"flags", 0}};
  std::string text = TextPrefix(identifier.c_str(), MaxHighlightBytes);
  return Json{{"active", true}, {"text", std::move(text)}, {"flags", flags}};
}

const char *WidgetKind(int type)
{
  switch ( type )
  {
    case BWN_UNKNOWN: return "unknown";
    case BWN_DISASM: return "disassembly";
    case BWN_PSEUDOCODE: return "pseudocode";
    case BWN_HEXVIEW: return "hexView";
    case BWN_OUTPUT: return "output";
    case BWN_CLI: return "cli";
    case BWN_CUSTVIEW: return "customViewer";
    default: return "other";
  }
}

Json UiView()
{
  TWidget *widget = get_current_widget();
  if ( widget == nullptr )
    return Json{{"active", false}, {"title", nullptr}, {"kind", "none"}};
  const int type = get_widget_type(widget);
  qstring title;
  const bool titled = get_widget_title(&title, widget);
  Json result{{"active", true}, {"kind", WidgetKind(type)}};
  if ( titled && !title.empty() )
    result["title"] = TextPrefix(title.c_str(), MaxWidgetTitleBytes);
  else
    result["title"] = nullptr;
  return result;
}

Json SegmentInfo(ea_t address)
{
  segment_t *segment = getseg(address);
  if ( segment == nullptr ) return Json(nullptr);
  Json result{
      {"start", rpc::FormatAddress(static_cast<std::uint64_t>(segment->start_ea))},
      {"end", rpc::FormatAddress(static_cast<std::uint64_t>(segment->end_ea))}};
  qstring name;
  const ssize_t size = get_segm_name(&name, segment);
  if ( size > 0 && !name.empty() )
    result["name"] = TextPrefix(name.c_str(), MaxSegmentNameBytes);
  else
    result["name"] = nullptr;
  return result;
}

Json AddressBoundaries(std::uint64_t address)
{
  const ea_t requested = static_cast<ea_t>(address);
  Json result{{"address", rpc::FormatAddress(address)}};
  bool code_item = false;

  if ( is_mapped(requested) )
  {
    Json item = nullptr;
    const ea_t head = get_item_head(requested);
    if ( head != BADADDR && is_mapped(head) )
    {
      const flags64_t flags = get_flags(head);
      code_item = is_code(flags);
      if ( code_item || is_data(flags) )
      {
        const ea_t end = get_item_end(head);
        if ( end != BADADDR && end > head ) item = RangeJson(head, end);
      }
    }
    result["item"] = std::move(item);
  }
  else
  {
    result["item"] = nullptr;
  }
  result["segment"] = SegmentInfo(requested);

  Json function = nullptr;
  Json chunk = nullptr;
  Json basic_block = nullptr;
  const ea_t entry = get_func_start(requested);
  if ( entry != BADADDR )
  {
    rangeset_t ranges;
    if ( get_func_ranges_ea(&ranges, entry) != BADADDR && !ranges.empty()
      && ranges.nranges() <= MaxFunctionChunks )
    {
      function = Json{
          {"entryAddress", rpc::FormatAddress(static_cast<std::uint64_t>(entry))},
          {"start", rpc::FormatAddress(static_cast<std::uint64_t>(ranges.getrange(0).start_ea))},
          {"end", rpc::FormatAddress(static_cast<std::uint64_t>(ranges.lastrange().end_ea))},
          {"chunkCount", static_cast<std::uint64_t>(ranges.nranges())}};
      const std::size_t count = ranges.nranges();
      for ( std::size_t index = 0; index < count; ++index )
      {
        const range_t &range = ranges.getrange(index);
        if ( requested >= range.start_ea && requested < range.end_ea )
        {
          chunk = RangeJson(range.start_ea, range.end_ea);
          break;
        }
      }
      if ( code_item )
      {
        const asize_t size = calc_func_size_ea(entry);
        if ( size != 0 && size <= MaxFunctionAnalysisBytes )
        {
          const qflow_chart_ea_t flow_chart(
              "", entry, BADADDR, BADADDR, FC_NOEXT);
          for ( const qbasic_block_t &block : flow_chart.blocks )
          {
            if ( requested >= block.start_ea && requested < block.end_ea )
            {
              basic_block = RangeJson(block.start_ea, block.end_ea);
              break;
            }
          }
        }
      }
    }
  }
  result["function"] = std::move(function);
  result["chunk"] = std::move(chunk);
  result["basicBlock"] = std::move(basic_block);
  return result;
}
} // namespace

void PopulateAgentUiContextInvokers(
    AgentToolInvokers &invokers,
    bridge::IdaExecutor &executor)
{
  invokers.ui_cursor = [&executor]()
  {
    return executor.ReadFor(std::chrono::seconds(12), []() { return UiCursor(); });
  };
  invokers.ui_selection = [&executor]()
  {
    return executor.ReadFor(std::chrono::seconds(12), []() { return UiSelection(); });
  };
  invokers.ui_highlight = [&executor]()
  {
    return executor.ReadFor(std::chrono::seconds(12), []() { return UiHighlight(); });
  };
  invokers.ui_view = [&executor]()
  {
    return executor.ReadFor(std::chrono::seconds(12), []() { return UiView(); });
  };
  invokers.address_boundaries = [&executor](std::uint64_t address)
  {
    return executor.ReadFor(
        std::chrono::seconds(12), [address]() { return AddressBoundaries(address); });
  };
}

} // namespace ida_agent::ai
