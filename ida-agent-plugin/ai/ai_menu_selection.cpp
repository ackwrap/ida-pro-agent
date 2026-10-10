#include "ai/ai_menu_selection.hpp"

#include <bytes.hpp>
#include <hexrays.hpp>
#include <lines.hpp>
#include <name.hpp>
#include <ua.hpp>

#include <cstddef>
#include <cstdint>
#include <sstream>
#include <string>

namespace ida_agent::ai
{
namespace
{

constexpr std::size_t MaxSelectionLines = 2000;
constexpr std::size_t MaxSelectionBytes = 512 * 1024;
constexpr std::string_view TruncatedMarker = "/* ...truncated... */\n";

std::string HexAddress(ea_t address)
{
  std::ostringstream out;
  out << "0x" << std::hex << static_cast<std::uint64_t>(address);
  return out.str();
}

std::string PlainText(const qstring &line)
{
  qstring plain;
  tag_remove(&plain, line);
  return std::string(plain.c_str());
}

bool AppendLine(std::string &result, ea_t address, const std::string &line)
{
  std::string text = HexAddress(address);
  text += ": ";
  text += line;
  text += '\n';
  if ( result.size() + text.size() > MaxSelectionBytes ) return false;
  result += text;
  return true;
}

void AppendTruncatedMarker(std::string &result)
{
  if ( result.size() <= MaxSelectionBytes
      && TruncatedMarker.size() <= MaxSelectionBytes - result.size() )
    result.append(TruncatedMarker);
}

} // namespace

std::string CaptureDisassemblySelection(TWidget *viewer, ea_t cursor_ea)
{
  std::string result;
  ea_t start = BADADDR, end = BADADDR;
  const bool ranged = viewer != nullptr
      && read_range_selection(viewer, &start, &end)
      && start != BADADDR && end != BADADDR && start < end;
  if ( ranged )
  {
    std::size_t lines = 0;
    for ( ea_t current = start; current < end && lines < MaxSelectionLines; )
    {
      if ( !is_mapped(current) )
      {
        if ( current == end - 1 ) break;
        ++current;
        continue;
      }
      qstring generated;
      if ( generate_disasm_line(&generated, current, 0) )
      {
        const std::string text = PlainText(generated);
        if ( !text.empty() )
        {
          if ( !AppendLine(result, current, text) ) break;
          ++lines;
        }
      }
      const ea_t item_end = get_item_end(current);
      if ( item_end <= current ) ++current;
      else current = item_end;
    }
    return result;
  }

  if ( cursor_ea == BADADDR || !is_mapped(cursor_ea) ) return {};
  qstring generated;
  if ( !generate_disasm_line(&generated, cursor_ea, 0) ) return {};
  const std::string text = PlainText(generated);
  if ( text.empty() ) return {};
  AppendLine(result, cursor_ea, text);
  return result;
}

std::string CapturePseudocodeText(TWidget *viewer)
{
  if ( viewer == nullptr ) return {};
  vdui_t *view = get_widget_vdui(viewer);
  if ( view == nullptr || !view->cfunc ) return {};

  std::string result = "/* Pseudocode ";
  qstring name;
  if ( get_func_name(&name, view->cfunc->entry_ea) > 0 && !name.empty() )
  {
    result += std::string(name.c_str());
    result += " @ ";
  }
  result += HexAddress(view->cfunc->entry_ea);
  result += " */\n";
  if ( result.size() > MaxSelectionBytes )
    return std::string(TruncatedMarker);

  const strvec_t &lines = view->cfunc->get_pseudocode();
  for ( std::size_t index = 0; index < lines.size(); ++index )
  {
    if ( result.size() >= MaxSelectionBytes )
    {
      AppendTruncatedMarker(result);
      break;
    }
    const std::string text = PlainText(lines[index].line);
    if ( result.size() + text.size() + 1 > MaxSelectionBytes )
    {
      AppendTruncatedMarker(result);
      break;
    }
    result += text;
    result += '\n';
  }
  return result;
}

} // namespace ida_agent::ai
