#pragma once

#include <ida.hpp>
#include <kernwin.hpp>

#include <string>

namespace ida_agent::ai
{

// Renders the currently selected disassembly lines from an IDA disassembly
// window into plain text with one hex address prefix per line. When no
// selection is present the single item at `cursor_ea` is returned. Runs on the
// IDA UI thread and returns an empty string when nothing can be captured.
std::string CaptureDisassemblySelection(TWidget *viewer, ea_t cursor_ea);

// Renders the pseudocode currently displayed in an IDA Hex-Rays pseudocode
// window as plain text prefixed by a function header that carries the entry
// address. Runs on the IDA UI thread and returns an empty string when the
// widget is not a valid pseudocode window.
std::string CapturePseudocodeText(TWidget *viewer);

} // namespace ida_agent::ai
