#pragma once

#include <QtWidgets>

namespace ida_agent::ai
{

// Extends the AI chat output's context menu with a "Jump To" action. When the
// selected text holds a hex address or a known symbol name, the action resolves
// it against the current database and navigates the IDA disassembly view.
// Call once per output view; must run on the IDA UI thread (Qt event loop).
void AttachChatOutputJumpMenu(QT::QPlainTextEdit *output);

} // namespace ida_agent::ai
