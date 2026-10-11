#pragma once

#include <QtGui>
#include "ai/chat_code_fences.hpp"

namespace ida_agent::ai
{
inline constexpr int ChatCodeGroupProperty = QT::QTextFormat::UserProperty + 171;
void RestoreChatCodeGroups(QT::QTextDocument &document, const ChatCodeMarkdown &markdown);

// Native display overlays only; call after styling a completed message.
void ApplyChatCodeHighlighting(QT::QTextFrame *frame, const QT::QPalette &palette);
} // namespace ida_agent::ai
