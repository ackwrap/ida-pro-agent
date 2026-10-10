#pragma once

#include "ai/chat_display_formatter.hpp"

#include <QtWidgets>

#include <string_view>

namespace ida_agent::ai
{

QT::QString ToQString(std::string_view value);
QT::QPlainTextEdit *CreateChatOutputView(QT::QWidget *parent);
bool IsChatOutputAtBottom(QT::QPlainTextEdit *output);
void RestoreChatOutputView(
    QT::QPlainTextEdit *output,
    bool followed_bottom,
    int previous_scroll,
    const QT::QTextCursor &selection);
void RefreshChatOutputView(
    QT::QPlainTextEdit *output,
    bool force_bottom,
    std::string_view old_committed,
    std::string_view new_committed,
    std::string_view old_preview,
    std::string_view new_preview,
    ChatDisplayMigrationCandidate migration);

} // namespace ida_agent::ai
