#pragma once

#include "ai/chat_message_view.hpp"
#include <string_view>

namespace ida_agent::ai
{
QT::QString ToQString(std::string_view value);
ChatMessageView *CreateChatOutputView(QT::QWidget *parent);
} // namespace ida_agent::ai
