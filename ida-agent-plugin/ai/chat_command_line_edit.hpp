#pragma once

#include <QtWidgets>

#include <functional>
#include <string>

namespace ida_agent::ai
{

QT::QLineEdit *CreateChatCommandLineEdit(
    QT::QWidget *parent,
    std::function<void(std::string)> submit);

} // namespace ida_agent::ai
