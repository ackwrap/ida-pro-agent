#pragma once
#include <QtWidgets>

namespace ida_agent::ai
{
class UpdateController;
QT::QCheckBox *AddUpdateSettings(
    UpdateController &updates, QT::QVBoxLayout *layout, QT::QWidget *parent);
}
