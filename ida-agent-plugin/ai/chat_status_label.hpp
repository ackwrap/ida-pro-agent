#pragma once

#include <QtWidgets>

#include <string_view>

namespace ida_agent::ai
{

class ChatStatusView final
{
public:
  void Create(QT::QWidget *parent);
  void Detach() noexcept;
  void Set(std::string_view text);
  QT::QScrollArea *Widget() const noexcept;

private:
  QT::QScrollArea *scroll_ = nullptr;
  QT::QLabel *label_ = nullptr;
};

} // namespace ida_agent::ai
