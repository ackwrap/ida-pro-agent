#pragma once
#include "ai/chat_reasoning.hpp"
#include <QtWidgets>
#include <functional>

namespace ida_agent::ai
{
class ChatReasoningControl final
{
public:
  void SetHandler(std::function<void(ChatReasoningSelection)> handler);
  QT::QComboBox *Create(QT::QWidget *parent, QT::QLineEdit *input);
  void SetState(ChatReasoningState state);
  void Detach() noexcept;
private:
  ChatReasoningState state_;
  std::function<void(ChatReasoningSelection)> handler_;
  QT::QPointer<QT::QComboBox> combo_;
};
} // namespace ida_agent::ai
