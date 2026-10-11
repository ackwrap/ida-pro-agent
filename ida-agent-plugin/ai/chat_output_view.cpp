#include "ai/chat_output_view.hpp"

namespace ida_agent::ai
{
QT::QString ToQString(std::string_view value)
{
  return QT::QString::fromUtf8(value.data(), static_cast<int>(value.size()));
}

ChatMessageView *CreateChatOutputView(QT::QWidget *parent)
{
  auto *output = new ChatMessageView(parent);
  output->setToolTip("Markdown is formatted when a reply completes. Right-click a message "
      "or code block to copy it. The view retains the latest 256 messages within its "
      "display budget; complete messages remain in session history.");
  return output;
}
} // namespace ida_agent::ai
