#include "ai/chat_reasoning_control.hpp"
#include <utility>

namespace ida_agent::ai
{
namespace
{
QT::QString Text(std::string_view value)
{ return QT::QString::fromUtf8(value.data(), static_cast<int>(value.size())); }
const char *Label(ProviderReasoningEffort effort)
{
  switch (effort)
  {
    case ProviderReasoningEffort::None: return "Effort: None";
    case ProviderReasoningEffort::Low: return "Effort: Low";
    case ProviderReasoningEffort::Medium: return "Effort: Medium";
    case ProviderReasoningEffort::High: return "Effort: High";
    case ProviderReasoningEffort::XHigh: return "Effort: XHigh";
    case ProviderReasoningEffort::Max: return "Effort: Max";
    default: return "Effort: Default";
  }
}
// Use the native input's style/font height, including theme and DPI changes,
// so the extra control does not increase the IDA console input-row height.
class EffortCombo final : public QT::QComboBox
{
public:
  EffortCombo(QT::QWidget *parent, QT::QLineEdit *input) : QT::QComboBox(parent), input_(input) {}
  QT::QSize sizeHint() const override
  { auto size = QT::QComboBox::sizeHint(); if (input_) size.setHeight(input_->sizeHint().height()); return size; }
  QT::QSize minimumSizeHint() const override
  { auto size = QT::QComboBox::minimumSizeHint(); if (input_) size.setHeight(input_->sizeHint().height()); return size; }
private:
  QT::QPointer<QT::QLineEdit> input_;
};
}
void ChatReasoningControl::SetHandler(std::function<void(ChatReasoningSelection)> handler)
{ handler_ = std::move(handler); }
QT::QComboBox *ChatReasoningControl::Create(QT::QWidget *parent, QT::QLineEdit *input)
{
  Detach();
  combo_ = new EffortCombo(parent, input);
  combo_->setObjectName("idaAgentReasoningEffort");
  combo_->setAccessibleName("Model reasoning effort");
  combo_->setSizePolicy(QT::QSizePolicy::Preferred, QT::QSizePolicy::Fixed);
  combo_->setSizeAdjustPolicy(QT::QComboBox::AdjustToContents);
  for (const auto effort : ChatReasoningLevels)
    combo_->addItem(Label(effort), Text(ProviderReasoningEffortName(effort)));
  // activated is user-only: restoring a setting never writes it back.
  QT::QObject::connect(combo_, &QT::QComboBox::activated, combo_,
      [this, input = QT::QPointer<QT::QLineEdit>(input)](int index)
  {
    if (!combo_ || !state_.enabled || index < 0) return;
    auto selected = state_.selection;
    const auto encoded = combo_->itemData(index).toString().toUtf8();
    if (!ParseProviderReasoningEffort(std::string_view(encoded.constData(), encoded.size()), selected.effort)) return;
    if (handler_) handler_(std::move(selected));
    if (input) input->setFocus(QT::Qt::OtherFocusReason);
  });
  SetState(state_);
  return combo_;
}
void ChatReasoningControl::SetState(ChatReasoningState state)
{
  state_ = std::move(state);
  if (!combo_) return;
  const QT::QSignalBlocker blocked(combo_);
  combo_->setCurrentIndex(combo_->findData(Text(ProviderReasoningEffortName(state_.selection.effort))));
  combo_->setEnabled(state_.enabled);
  combo_->setToolTip(Text(state_.tooltip));
}
void ChatReasoningControl::Detach() noexcept
{
  if (combo_) QT::QObject::disconnect(combo_, nullptr, nullptr, nullptr);
  combo_.clear();
}
} // namespace ida_agent::ai
