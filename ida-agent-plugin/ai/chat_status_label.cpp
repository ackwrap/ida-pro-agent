#include "ai/chat_status_label.hpp"

#include "ai/chat_output_view.hpp"

#include <string>

namespace ida_agent::ai
{
namespace
{

class ChatStatusLabel final : public QT::QLabel
{
public:
  using QT::QLabel::QLabel;

  QT::QSize sizeHint() const override
  {
    QT::QSize result = QT::QLabel::sizeHint();
    if ( wordWrap() && width() > 0 )
      result.setHeight(heightForWidth(width()));
    return result;
  }

  QT::QSize minimumSizeHint() const override
  {
    QT::QSize result = sizeHint();
    result.setWidth(0);
    return result;
  }

protected:
  void resizeEvent(QT::QResizeEvent *event) override
  {
    QT::QLabel::resizeEvent(event);
    updateGeometry();
  }
};

} // namespace

void ChatStatusView::Create(QT::QWidget *parent)
{
  scroll_ = new QT::QScrollArea(parent);
  scroll_->setFrameShape(QT::QFrame::NoFrame);
  scroll_->setWidgetResizable(true);
  scroll_->setHorizontalScrollBarPolicy(QT::Qt::ScrollBarAlwaysOff);
  scroll_->setVerticalScrollBarPolicy(QT::Qt::ScrollBarAsNeeded);
  scroll_->setMaximumHeight(scroll_->fontMetrics().lineSpacing() * 4);
  label_ = new ChatStatusLabel(scroll_);
  label_->setTextFormat(QT::Qt::PlainText);
  label_->setAlignment(QT::Qt::AlignLeft | QT::Qt::AlignTop);
  label_->setWordWrap(true);
  label_->setTextInteractionFlags(
      QT::Qt::TextSelectableByMouse | QT::Qt::TextSelectableByKeyboard);
  label_->setSizePolicy(QT::QSizePolicy::Ignored, QT::QSizePolicy::Preferred);
  scroll_->setWidget(label_);
  scroll_->hide();
}

void ChatStatusView::Detach() noexcept
{
  scroll_ = nullptr;
  label_ = nullptr;
}

void ChatStatusView::Set(std::string_view text)
{
  if ( scroll_ == nullptr || label_ == nullptr )
    return;
  if ( text.empty() )
  {
    label_->clear();
    scroll_->hide();
    return;
  }
  label_->setText(ToQString(std::string("[System] ") + std::string(text)));
  scroll_->verticalScrollBar()->setValue(0);
  scroll_->show();
}

QT::QScrollArea *ChatStatusView::Widget() const noexcept
{
  return scroll_;
}

} // namespace ida_agent::ai
