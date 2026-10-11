#include "ai/chat_panel_impl.hpp"
#include "ai/chat_command_line_edit.hpp"
#include "ai/chat_output_menu.hpp"
#include "ai/chat_output_view.hpp"

namespace ida_agent::ai
{

ChatPanel::Impl::~Impl()
{
  Close();
}

bool ChatPanel::Impl::Open(bool focus_input)
{
  if ( widget != nullptr )
  {
    activate_widget(widget, focus_input);
    if ( focus_input )
      FocusInput();
    return true;
  }

  focus_input_on_open = focus_input;
  widget = create_empty_widget(title.c_str());
  if ( widget == nullptr )
    return false;
  listener_hooked = ::hook_event_listener(HT_UI, this, nullptr);
  if ( !listener_hooked )
  {
    close_widget(widget, 0);
    widget = nullptr;
    return false;
  }

  display_widget(
      widget,
      WOPN_PERSIST | WOPN_NOT_CLOSED_BY_ESC | WOPN_DP_RIGHT,
      "Output window");
  if ( !set_dock_pos(title.c_str(), "Output window", DP_RIGHT) )
    set_dock_pos(title.c_str(), "Output", DP_RIGHT);
  if ( focus_input )
    FocusInput();
  return true;
}

void ChatPanel::Impl::Close() noexcept
{
  if ( listener_hooked )
  {
    unhook_event_listener(HT_UI, this);
    listener_hooked = false;
  }
  if ( input != nullptr )
    QT::QObject::disconnect(input, nullptr, nullptr, nullptr);
  reasoning_control.Detach();
  DestroyTimer();
  preview.Discard();
  reasoning_preview.Discard();
  transient_status.clear();
  pending_input.clear();
  output = nullptr;
  status_view.Detach();
  input = nullptr;
  if ( widget != nullptr )
  {
    close_widget(widget, WCLS_DONT_SAVE_SIZE);
    widget = nullptr;
  }
}

void ChatPanel::Impl::FocusInput()
{
  if ( input != nullptr )
    input->setFocus(QT::Qt::OtherFocusReason);
}

void ChatPanel::Impl::ApplyPendingInput()
{
  if ( input == nullptr || pending_input.empty() )
    return;
  input->setText(QT::QString::fromUtf8(pending_input.data(),
      static_cast<int>(pending_input.size())));
  input->setCursorPosition(input->text().size());
  pending_input.clear();
  FocusInput();
}

bool ChatPanel::Impl::SetInputText(std::string_view text)
{
  if ( widget == nullptr && !Open(false) )
    return false;
  pending_input.assign(text);
  ApplyPendingInput();
  return true;
}

ssize_t idaapi ChatPanel::Impl::on_event(ssize_t code, va_list args)
{
  if ( code == ui_widget_visible )
  {
    TWidget *visible_widget = va_arg(args, TWidget *);
    if ( visible_widget == widget && output == nullptr )
      Populate();
  }
  else if ( code == ui_widget_invisible )
  {
    TWidget *hidden_widget = va_arg(args, TWidget *);
    if ( hidden_widget == widget )
    {
      output = nullptr;
      status_view.Detach();
      reasoning_control.Detach();
      input = nullptr;
      widget = nullptr;
      unhook_event_listener(HT_UI, this);
      listener_hooked = false;
      preview.Discard();
      reasoning_preview.Discard();
      pending_input.clear();
      if ( close )
        close();
    }
  }
  return 0;
}

void ChatPanel::Impl::Populate()
{
  auto *container = reinterpret_cast<QT::QWidget *>(widget);
  auto *layout = new QT::QVBoxLayout(container);
  layout->setContentsMargins(0, 0, 0, 2);
  layout->setSpacing(2);

  output = CreateChatOutputView(container);
  AttachChatOutputJumpMenu(output);
  status_view.Create(container);

  input = CreateChatCommandLineEdit(container, [this](std::string line)
  {
    if ( submit )
      submit(std::move(line));
  });

  if ( timer == nullptr )
  {
    // Created on the UI thread and owned explicitly by this controller-side
    // panel so polling survives destruction of a hidden dock widget.
    timer = new QT::QTimer();
    timer->setInterval(40);
    QT::QObject::connect(timer, &QT::QTimer::timeout, timer, [this]()
    {
      if ( poll )
        poll();
      FlushPreviewDisplay();
    });
    timer->start();
  }

  layout->addWidget(output, 1);
  layout->addWidget(status_view.Widget(), 0);
  auto *input_row = new QT::QHBoxLayout();
  input_row->setContentsMargins(0, 0, 0, 0);
  input_row->setSpacing(2);
  input_row->addWidget(input, 1);
  input_row->addWidget(reasoning_control.Create(container, input), 0);
  layout->addLayout(input_row, 0);
  RefreshFull();
  status_view.Set(transient_status);
  if ( !pending_input.empty() )
    ApplyPendingInput();
  else if ( focus_input_on_open )
    FocusInput();
}

void ChatPanel::Impl::DestroyTimer() noexcept
{
  if ( timer == nullptr )
    return;
  timer->stop();
  delete timer;
  timer = nullptr;
}

} // namespace ida_agent::ai
