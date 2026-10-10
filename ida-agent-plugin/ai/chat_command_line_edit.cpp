#include "ai/chat_command_line_edit.hpp"

#include "ai/cli_command.hpp"

#include <string_view>
#include <utility>

namespace ida_agent::ai
{
namespace
{

QT::QString ToQString(std::string_view value)
{
  return QT::QString::fromUtf8(value.data(), static_cast<int>(value.size()));
}

class ChatCommandLineEdit final : public QT::QLineEdit
{
public:
  using QT::QLineEdit::QLineEdit;

protected:
  bool event(QT::QEvent *event) override
  {
    if ( event->type() != QT::QEvent::KeyPress )
      return QT::QLineEdit::event(event);
    auto *key_event = static_cast<QT::QKeyEvent *>(event);
    QT::QCompleter *command_completer = completer();
    if ( command_completer == nullptr || !command_completer->popup()->isVisible() )
      return QT::QLineEdit::event(event);

    QT::QAbstractItemModel *model = command_completer->completionModel();
    const int row_count = model->rowCount();
    const int key = key_event->key();
    if ( (key == QT::Qt::Key_Down || key == QT::Qt::Key_Up) && row_count > 0 )
    {
      int row = command_completer->popup()->currentIndex().row();
      if ( key == QT::Qt::Key_Down )
        row = (row + 1) % row_count;
      else
        row = row <= 0 ? row_count - 1 : row - 1;
      command_completer->popup()->setCurrentIndex(model->index(row, 0));
      key_event->accept();
      return true;
    }
    if ( (key == QT::Qt::Key_Return
          || key == QT::Qt::Key_Enter
          || key == QT::Qt::Key_Tab
          || key == QT::Qt::Key_Backtab)
        && row_count > 0 )
    {
      QT::QModelIndex index = command_completer->popup()->currentIndex();
      if ( !index.isValid() )
        index = model->index(0, 0);
      const QT::QString command = index.data(QT::Qt::UserRole).toString();
      if ( !command.isEmpty() )
      {
        setText(command);
        setCursorPosition(command.size());
      }
      command_completer->popup()->hide();
      key_event->accept();
      return true;
    }
    if ( key == QT::Qt::Key_Escape )
    {
      command_completer->popup()->hide();
      key_event->accept();
      return true;
    }
    return QT::QLineEdit::event(event);
  }
};

} // namespace

QT::QLineEdit *CreateChatCommandLineEdit(
    QT::QWidget *parent,
    std::function<void(std::string)> submit)
{
  auto *input = new ChatCommandLineEdit(parent);
  input->setPlaceholderText(QT::QString::fromUtf8("Ask IDA Agent AI..."));
  input->setClearButtonEnabled(true);

  auto *command_model = new QT::QStandardItemModel(input);
  for ( const CliCommandDefinition &definition : AvailableCliCommands() )
  {
    const QT::QString command = ToQString(definition.command);
    auto *item = new QT::QStandardItem(
        command + QT::QString::fromUtf8("    ") + ToQString(definition.description));
    item->setData(command, QT::Qt::UserRole);
    item->setToolTip(ToQString(definition.description));
    command_model->appendRow(item);
  }

  auto *command_completer = new QT::QCompleter(command_model, input);
  command_completer->setCaseSensitivity(QT::Qt::CaseInsensitive);
  command_completer->setCompletionMode(QT::QCompleter::PopupCompletion);
  command_completer->setCompletionRole(QT::Qt::UserRole);
  command_completer->setFilterMode(QT::Qt::MatchStartsWith);
  command_completer->setMaxVisibleItems(10);
  command_completer->setWrapAround(true);
  input->setCompleter(command_completer);

  QT::QObject::connect(
      input,
      &QT::QLineEdit::textEdited,
      input,
      [input, command_completer](const QT::QString &text)
      {
        bool command_prefix = text.startsWith(QT::QChar('/'));
        for ( const QT::QChar character : text )
          command_prefix = command_prefix && !character.isSpace();
        if ( !command_prefix )
        {
          command_completer->popup()->hide();
          return;
        }

        command_completer->setCompletionPrefix(text);
        const int match_count = command_completer->completionCount();
        if ( match_count == 0
            || (match_count == 1
                && command_completer->currentCompletion().compare(
                       text,
                       QT::Qt::CaseInsensitive) == 0) )
        {
          command_completer->popup()->hide();
          return;
        }
        command_completer->popup()->setMinimumWidth(input->width());
        command_completer->complete();
      });
  QT::QObject::connect(
      input,
      &QT::QLineEdit::returnPressed,
      input,
      [input, submit = std::move(submit)]()
      {
        const QT::QString line = input->text();
        if ( line.trimmed().isEmpty() )
          return;
        const QT::QByteArray encoded = line.toUtf8();
        input->clear();
        if ( submit )
        {
          submit(std::string(
              encoded.constData(),
              static_cast<std::size_t>(encoded.size())));
        }
      });
  return input;
}

} // namespace ida_agent::ai
