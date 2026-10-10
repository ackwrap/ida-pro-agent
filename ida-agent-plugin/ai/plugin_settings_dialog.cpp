#include "ai/plugin_settings_dialog.hpp"
#include "ai/file_log.hpp"
#ifndef _WIN32
#include "ai/application_paths_linux.hpp"
#endif

#include <QtWidgets>

namespace ida_agent::ai
{

bool ShowPluginSettingsDialog(
    PluginSettings &settings,
    const std::function<bool()> &clear_all_history)
{
  PluginSettings working = settings;
  bool applied = false;

  QT::QDialog dialog(QT::QApplication::activeWindow());
  dialog.setObjectName("idaAgentPluginSettings");
  dialog.setWindowTitle("IDA Agent Settings");
  dialog.setWindowFlag(QT::Qt::WindowContextHelpButtonHint, false);
  dialog.setModal(true);
  dialog.setMinimumWidth(500);

  auto *layout = new QT::QVBoxLayout(&dialog);
  layout->setContentsMargins(12, 10, 12, 10);
  layout->setSpacing(9);

  auto *chat_group = new QT::QGroupBox("AI Chat", &dialog);
  auto *chat_layout = new QT::QVBoxLayout(chat_group);
  auto *auto_open = new QT::QCheckBox(
      "Open AI Chat automatically when a database is ready",
      chat_group);
  auto_open->setObjectName("idaAgentAutoOpenChat");
  auto_open->setChecked(working.open_chat_on_database_open);
  auto *focus_input = new QT::QCheckBox(
      "Focus the chat input after automatic opening",
      chat_group);
  focus_input->setObjectName("idaAgentFocusAutoOpenInput");
  focus_input->setChecked(working.focus_input_on_auto_open);
  focus_input->setEnabled(working.open_chat_on_database_open);
  chat_layout->addWidget(auto_open);
  chat_layout->addWidget(focus_input);
  layout->addWidget(chat_group);

  auto *history_group = new QT::QGroupBox("External Chat History", &dialog);
  auto *history_layout = new QT::QVBoxLayout(history_group);
  auto *load_history = new QT::QCheckBox(
      "Restore history for the current IDB when it opens",
      history_group);
  load_history->setObjectName("idaAgentLoadChatHistory");
  load_history->setChecked(working.load_chat_history);
  auto *save_history = new QT::QCheckBox(
      "Save chat history outside the IDB",
      history_group);
  save_history->setObjectName("idaAgentSaveChatHistory");
  save_history->setChecked(working.save_chat_history);
  auto *history_note = new QT::QLabel(
#ifdef _WIN32
      "New history is stored under %LOCALAPPDATA%\\ida-agent\\ai\\chat.db. Existing ida-mcp history stays at its original path. "
      "Disabling saving does not delete existing history.",
#else
      QT::QString("History is stored at %1. Disabling saving does not delete existing history.")
          .arg(QT::QString::fromStdString(LinuxAiPath("XDG_STATE_HOME", ".local/state", "chat.db").u8string())),
#endif
      history_group);
  history_note->setTextFormat(QT::Qt::PlainText);
  history_note->setWordWrap(true);
  history_note->setTextInteractionFlags(QT::Qt::TextSelectableByMouse);
  auto *clear_history = new QT::QPushButton(
      "Clear All Stored Conversations...",
      history_group);
  clear_history->setObjectName("idaAgentClearAllChatHistory");
  history_layout->addWidget(load_history);
  history_layout->addWidget(save_history);
  history_layout->addWidget(history_note);
  history_layout->addWidget(clear_history);
  layout->addWidget(history_group);

  auto *logging_group = new QT::QGroupBox("File Logging", &dialog);
  auto *logging_layout = new QT::QVBoxLayout(logging_group);
  auto *debug_logging = new QT::QCheckBox(
      "Write debug diagnostics to a file",
      logging_group);
  debug_logging->setObjectName("idaAgentDebugLogging");
  debug_logging->setChecked(working.debug_logging);
  auto *network_logging = new QT::QCheckBox(
      "Log AI requests and responses by chat session",
      logging_group);
  network_logging->setObjectName("idaAgentNetworkLogging");
  network_logging->setChecked(working.network_logging);
  auto *logging_note = new QT::QLabel(
      QT::QString("Logs are written under %1. Both logging options are disabled by default.")
          .arg(QT::QString::fromStdString(McpLogDirectory().u8string())),
      logging_group);
  logging_note->setTextFormat(QT::Qt::PlainText);
  logging_note->setWordWrap(true);
  logging_note->setTextInteractionFlags(QT::Qt::TextSelectableByMouse);
  logging_layout->addWidget(debug_logging);
  logging_layout->addWidget(network_logging);
  logging_layout->addWidget(logging_note);
  layout->addWidget(logging_group);

  auto *settings_note = new QT::QLabel(
      "Plugin settings are global and stored outside all IDA databases.",
      &dialog);
  settings_note->setWordWrap(true);
  layout->addWidget(settings_note);

  auto *buttons = new QT::QDialogButtonBox(
      QT::QDialogButtonBox::Ok
          | QT::QDialogButtonBox::Cancel
          | QT::QDialogButtonBox::Apply,
      &dialog);
  layout->addWidget(buttons);

  QT::QObject::connect(
      auto_open,
      &QT::QCheckBox::toggled,
      focus_input,
      &QT::QWidget::setEnabled);
  QT::QObject::connect(
      clear_history,
      &QT::QPushButton::clicked,
      &dialog,
      [&]()
      {
        const auto answer = QT::QMessageBox::question(
            &dialog,
            "Clear All Chat History",
            "Permanently delete every stored AI chat conversation for all IDBs? "
            "This cannot be undone.",
            QT::QMessageBox::Yes | QT::QMessageBox::No,
            QT::QMessageBox::No);
        if ( answer != QT::QMessageBox::Yes )
          return;
        if ( clear_all_history && clear_all_history() )
        {
          QT::QMessageBox::information(
              &dialog,
              "Chat History Cleared",
              "All stored AI chat conversations were deleted.");
        }
        else
        {
          QT::QMessageBox::warning(
              &dialog,
              "Unable to Clear Chat History",
              "Stored conversations could not be deleted. Cancel any active AI "
              "requests and try again.");
        }
      });

  const auto apply = [&]()
  {
    working.open_chat_on_database_open = auto_open->isChecked();
    working.focus_input_on_auto_open = focus_input->isChecked();
    working.load_chat_history = load_history->isChecked();
    working.save_chat_history = save_history->isChecked();
    working.debug_logging = debug_logging->isChecked();
    working.network_logging = network_logging->isChecked();
    settings = working;
    applied = true;
  };
  QT::QObject::connect(
      buttons->button(QT::QDialogButtonBox::Apply),
      &QT::QPushButton::clicked,
      &dialog,
      apply);
  QT::QObject::connect(
      buttons,
      &QT::QDialogButtonBox::accepted,
      &dialog,
      [&]()
      {
        apply();
        dialog.accept();
      });
  QT::QObject::connect(
      buttons,
      &QT::QDialogButtonBox::rejected,
      &dialog,
      &QT::QDialog::reject);

  dialog.exec();
  return applied;
}

} // namespace ida_agent::ai
