#include "ai/chat_script_approval_dialog.hpp"

#include <QtWidgets>

namespace ida_agent::ai
{

ChatScriptApprovalDecision ShowChatScriptApprovalDialog(
    void *parent,
    const std::vector<ChatScriptSource> &sources)
{
  if ( parent == nullptr || sources.empty() )
    return ChatScriptApprovalDecision::DenySession;

  auto *parent_widget = static_cast<QT::QWidget *>(parent);
  QT::QDialog dialog(parent_widget);
  dialog.setWindowTitle("Approve Reviewed Script Files for This Session");
  dialog.setWindowModality(QT::Qt::ApplicationModal);

  auto *layout = new QT::QVBoxLayout(&dialog);
  auto *warning = new QT::QLabel(
      "Review the relative script file identities below. Source is held only "
      "in an immutable approved snapshot and is not displayed. Allowing grants side-effect "
      "permission for this entire conversation session and immediately "
      "executes every prepared side effect in this batch. The simple script "
      "scan is a heuristic gate, not a complete sandbox.",
      &dialog);
  warning->setWordWrap(true);
  layout->addWidget(warning);

  auto *source_view = new QT::QPlainTextEdit(&dialog);
  source_view->setReadOnly(true);
  source_view->setLineWrapMode(QT::QPlainTextEdit::NoWrap);
  source_view->setFont(
      QT::QFontDatabase::systemFont(QT::QFontDatabase::FixedFont));
  const std::string preview = FormatChatScriptApprovalPreview(sources);
  source_view->setPlainText(QT::QString::fromUtf8(
      preview.data(), static_cast<QT::qsizetype>(preview.size())));
  layout->addWidget(source_view, 1);

  auto *buttons = new QT::QDialogButtonBox(&dialog);
  auto *allow = buttons->addButton(
      "Allow Session and Execute", QT::QDialogButtonBox::AcceptRole);
  auto *deny = buttons->addButton(
      "Deny Session", QT::QDialogButtonBox::RejectRole);
  deny->setDefault(true);
  QT::QObject::connect(allow, &QT::QPushButton::clicked, &dialog, &QT::QDialog::accept);
  QT::QObject::connect(deny, &QT::QPushButton::clicked, &dialog, &QT::QDialog::reject);
  layout->addWidget(buttons);

  dialog.resize(900, 640);
  return ChatScriptDecisionFromAccepted(
      dialog.exec() == QT::QDialog::Accepted);
}

} // namespace ida_agent::ai
