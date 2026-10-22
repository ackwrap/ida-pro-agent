#include "ai/update_notice.hpp"
#include <utility>

namespace ida_agent::ai
{
namespace
{
void Present(QT::QDialog *dialog)
{
  dialog->show();
  dialog->raise();
  dialog->activateWindow();
  QT::QApplication::alert(dialog);
}
} // namespace

UpdateNotice::UpdateNotice(OpenReleasePage open_release)
    : open_release_(std::move(open_release))
{
  if ( !open_release_ )
    open_release_ = [](const QT::QUrl &url) { return QT::QDesktopServices::openUrl(url); };
}

UpdateNotice::~UpdateNotice() { Close(); }

bool UpdateNotice::Show(std::string_view installed, const UpdateCache &cache,
    bool manual, QT::QWidget *parent)
{
  if ( !HasNewerRelease(installed, cache.release_tag)
      || (!manual && notified_tag_ == cache.release_tag) ) return false;
  if ( dialog_ && dialog_->isVisible() && notified_tag_ == cache.release_tag )
  {
    Present(dialog_);
    return false;
  }
  if ( dialog_ && parent && (parent == dialog_ || dialog_->isAncestorOf(parent)) )
    parent = dialog_->parentWidget();
  Close();
  const QT::QUrl url(QT::QString::fromStdString(ReleasePagePrefix + cache.release_tag));
  auto *dialog = new QT::QDialog(parent);
  dialog_ = dialog;
  dialog->setObjectName("idaAgentUpdateNotice");
  dialog->setWindowTitle("IDA Agent Update Available");
  dialog->setAttribute(QT::Qt::WA_DeleteOnClose);
  // Return to the event loop while keeping the prompt in front of IDA.
  dialog->setWindowModality(QT::Qt::ApplicationModal);
  auto *layout = new QT::QVBoxLayout(dialog);
  auto *label = new QT::QLabel(QT::QString(
      "A new version of IDA Agent is available.\n\n"
      "Installed version: %1\nLatest version: %2\n\n"
      "Open the release page to download the package for your platform. "
      "Close IDA before installing the matching plugin and Gateway.")
      .arg(QT::QString::fromUtf8(installed.data(), static_cast<int>(installed.size())),
          QT::QString::fromStdString(cache.release_tag)), dialog);
  label->setObjectName("idaAgentUpdateMessage");
  label->setTextFormat(QT::Qt::PlainText);
  label->setWordWrap(true);
  layout->addWidget(label);
  auto *status = new QT::QLabel("Download page:\n" + url.toString(), dialog);
  status->setObjectName("idaAgentUpdateDownloadStatus");
  status->setTextFormat(QT::Qt::PlainText);
  status->setTextInteractionFlags(QT::Qt::TextSelectableByMouse | QT::Qt::TextSelectableByKeyboard);
  status->setWordWrap(true);
  layout->addWidget(status);
  auto *buttons = new QT::QDialogButtonBox(dialog);
  auto *download = buttons->addButton("Download Update", QT::QDialogButtonBox::AcceptRole);
  download->setObjectName("idaAgentDownloadUpdate");
  download->setDefault(true);
  auto *later = buttons->addButton("Later", QT::QDialogButtonBox::RejectRole);
  later->setObjectName("idaAgentUpdateLater");
  QT::QObject::connect(download, &QT::QPushButton::clicked, dialog,
      [dialog, status, url, open_release = open_release_]()
      {
        if ( open_release(url) )
          dialog->accept();
        else
        {
          status->setText("Unable to open your browser. Try again or copy this address:\n"
              + url.toString());
        }
      });
  QT::QObject::connect(buttons, &QT::QDialogButtonBox::rejected, dialog, &QT::QDialog::reject);
  layout->addWidget(buttons);
  dialog->setMinimumWidth(460);
  Present(dialog);
  notified_tag_ = cache.release_tag;
  return true;
}

void UpdateNotice::Close() noexcept
{
  if ( dialog_ ) delete dialog_.data();
}
} // namespace ida_agent::ai
