#include "ai/update_notice.hpp"
#include <cstdio>
#include <stdexcept>

using ida_agent::ai::UpdateCache;
using ida_agent::ai::UpdateNotice;

namespace
{
void Require(bool condition, const char *message)
{
  if ( !condition ) throw std::runtime_error(message);
}

QT::QDialog *Notice()
{
  for ( auto *widget : QT::QApplication::topLevelWidgets() )
    if ( widget->objectName() == "idaAgentUpdateNotice" )
      return QT::qobject_cast<QT::QDialog *>(widget);
  return nullptr;
}

QT::QPushButton *Button(QT::QDialog *dialog, const char *name)
{
  auto *button = dialog->findChild<QT::QPushButton *>(name);
  Require(button != nullptr, "notice button missing");
  return button;
}

void FlushDeletes()
{
  QT::QCoreApplication::sendPostedEvents(nullptr, QT::QEvent::DeferredDelete);
  QT::QApplication::processEvents();
}

void TestUpdatePrompt()
{
  QT::QWidget owner;
  owner.show();
  int opened = 0;
  bool browser_available = true;
  QT::QUrl opened_url;
  UpdateNotice notice([&](const QT::QUrl &url)
      {
        ++opened;
        opened_url = url;
        return browser_available;
      });
  for ( const char *tag : {"", "v0.5.3", "v0.5.4", "v0.5.5-beta", "../v0.5.5"} )
    Require(!notice.Show("0.5.4", {1, tag, {}}, false, &owner), "invalid update prompted");
  Require(Notice() == nullptr && opened == 0, "no-update check opened a window");

  UpdateCache cache{1, "v0.5.5", {}};
  Require(notice.Show("0.5.4", cache, false, &owner), "automatic update did not prompt");
  QT::QPointer<QT::QDialog> first = Notice();
  Require(first && first->isVisible() && first->isModal(), "update prompt not visible and modal");
  Require(!first->testAttribute(QT::Qt::WA_ShowWithoutActivating), "update prompt suppresses activation");
  Require(QT::QApplication::activeModalWidget() == first, "update prompt is not the active modal window");
  const auto *message = first->findChild<QT::QLabel *>("idaAgentUpdateMessage");
  Require(message && message->text().contains("0.5.4") && message->text().contains("v0.5.5"),
      "installed/latest version missing");
  Require(Button(first, "idaAgentDownloadUpdate")->isDefault(), "download is not the default action");
  Require(opened == 0, "browser opened before choosing Download Update");
  const auto capture = QT::qgetenv("IDA_AGENT_TEST_UPDATE_CAPTURE");
  if ( !capture.isEmpty() )
    Require(first->grab().save(QT::QString::fromLocal8Bit(capture)), "prompt capture failed");
  Require(!notice.Show("0.5.4", cache, false, first) && Notice() == first,
      "automatic check duplicated a visible prompt");
  Require(!notice.Show("0.5.4", cache, true, first) && Notice() == first,
      "manual check duplicated a visible prompt");
  Button(first, "idaAgentUpdateLater")->click();
  FlushDeletes();
  Require(!first && opened == 0, "Later did not dismiss without opening the browser");
  Require(!notice.Show("0.5.4", cache, false, &owner), "automatic reminder repeated for the same release");

  Require(notice.Show("0.5.4", cache, true, &owner), "manual check did not reopen dismissed update");
  QT::QPointer<QT::QDialog> download = Notice();
  Button(download, "idaAgentDownloadUpdate")->click();
  FlushDeletes();
  Require(!download && opened == 1 && opened_url.toString()
      == "https://github.com/ackwrap/ida-pro-agent/releases/tag/v0.5.5",
      "download did not open the exact release page and close the prompt");

  browser_available = false;
  Require(notice.Show("0.5.4", cache, true, &owner), "manual retry did not prompt");
  QT::QPointer<QT::QDialog> retry = Notice();
  Button(retry, "idaAgentDownloadUpdate")->click();
  const auto *error = retry->findChild<QT::QLabel *>("idaAgentUpdateDownloadStatus");
  Require(retry->isVisible() && error && error->isVisible()
      && error->text().contains(opened_url.toString()), "browser failure lost retry or release URL");
  browser_available = true;
  Button(retry, "idaAgentDownloadUpdate")->click();
  FlushDeletes();
  Require(!retry && opened == 3, "browser retry failed");

  Require(notice.Show("0.5.4", cache, true, &owner), "manual reminder missing");
  QT::QPointer<QT::QDialog> closing = Notice();
  Button(closing, "idaAgentUpdateLater")->click();
  Require(notice.Show("0.5.4", cache, true, &owner), "manual check reused a closing prompt");
  Require(!closing && Notice()->isVisible(), "closing prompt was revived instead of replaced");
  notice.Close();

  Require(notice.Show("0.5.4", cache, true, &owner), "manual update missing before replacement");
  QT::QPointer<QT::QDialog> previous = Notice();
  cache.release_tag = "v0.5.6";
  Require(notice.Show("0.5.4", cache, false, previous), "newer release did not replace prompt");
  Require(!previous && Notice() && Notice()->parentWidget() == &owner,
      "replaced prompt kept a deleted dialog as its parent");
  notice.Close();
  Require(Notice() == nullptr, "shutdown left an update prompt open");
}

void TestOwnerLifetime()
{
  UpdateNotice notice([](const QT::QUrl &) { return true; });
  const UpdateCache cache{1, "v0.5.5", {}};
  {
    QT::QWidget settings;
    settings.setWindowModality(QT::Qt::ApplicationModal);
    settings.show();
    Require(notice.Show("0.5.4", cache, true, &settings), "prompt over Settings missing");
    Require(Notice()->parentWidget() == &settings, "prompt is not owned by active Settings");
  }
  Require(Notice() == nullptr, "parent destruction left a dangling update prompt");
  Require(!notice.Show("0.5.4", cache, false, nullptr), "parent deletion reset automatic suppression");
  Require(notice.Show("0.5.4", cache, true, nullptr), "manual check after parent destruction failed");
  notice.Close();
}
} // namespace

int main(int argc, char **argv)
{
  QT::qInstallMessageHandler([](QT::QtMsgType, const QT::QMessageLogContext &,
      const QT::QString &message)
      {
        std::fprintf(stderr, "%s\n", message.toLocal8Bit().constData());
        std::fflush(stderr);
      });
  QT::QApplication app(argc, argv);
  app.setQuitOnLastWindowClosed(false);
  try
  {
    TestUpdatePrompt();
    TestOwnerLifetime();
    std::puts("PASS: foreground update prompt, manual retry and release-page navigation");
    return 0;
  }
  catch ( const std::exception &error )
  {
    std::fprintf(stderr, "%s\n", error.what());
    return 1;
  }
}
