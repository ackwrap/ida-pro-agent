#include "ai/update_settings_widget.hpp"
#include "ai/update_controller.hpp"

namespace ida_agent::ai
{
QT::QCheckBox *AddUpdateSettings(
    UpdateController &updates, QT::QVBoxLayout *layout, QT::QWidget *parent)
{
  auto *group = new QT::QGroupBox("Software Updates", parent);
  auto *content = new QT::QVBoxLayout(group);
  auto *automatic = new QT::QCheckBox("Check for stable releases automatically (once a day)", group);
  automatic->setObjectName("idaAgentAutomaticUpdates");
  automatic->setChecked(updates.Automatic());
  content->addWidget(automatic);
  auto *status = new QT::QLabel(group);
  status->setObjectName("idaAgentUpdateStatus");
  status->setTextFormat(QT::Qt::PlainText);
  status->setWordWrap(true);
  content->addWidget(status);
  auto *actions = new QT::QHBoxLayout;
  auto *check = new QT::QPushButton("Check Now", group);
  check->setObjectName("idaAgentCheckUpdates");
  auto *release = new QT::QPushButton("Open Release Page", group);
  release->setObjectName("idaAgentOpenRelease");
  actions->addWidget(check);
  actions->addWidget(release);
  actions->addStretch();
  content->addLayout(actions);
  auto *note = new QT::QLabel(
      "Checks use the public ackwrap/ida-pro-agent repository. Download the matching "
      "plugin and Gateway package, close IDA, then install it. This setting is shared "
      "with the local Web manager.", group);
  note->setWordWrap(true);
  content->addWidget(note);
  const auto refresh = [&updates, status, check, release]()
  {
    status->setText(QT::QString::fromStdString(updates.Status()));
    check->setEnabled(!updates.Checking());
    release->setEnabled(!updates.ReleaseUrl().empty());
  };
  QT::QObject::connect(check, &QT::QPushButton::clicked, group, [&updates, refresh]()
  {
    updates.CheckNow();
    refresh();
  });
  QT::QObject::connect(release, &QT::QPushButton::clicked, group, [&updates]()
  {
    const auto url = updates.ReleaseUrl();
    if ( !url.empty() ) QT::QDesktopServices::openUrl(QT::QUrl(QT::QString::fromStdString(url)));
  });
  auto *timer = new QT::QTimer(group);
  QT::QObject::connect(timer, &QT::QTimer::timeout, group, refresh);
  timer->start(500);
  refresh();
  layout->addWidget(group);
  return automatic;
}
} // namespace ida_agent::ai
