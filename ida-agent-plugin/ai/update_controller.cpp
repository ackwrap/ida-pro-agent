#include "ai/update_controller.hpp"
#include "ai/update_store.hpp"
#include "product_version.hpp"

#include <ida.hpp>
#include <kernwin.hpp>
#include <QtWidgets>

#include <chrono>

namespace ida_agent::ai
{
namespace
{
std::int64_t Now()
{
  return std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
}
}

struct UpdateController::Impl
{
  void Notify(bool manual)
  {
    if ( !HasNewerRelease(ida_agent::Version, cache.release_tag)
        || notified_tag == cache.release_tag ) return;
    notified_tag = cache.release_tag;
    const std::string url = ReleasePagePrefix + cache.release_tag;
    msg("[ida-agent] Update available: %s (installed %s). Download: %s\n",
        cache.release_tag.c_str(), ida_agent::Version, url.c_str());
    if ( manual ) return;
    if ( notice ) delete notice.data();
    auto *dialog = new QT::QDialog(QT::QApplication::activeWindow());
    notice = dialog;
    dialog->setObjectName("idaAgentUpdateNotice");
    dialog->setWindowTitle("IDA Agent Update Available");
    dialog->setAttribute(QT::Qt::WA_DeleteOnClose);
    dialog->setAttribute(QT::Qt::WA_ShowWithoutActivating);
    auto *layout = new QT::QVBoxLayout(dialog);
    auto *label = new QT::QLabel(QT::QString::fromStdString(
        UpdateStatusText(ida_agent::Version, cache)), dialog);
    label->setTextFormat(QT::Qt::PlainText);
    label->setWordWrap(true);
    layout->addWidget(label);
    auto *buttons = new QT::QDialogButtonBox(dialog);
    auto *download = buttons->addButton("Open Release Page", QT::QDialogButtonBox::ActionRole);
    buttons->addButton(QT::QDialogButtonBox::Close);
    QT::QObject::connect(download, &QT::QPushButton::clicked, dialog, [url]()
    {
      QT::QDesktopServices::openUrl(QT::QUrl(QT::QString::fromStdString(url)));
    });
    QT::QObject::connect(buttons, &QT::QDialogButtonBox::rejected, dialog, &QT::QDialog::close);
    layout->addWidget(buttons);
    dialog->show();
  }

  void Check(bool manual)
  {
    if ( !http || request != 0 ) return;
    manual_note.clear();
    if ( !UpdateCheckDue(cache, Now(), manual) )
    {
      if ( manual ) manual_note = " Please wait one minute between manual checks.";
      return;
    }
    request = http->Submit(MakeUpdateRequest(ida_agent::Version));
    manual_request = manual;
    deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
  }

  void Tick()
  {
    try
    {
      const bool automatic = store.Automatic();
      if ( request != 0 )
      {
        if ( !automatic && !manual_request )
        {
          http->CancelAndForget(request);
          request = 0;
          return;
        }
        auto result = http->TryTakeResult(request);
        if ( !result && std::chrono::steady_clock::now() >= deadline )
        {
          http->CancelAndForget(request);
          result = HttpResponse{HttpResponseStatus::NetworkError, 0, {}, {}};
        }
        if ( !result ) return;
        request = 0;
        cache = DecodeUpdateResponse(*result, Now(), cache);
        store.SaveCache(cache);
        Notify(manual_request);
      }
      const auto shared = store.LoadCache();
      if ( shared.checked_at > cache.checked_at && shared.checked_at <= Now() ) cache = shared;
      if ( automatic )
      {
        Notify(false);
        Check(false);
      }
    }
    catch ( ... )
    {
      // Update checks must not propagate into IDA's UI event loop.
    }
  }

  UpdateStore store;
  UpdateCache cache;
  std::unique_ptr<HttpClient> http;
  std::unique_ptr<QT::QTimer> timer;
  QT::QPointer<QT::QDialog> notice;
  HttpClient::RequestId request = 0;
  std::chrono::steady_clock::time_point deadline;
  std::string notified_tag;
  std::string manual_note;
  bool manual_request = false;
};

UpdateController::UpdateController() : impl_(std::make_unique<Impl>()) {}
UpdateController::~UpdateController() { Stop(); }
void UpdateController::Start()
{
  if ( impl_->timer ) return;
  impl_->cache = impl_->store.LoadCache();
  impl_->http = std::make_unique<HttpClient>();
  impl_->timer = std::make_unique<QT::QTimer>();
  QT::QObject::connect(impl_->timer.get(), &QT::QTimer::timeout, impl_->timer.get(),
      [this]() { impl_->Tick(); });
  impl_->timer->start(1000);
}
void UpdateController::Stop() noexcept
{
  impl_->timer.reset();
  if ( impl_->notice ) delete impl_->notice.data();
  if ( impl_->http && impl_->request != 0 ) impl_->http->CancelAndForget(impl_->request);
  impl_->request = 0;
  impl_->http.reset();
}
bool UpdateController::Automatic() { return impl_->store.Automatic(); }
bool UpdateController::SetAutomatic(bool automatic)
{
  if ( !impl_->store.SaveAutomatic(automatic) ) return false;
  impl_->Tick();
  return true;
}
void UpdateController::CheckNow() { impl_->Check(true); }
bool UpdateController::Checking() const { return impl_->request != 0; }
std::string UpdateController::Status() const
{
  return std::string(Checking() ? "Checking GitHub... " : "")
      + UpdateStatusText(ida_agent::Version, impl_->cache) + impl_->manual_note;
}
std::string UpdateController::ReleaseUrl() const
{
  return impl_->cache.release_tag.empty() ? std::string{} : ReleasePagePrefix + impl_->cache.release_tag;
}
} // namespace ida_agent::ai
