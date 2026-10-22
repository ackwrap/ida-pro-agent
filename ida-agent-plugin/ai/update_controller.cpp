#include "ai/update_controller.hpp"
#include "ai/update_notice.hpp"
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
    if ( !notice.Show(ida_agent::Version, cache, manual, QT::QApplication::activeWindow()) ) return;
    const std::string url = ReleasePagePrefix + cache.release_tag;
    msg("[ida-agent] Update available: %s (installed %s). Download: %s\n",
        cache.release_tag.c_str(), ida_agent::Version, url.c_str());
  }

  void Check(bool manual)
  {
    if ( !http ) return;
    if ( request != 0 )
    {
      manual_request = manual_request || manual;
      return;
    }
    manual_note.clear();
    if ( !UpdateCheckDue(cache, Now(), manual) )
    {
      if ( manual )
      {
        manual_note = " Please wait one minute between manual checks.";
        // The menu opens Settings immediately after CheckNow. Queue the notice
        // so it is parented to that dialog and remains the active modal window.
        QT::QTimer::singleShot(0, timer.get(), [this]() { Notify(true); });
      }
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
  UpdateNotice notice;
  HttpClient::RequestId request = 0;
  std::chrono::steady_clock::time_point deadline;
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
  impl_->notice.Close();
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
