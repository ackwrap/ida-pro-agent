#include "ai/provider_settings/dialog_controller.hpp"

#include <utility>

namespace ida_agent::ai::provider_settings
{
namespace
{

QT::QString DiscoveryFailureText(const ProviderDiscoveryResult &result)
{
  switch ( result.status )
  {
    case ProviderDiscoveryStatus::HttpError:
      return result.http_status == 0
          ? QT::QString("The provider returned an HTTP error.")
          : QT::QString("The provider returned HTTP status %1.").arg(result.http_status);
    case ProviderDiscoveryStatus::NetworkError:
      return "The provider could not be reached.";
    case ProviderDiscoveryStatus::InvalidResponse:
      return "The provider returned an invalid model-list response.";
    case ProviderDiscoveryStatus::Cancelled:
      return "The request was cancelled.";
    case ProviderDiscoveryStatus::ReachableButModelDiscoveryUnsupported:
      return "The provider is reachable, but model discovery is not supported.";
    case ProviderDiscoveryStatus::Success:
      return "The request succeeded.";
    default:
      return "The provider request failed.";
  }
}

} // namespace

void DialogController::CancelAndForget()
{
  ++request_generation_;
  if ( active_request_.has_value() )
    client_.CancelAndForget(active_request_->request_id);
  active_request_.reset();
  UpdateEnabled();
}

void DialogController::StartRequest(RequestOperation operation)
{
  CancelAndForget();
  ProviderProfileDraft *profile = CurrentProfile();
  if ( profile == nullptr )
    return;
  const ProviderClient::RequestId request_id = client_.SubmitListModels(*profile);
  const std::uint64_t generation = ++request_generation_;
  active_request_ = DialogRequestState{
      request_id,
      generation,
      profile->id,
      operation};
  connection_status_->setText(
      operation == RequestOperation::Test
          ? "Testing connection..."
          : "Refreshing models...");
  UpdateEnabled();
}

void DialogController::PollRequest()
{
  if ( !active_request_.has_value() )
    return;
  const DialogRequestState request = *active_request_;
  std::optional<ProviderDiscoveryResult> result =
      client_.TryTakeResult(request.request_id);
  if ( !result.has_value() )
    return;
  active_request_.reset();
  UpdateEnabled();
  if ( request.generation != request_generation_
      || request.profile_id != selected_profile_id_ )
    return;

  if ( request.operation == RequestOperation::Test )
  {
    if ( result->status == ProviderDiscoveryStatus::Success )
    {
      connection_status_->setText(
          QT::QString("Connection succeeded; %1 model(s) reported.")
              .arg(result->models.size()));
    }
    else if ( result->status
        == ProviderDiscoveryStatus::ReachableButModelDiscoveryUnsupported )
    {
      connection_status_->setText(
          "Provider is reachable; model discovery is not supported.");
    }
    else
    {
      connection_status_->setText(DiscoveryFailureText(*result));
    }
    return;
  }

  ProviderProfileDraft *profile = FindProvider(working_, request.profile_id);
  if ( result->status == ProviderDiscoveryStatus::Success && profile != nullptr )
  {
    MergeDiscoveredModels(*profile, result->models);
    RefreshModelsTable();
    connection_status_->setText(
        QT::QString("Models refreshed; %1 model(s) reported. Apply to save.")
            .arg(result->models.size()));
  }
  else if ( result->status
      == ProviderDiscoveryStatus::ReachableButModelDiscoveryUnsupported )
  {
    connection_status_->setText("Provider is reachable; existing models were kept.");
    QT::QMessageBox::information(
        &dialog_,
        "Refresh Models",
        "This provider does not support model discovery. Existing models were kept.");
  }
  else
  {
    const QT::QString error = DiscoveryFailureText(*result);
    connection_status_->setText(error);
    QT::QMessageBox::warning(&dialog_, "Refresh Models", error);
  }
}

bool DialogController::Apply()
{
  CancelAndForget();
  ProviderManagerDraft normalized = working_;
  NormalizeProviderManagerDraft(normalized);
  if ( !IsValidManagerDraft(normalized) )
  {
    QT::QMessageBox::warning(
        &dialog_,
        "Invalid Provider Settings",
        "Check provider names and URLs, enabled default models, headers, and proxy settings.");
    return false;
  }
  ProviderSettingsCommitResult result{
      ProviderSettingsCommitStatus::Failed,
      expected_revision_};
  if ( commit_ )
    result = commit_(normalized, expected_revision_);
  if ( result.status == ProviderSettingsCommitStatus::Conflict )
  {
    QT::QMessageBox::warning(
        &dialog_,
        "Provider Settings Conflict",
        "Provider settings changed elsewhere. Reopen the dialog and try again.");
    return false;
  }
  if ( result.status != ProviderSettingsCommitStatus::Saved )
  {
    QT::QMessageBox::warning(
        &dialog_, "Save Provider Settings", "Unable to save provider settings.");
    return false;
  }
  draft_ = normalized;
  working_ = normalized;
  revision_ = result.revision;
  expected_revision_ = result.revision;
  applied_ = true;
  connection_status_->setText("Settings saved.");
  RebuildTree();
  return true;
}

void DialogController::ConnectRequests()
{
  QT::QObject::connect(
      test_connection_, &QT::QPushButton::clicked, &dialog_, [this]()
      {
        StartRequest(RequestOperation::Test);
      });
  QT::QObject::connect(
      refresh_models_, &QT::QPushButton::clicked, &dialog_, [this]()
      {
        StartRequest(RequestOperation::Refresh);
      });

  poll_timer_ = new QT::QTimer(&dialog_);
  poll_timer_->setInterval(75);
  QT::QObject::connect(poll_timer_, &QT::QTimer::timeout, &dialog_, [this]()
  {
    PollRequest();
  });
  poll_timer_->start();

  QT::QObject::connect(apply_button_, &QT::QPushButton::clicked, &dialog_, [this]()
  {
    Apply();
  });
  QT::QObject::connect(
      buttons_, &QT::QDialogButtonBox::accepted, &dialog_, [this]()
      {
        if ( Apply() )
          dialog_.accept();
      });
  QT::QObject::connect(
      buttons_, &QT::QDialogButtonBox::rejected, &dialog_, [this]()
      {
        CancelAndForget();
        dialog_.reject();
      });
  QT::QObject::connect(
      &dialog_, &QT::QDialog::finished, &dialog_, [this](int)
      {
        CancelAndForget();
      });
}

} // namespace ida_agent::ai::provider_settings
