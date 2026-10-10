#pragma once

#include "ai/provider_settings_dialog.hpp"

#include <QtWidgets>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace ida_agent::ai::provider_settings
{

QT::QString ToQString(std::string_view value);
std::string ToString(const QT::QString &value);
void SetReadOnlyItem(QT::QTableWidgetItem &item);

enum class RequestOperation
{
  Test,
  Refresh,
};

struct DialogRequestState
{
  ProviderClient::RequestId request_id = 0;
  std::uint64_t generation = 0;
  std::string profile_id;
  RequestOperation operation = RequestOperation::Test;
};

class DialogController final
{
public:
  DialogController(
      ProviderManagerDraft &draft,
      std::uint64_t &revision,
      ProviderClient &client,
      const ProviderSettingsCommitCallback &commit);

  bool Exec();

private:
  void BuildUi();
  void BuildModelsPage();
  void BuildAdvancedPage();
  void ConnectCore();
  void ConnectModels();
  void ConnectAdvanced();
  void ConnectRequests();

  ProviderProfileDraft *CurrentProfile();
  const ProviderProfileDraft *CurrentProfile() const;
  void RefreshProfile();
  void RebuildTree();
  void UpdateEnabled();
  void UpdateProxyFields();

  void EnsureDefaultModel(ProviderProfileDraft &profile);
  void RefreshModelsTable();
  void RefreshDefaultModels();
  void UpdateModelActions();
  void UpdateModelDetails();
  void HandleModelItemChanged(QT::QTableWidgetItem *item);
  void EditSelectedModelMetadata(int row);
  void SetSelectedModelDefault(int row, bool show_disabled_message);

  void RefreshHeadersTable();
  void UpdateHeaderActions();
  void EditSelectedHeader();

  void StartRequest(RequestOperation operation);
  void CancelAndForget();
  void PollRequest();
  bool Apply();

  ProviderManagerDraft &draft_;
  std::uint64_t &revision_;
  ProviderClient &client_;
  const ProviderSettingsCommitCallback &commit_;
  ProviderManagerDraft working_;
  std::uint64_t expected_revision_ = 0;
  std::string selected_profile_id_;
  bool applied_ = false;
  bool loading_ = false;
  std::uint64_t request_generation_ = 0;
  std::optional<DialogRequestState> active_request_;

  QT::QDialog dialog_;
  QT::QVBoxLayout *main_layout_ = nullptr;
  QT::QListWidget *provider_list_ = nullptr;
  QT::QPushButton *add_provider_ = nullptr;
  QT::QPushButton *edit_provider_ = nullptr;
  QT::QPushButton *remove_provider_ = nullptr;
  QT::QPushButton *set_default_provider_ = nullptr;
  QT::QGroupBox *provider_group_ = nullptr;
  QT::QLineEdit *display_name_ = nullptr;
  QT::QComboBox *protocol_ = nullptr;
  QT::QComboBox *api_mode_ = nullptr;
  QT::QLineEdit *base_url_ = nullptr;
  QT::QLineEdit *api_key_ = nullptr;
  QT::QCheckBox *show_key_ = nullptr;
  QT::QPushButton *test_connection_ = nullptr;
  QT::QLabel *connection_status_ = nullptr;
  QT::QTabWidget *tabs_ = nullptr;

  QT::QTableWidget *models_ = nullptr;
  QT::QPushButton *refresh_models_ = nullptr;
  QT::QPushButton *add_model_ = nullptr;
  QT::QPushButton *edit_model_ = nullptr;
  QT::QPushButton *remove_model_ = nullptr;
  QT::QPushButton *set_default_model_ = nullptr;
  QT::QLabel *detail_id_ = nullptr;
  QT::QLabel *detail_capabilities_ = nullptr;
  QT::QLabel *detail_context_ = nullptr;
  QT::QLabel *detail_output_ = nullptr;
  QT::QLabel *detail_reasoning_effort_ = nullptr;
  QT::QLabel *detail_reasoning_summary_ = nullptr;
  QT::QComboBox *default_model_ = nullptr;

  QT::QTableWidget *headers_ = nullptr;
  QT::QPushButton *add_header_ = nullptr;
  QT::QPushButton *edit_header_ = nullptr;
  QT::QPushButton *remove_header_ = nullptr;
  QT::QComboBox *proxy_mode_ = nullptr;
  QT::QLineEdit *proxy_host_ = nullptr;
  QT::QSpinBox *proxy_port_ = nullptr;
  QT::QLineEdit *proxy_username_ = nullptr;
  QT::QLineEdit *proxy_password_ = nullptr;
  QT::QCheckBox *show_proxy_password_ = nullptr;
  QT::QCheckBox *proxy_bypass_local_ = nullptr;

  QT::QDialogButtonBox *buttons_ = nullptr;
  QT::QPushButton *ok_button_ = nullptr;
  QT::QPushButton *apply_button_ = nullptr;
  QT::QTimer *poll_timer_ = nullptr;
};

} // namespace ida_agent::ai::provider_settings
