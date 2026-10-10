#include "ai/provider_settings/dialog_controller.hpp"
#ifndef _WIN32
#include "ai/application_paths_linux.hpp"
#endif

#include <algorithm>

namespace ida_agent::ai::provider_settings
{
namespace
{

constexpr int OpenAiProtocolIndex = 0;
constexpr int ClaudeProtocolIndex = 1;

int ProtocolIndex(ProviderProtocol protocol)
{
  return protocol == ProviderProtocol::Claude
      ? ClaudeProtocolIndex
      : OpenAiProtocolIndex;
}

ProviderProtocol ProtocolFromIndex(int index)
{
  return index == ClaudeProtocolIndex
      ? ProviderProtocol::Claude
      : ProviderProtocol::OpenAI;
}

int ApiModeIndex(const ProviderSettingsDraft &draft)
{
  return draft.openai_api_mode == OpenAIApiMode::ChatCompletions ? 1 : 0;
}

} // namespace

QT::QString ToQString(std::string_view value)
{
  return QT::QString::fromUtf8(value.data(), static_cast<int>(value.size()));
}

std::string ToString(const QT::QString &value)
{
  const QT::QByteArray encoded = value.toUtf8();
  return std::string(encoded.constData(), static_cast<std::size_t>(encoded.size()));
}

void SetReadOnlyItem(QT::QTableWidgetItem &item)
{
  item.setFlags(item.flags() & ~QT::Qt::ItemIsEditable);
}

DialogController::DialogController(
    ProviderManagerDraft &draft,
    std::uint64_t &revision,
    ProviderClient &client,
    const ProviderSettingsCommitCallback &commit)
    : draft_(draft),
      revision_(revision),
      client_(client),
      commit_(commit),
      working_(draft),
      expected_revision_(revision),
      selected_profile_id_(working_.active_profile_id),
      dialog_(QT::QApplication::activeWindow())
{
  BuildUi();
  ConnectCore();
  ConnectModels();
  ConnectAdvanced();
  ConnectRequests();
}

bool DialogController::Exec()
{
  RebuildTree();
  dialog_.exec();
  CancelAndForget();
  return applied_;
}

ProviderProfileDraft *DialogController::CurrentProfile()
{
  return FindProvider(working_, selected_profile_id_);
}

const ProviderProfileDraft *DialogController::CurrentProfile() const
{
  return FindProvider(working_, selected_profile_id_);
}

void DialogController::BuildUi()
{
  dialog_.setObjectName("idaAgentProviderManager");
  dialog_.setWindowTitle("IDA Agent AI Provider Manager");
  dialog_.setWindowFlag(QT::Qt::WindowContextHelpButtonHint, false);
  dialog_.setModal(true);
  dialog_.setSizeGripEnabled(true);
  dialog_.resize(1060, 760);
  dialog_.setMinimumSize(900, 640);

  main_layout_ = new QT::QVBoxLayout(&dialog_);
  main_layout_->setContentsMargins(12, 10, 12, 10);
  main_layout_->setSpacing(8);
  auto *content_layout = new QT::QHBoxLayout();
  content_layout->setSpacing(10);
  main_layout_->addLayout(content_layout, 1);

  auto *providers_layout = new QT::QVBoxLayout();
  providers_layout->setSpacing(6);
  providers_layout->addWidget(new QT::QLabel("Providers:", &dialog_));
  provider_list_ = new QT::QListWidget(&dialog_);
  provider_list_->setObjectName("idaAgentProviderList");
  provider_list_->setMinimumWidth(220);
  provider_list_->setMaximumWidth(280);
  provider_list_->setSelectionMode(QT::QAbstractItemView::SingleSelection);
  providers_layout->addWidget(provider_list_, 1);
  auto *provider_buttons = new QT::QHBoxLayout();
  add_provider_ = new QT::QPushButton("Add...", &dialog_);
  edit_provider_ = new QT::QPushButton("Edit...", &dialog_);
  remove_provider_ = new QT::QPushButton("Remove", &dialog_);
  provider_buttons->addWidget(add_provider_);
  provider_buttons->addWidget(edit_provider_);
  provider_buttons->addWidget(remove_provider_);
  providers_layout->addLayout(provider_buttons);
  set_default_provider_ = new QT::QPushButton("Set as Default", &dialog_);
  providers_layout->addWidget(set_default_provider_);
  content_layout->addLayout(providers_layout);

  auto *settings_layout = new QT::QVBoxLayout();
  settings_layout->setSpacing(8);
  content_layout->addLayout(settings_layout, 1);
  provider_group_ = new QT::QGroupBox("Provider Settings", &dialog_);
  auto *provider_form = new QT::QFormLayout(provider_group_);
  provider_form->setContentsMargins(12, 10, 12, 10);
  provider_form->setHorizontalSpacing(10);
  provider_form->setVerticalSpacing(6);
  provider_form->setLabelAlignment(QT::Qt::AlignRight | QT::Qt::AlignVCenter);
  provider_form->setFieldGrowthPolicy(QT::QFormLayout::AllNonFixedFieldsGrow);
  display_name_ = new QT::QLineEdit(provider_group_);
  display_name_->setObjectName("idaAgentProviderName");
  display_name_->setClearButtonEnabled(true);
  provider_form->addRow("Name:", display_name_);
  protocol_ = new QT::QComboBox(provider_group_);
  protocol_->setObjectName("idaAgentProviderType");
  protocol_->addItems({"OpenAI Compatible", "Anthropic Messages"});
  provider_form->addRow("Type:", protocol_);
  api_mode_ = new QT::QComboBox(provider_group_);
  api_mode_->setObjectName("idaAgentProviderApiMode");
  provider_form->addRow("API Mode:", api_mode_);
  base_url_ = new QT::QLineEdit(provider_group_);
  base_url_->setObjectName("idaAgentProviderBaseUrl");
  base_url_->setClearButtonEnabled(true);
  base_url_->setToolTip("API prefix without the operation path.");
  provider_form->addRow("Base URL:", base_url_);

  auto *api_key_row = new QT::QWidget(provider_group_);
  auto *api_key_layout = new QT::QHBoxLayout(api_key_row);
  api_key_layout->setContentsMargins(0, 0, 0, 0);
  api_key_layout->setSpacing(8);
  api_key_ = new QT::QLineEdit(api_key_row);
  api_key_->setObjectName("idaAgentProviderApiKey");
  api_key_->setEchoMode(QT::QLineEdit::Password);
#ifdef _WIN32
  api_key_->setPlaceholderText(
      "Stored as plaintext in %LOCALAPPDATA%\\ida-agent\\ai\\providers.json (existing ida-mcp settings keep their original path)");
  api_key_->setToolTip(
      "API keys are stored as plaintext in %LOCALAPPDATA%\\ida-agent\\ai\\providers.json; existing ida-mcp settings keep their original path.");
#else
  api_key_->setPlaceholderText("Stored as plaintext in your user configuration");
  api_key_->setToolTip(QT::QString("API keys are stored as plaintext in %1.").arg(
      ToQString(LinuxAiPath("XDG_CONFIG_HOME", ".config", "providers.json").u8string())));
#endif
  show_key_ = new QT::QCheckBox("Show", api_key_row);
  api_key_layout->addWidget(api_key_, 1);
  api_key_layout->addWidget(show_key_);
  provider_form->addRow("API Key:", api_key_row);

  auto *connection_row = new QT::QWidget(provider_group_);
  auto *connection_layout = new QT::QHBoxLayout(connection_row);
  connection_layout->setContentsMargins(0, 0, 0, 0);
  connection_layout->setSpacing(10);
  test_connection_ = new QT::QPushButton("Test Connection", connection_row);
  connection_status_ = new QT::QLabel("Ready", connection_row);
  connection_status_->setObjectName("idaAgentProviderStatus");
  connection_status_->setTextInteractionFlags(QT::Qt::TextSelectableByMouse);
  connection_layout->addWidget(test_connection_);
  connection_layout->addWidget(connection_status_);
  connection_layout->addStretch(1);
  provider_form->addRow("", connection_row);
  settings_layout->addWidget(provider_group_);

  tabs_ = new QT::QTabWidget(&dialog_);
  settings_layout->addWidget(tabs_, 1);
  BuildModelsPage();
  BuildAdvancedPage();

  buttons_ = new QT::QDialogButtonBox(
      QT::QDialogButtonBox::Ok
          | QT::QDialogButtonBox::Cancel
          | QT::QDialogButtonBox::Apply,
      &dialog_);
  main_layout_->addWidget(buttons_);
  ok_button_ = buttons_->button(QT::QDialogButtonBox::Ok);
  apply_button_ = buttons_->button(QT::QDialogButtonBox::Apply);
}

void DialogController::UpdateProxyFields()
{
  const ProviderProfileDraft *profile = CurrentProfile();
  const bool enabled = profile != nullptr
      && profile->proxy.mode == ProviderProxyMode::Http
      && !active_request_.has_value();
  proxy_host_->setEnabled(enabled);
  proxy_port_->setEnabled(enabled);
  proxy_username_->setEnabled(enabled);
  proxy_password_->setEnabled(enabled);
  show_proxy_password_->setEnabled(enabled);
  proxy_bypass_local_->setEnabled(enabled);
}

void DialogController::UpdateEnabled()
{
  ProviderProfileDraft *profile = CurrentProfile();
  const bool available = profile != nullptr;
  const bool busy = active_request_.has_value();
  provider_list_->setEnabled(!busy);
  add_provider_->setEnabled(!busy);
  edit_provider_->setEnabled(available && !busy);
  remove_provider_->setEnabled(available && !profile->built_in && !busy);
  set_default_provider_->setEnabled(
      available && profile->id != working_.active_profile_id && !busy);
  provider_group_->setEnabled(available && !busy);
  tabs_->setEnabled(available && !busy);
  refresh_models_->setEnabled(available && !busy);
  add_model_->setEnabled(available && !busy);
  add_header_->setEnabled(available && !busy);
  proxy_mode_->setEnabled(available && !busy);
  ok_button_->setEnabled(!busy);
  apply_button_->setEnabled(!busy);
  UpdateModelActions();
  UpdateHeaderActions();
  UpdateProxyFields();
}

void DialogController::RefreshProfile()
{
  ProviderProfileDraft *profile = CurrentProfile();
  loading_ = true;
  const QT::QSignalBlocker name_blocker(display_name_);
  const QT::QSignalBlocker protocol_blocker(protocol_);
  const QT::QSignalBlocker mode_blocker(api_mode_);
  const QT::QSignalBlocker url_blocker(base_url_);
  const QT::QSignalBlocker key_blocker(api_key_);
  const QT::QSignalBlocker proxy_mode_blocker(proxy_mode_);
  const QT::QSignalBlocker proxy_host_blocker(proxy_host_);
  const QT::QSignalBlocker proxy_port_blocker(proxy_port_);
  const QT::QSignalBlocker proxy_username_blocker(proxy_username_);
  const QT::QSignalBlocker proxy_password_blocker(proxy_password_);
  const QT::QSignalBlocker proxy_bypass_blocker(proxy_bypass_local_);
  api_mode_->clear();
  if ( profile != nullptr )
  {
    display_name_->setText(ToQString(profile->settings.display_name));
    protocol_->setCurrentIndex(ProtocolIndex(profile->settings.protocol));
    if ( profile->settings.protocol == ProviderProtocol::Claude )
    {
      api_mode_->addItem("Messages");
      api_mode_->setEnabled(false);
    }
    else
    {
      api_mode_->addItems({"Responses", "Chat Completions"});
      api_mode_->setCurrentIndex(ApiModeIndex(profile->settings));
      api_mode_->setEnabled(true);
    }
    base_url_->setText(ToQString(profile->settings.base_url));
    api_key_->setText(ToQString(profile->settings.api_key));
    show_key_->setChecked(false);
    api_key_->setEchoMode(QT::QLineEdit::Password);
    proxy_mode_->setCurrentIndex(profile->proxy.mode == ProviderProxyMode::Direct
        ? 1
        : profile->proxy.mode == ProviderProxyMode::Http ? 2 : 0);
    proxy_host_->setText(ToQString(profile->proxy.host));
    proxy_port_->setValue(profile->proxy.port);
    proxy_username_->setText(ToQString(profile->proxy.username));
    proxy_password_->setText(ToQString(profile->proxy.password));
    show_proxy_password_->setChecked(false);
    proxy_password_->setEchoMode(QT::QLineEdit::Password);
    proxy_bypass_local_->setChecked(profile->proxy.bypass_local);
  }
  else
  {
    display_name_->clear();
    base_url_->clear();
    api_key_->clear();
    proxy_host_->clear();
    proxy_port_->setValue(0);
    proxy_username_->clear();
    proxy_password_->clear();
    proxy_bypass_local_->setChecked(true);
  }
  RefreshModelsTable();
  RefreshHeadersTable();
  loading_ = false;
  UpdateEnabled();
}

void DialogController::RebuildTree()
{
  const QT::QSignalBlocker blocker(provider_list_);
  provider_list_->clear();
  QT::QListWidgetItem *selected_item = nullptr;
  for ( const bool built_in : {true, false} )
  {
    auto *group = new QT::QListWidgetItem(
        built_in ? "Built-in Providers" : "Custom Providers",
        provider_list_);
    group->setFlags(group->flags() & ~QT::Qt::ItemIsSelectable);
    QT::QFont font = group->font();
    font.setBold(true);
    group->setFont(font);
    for ( const ProviderProfileDraft &profile : working_.profiles )
    {
      if ( profile.built_in != built_in )
        continue;
      auto *item = new QT::QListWidgetItem(
          QT::QString("    ") + ToQString(profile.settings.display_name),
          provider_list_);
      item->setData(QT::Qt::UserRole, ToQString(profile.id));
      if ( profile.id == working_.active_profile_id )
      {
        QT::QFont item_font = item->font();
        item_font.setBold(true);
        item->setFont(item_font);
        item->setToolTip("Default provider");
      }
      if ( profile.id == selected_profile_id_ )
        selected_item = item;
    }
  }
  if ( selected_item == nullptr )
  {
    selected_profile_id_ = working_.active_profile_id;
    for ( int index = 0; index < provider_list_->count(); ++index )
    {
      QT::QListWidgetItem *item = provider_list_->item(index);
      if ( ToString(item->data(QT::Qt::UserRole).toString()) == selected_profile_id_ )
      {
        selected_item = item;
        break;
      }
    }
  }
  provider_list_->setCurrentItem(selected_item);
  RefreshProfile();
}

void DialogController::ConnectCore()
{
  QT::QObject::connect(
      provider_list_,
      &QT::QListWidget::currentItemChanged,
      &dialog_,
      [this](QT::QListWidgetItem *current, QT::QListWidgetItem *)
      {
        if ( current == nullptr || active_request_.has_value() )
          return;
        const std::string id = ToString(current->data(QT::Qt::UserRole).toString());
        if ( id.empty() || FindProvider(working_, id) == nullptr )
          return;
        selected_profile_id_ = id;
        connection_status_->setText("Ready");
        RefreshProfile();
      });
  QT::QObject::connect(
      display_name_, &QT::QLineEdit::textEdited, &dialog_, [this](const QT::QString &text)
      {
        if ( !loading_ )
          if ( ProviderProfileDraft *profile = CurrentProfile() )
            profile->settings.display_name = ToString(text);
      });
  QT::QObject::connect(
      display_name_, &QT::QLineEdit::editingFinished, &dialog_, [this]()
      {
        if ( !loading_ )
          RebuildTree();
      });
  QT::QObject::connect(
      base_url_, &QT::QLineEdit::textEdited, &dialog_, [this](const QT::QString &text)
      {
        if ( !loading_ )
          if ( ProviderProfileDraft *profile = CurrentProfile() )
            profile->settings.base_url = ToString(text);
      });
  QT::QObject::connect(
      api_key_, &QT::QLineEdit::textEdited, &dialog_, [this](const QT::QString &text)
      {
        if ( !loading_ )
          if ( ProviderProfileDraft *profile = CurrentProfile() )
            profile->settings.api_key = ToString(text);
      });
  QT::QObject::connect(
      show_key_, &QT::QCheckBox::toggled, &dialog_, [this](bool checked)
      {
        api_key_->setEchoMode(checked ? QT::QLineEdit::Normal : QT::QLineEdit::Password);
      });
  QT::QObject::connect(
      protocol_, &QT::QComboBox::activated, &dialog_, [this](int index)
      {
        if ( loading_ )
          return;
        if ( ProviderProfileDraft *profile = CurrentProfile() )
        {
          SetProtocol(profile->settings, ProtocolFromIndex(index));
          RefreshProfile();
        }
      });
  QT::QObject::connect(
      api_mode_, &QT::QComboBox::activated, &dialog_, [this](int index)
      {
        if ( !loading_ )
          if ( ProviderProfileDraft *profile = CurrentProfile() )
            profile->settings.openai_api_mode = index == 1
                ? OpenAIApiMode::ChatCompletions
                : OpenAIApiMode::Responses;
      });
  QT::QObject::connect(add_provider_, &QT::QPushButton::clicked, &dialog_, [this]()
  {
    selected_profile_id_ = AddCustomProvider(working_);
    connection_status_->setText("Ready");
    RebuildTree();
    display_name_->setFocus();
    display_name_->selectAll();
  });
  QT::QObject::connect(edit_provider_, &QT::QPushButton::clicked, &dialog_, [this]()
  {
    display_name_->setFocus();
    display_name_->selectAll();
  });
  QT::QObject::connect(remove_provider_, &QT::QPushButton::clicked, &dialog_, [this]()
  {
    ProviderProfileDraft *profile = CurrentProfile();
    if ( profile == nullptr || profile->built_in )
      return;
    if ( QT::QMessageBox::question(
             &dialog_, "Remove Provider", "Remove the selected custom provider?")
        != QT::QMessageBox::Yes )
      return;
    RemoveCustomProvider(working_, profile->id);
    selected_profile_id_ = working_.active_profile_id;
    RebuildTree();
  });
  QT::QObject::connect(
      set_default_provider_, &QT::QPushButton::clicked, &dialog_, [this]()
      {
        if ( CurrentProfile() != nullptr )
        {
          working_.active_profile_id = selected_profile_id_;
          RebuildTree();
        }
      });
}

} // namespace ida_agent::ai::provider_settings
