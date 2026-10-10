#include "ai/provider_settings/dialog_controller.hpp"

#include <algorithm>
#include <cctype>
#include <optional>
#include <string>
#include <string_view>

namespace ida_agent::ai::provider_settings
{
namespace
{

constexpr int SystemProxyIndex = 0;
constexpr int DirectProxyIndex = 1;
constexpr int HttpProxyIndex = 2;

std::string LowerAscii(std::string value)
{
  std::transform(
      value.begin(),
      value.end(),
      value.begin(),
      [](unsigned char character)
      {
        return static_cast<char>(std::tolower(character));
      });
  return value;
}

bool HasControlCharacter(std::string_view value)
{
  return std::any_of(
      value.begin(),
      value.end(),
      [](unsigned char character)
      {
        return character < 0x20 || character == 0x7f;
      });
}

bool IsHeaderName(std::string_view value)
{
  constexpr std::string_view separators = "()<>@,;:\\\"/[]?={} \t";
  return !value.empty()
      && std::all_of(
          value.begin(),
          value.end(),
          [separators](unsigned char character)
          {
            return character > 0x20
                && character < 0x7f
                && separators.find(static_cast<char>(character)) == std::string_view::npos;
          });
}

ProviderProxyMode ProxyModeFromIndex(int index)
{
  if ( index == DirectProxyIndex )
    return ProviderProxyMode::Direct;
  if ( index == HttpProxyIndex )
    return ProviderProxyMode::Http;
  return ProviderProxyMode::System;
}

bool EditHeader(
    QT::QDialog &parent,
    const std::vector<ProviderHeaderDraft> &headers,
    std::optional<std::size_t> edited_index,
    ProviderHeaderDraft &header)
{
  QT::QDialog editor(&parent);
  editor.setWindowTitle(edited_index.has_value() ? "Edit Header" : "Add Header");
  editor.setWindowFlag(QT::Qt::WindowContextHelpButtonHint, false);
  editor.setModal(true);

  auto *layout = new QT::QVBoxLayout(&editor);
  auto *form = new QT::QFormLayout();
  auto *name = new QT::QLineEdit(&editor);
  name->setText(ToQString(header.name));
  name->setClearButtonEnabled(true);
  auto *value_row = new QT::QWidget(&editor);
  auto *value_layout = new QT::QHBoxLayout(value_row);
  value_layout->setContentsMargins(0, 0, 0, 0);
  auto *value = new QT::QLineEdit(value_row);
  value->setEchoMode(QT::QLineEdit::Password);
  value->setText(ToQString(header.value));
  auto *show = new QT::QCheckBox("Show", value_row);
  value_layout->addWidget(value, 1);
  value_layout->addWidget(show);
  form->addRow("Name:", name);
  form->addRow("Value:", value_row);
  layout->addLayout(form);
  auto *buttons = new QT::QDialogButtonBox(
      QT::QDialogButtonBox::Ok | QT::QDialogButtonBox::Cancel,
      &editor);
  layout->addWidget(buttons);

  QT::QObject::connect(
      show, &QT::QCheckBox::toggled, &editor, [value](bool checked)
      {
        value->setEchoMode(checked ? QT::QLineEdit::Normal : QT::QLineEdit::Password);
      });
  QT::QObject::connect(
      buttons, &QT::QDialogButtonBox::rejected, &editor, &QT::QDialog::reject);
  QT::QObject::connect(
      buttons, &QT::QDialogButtonBox::accepted, &editor, [&]()
      {
        const std::string candidate_name = ToString(name->text().trimmed());
        const std::string candidate_value = ToString(value->text());
        if ( !IsHeaderName(candidate_name) || HasControlCharacter(candidate_value) )
        {
          QT::QMessageBox::warning(
              &editor,
              "Invalid Header",
              "Header names must be non-empty HTTP tokens, and values cannot contain control characters.");
          return;
        }
        const std::string lowered = LowerAscii(candidate_name);
        for ( std::size_t index = 0; index < headers.size(); ++index )
        {
          if ( (!edited_index.has_value() || index != *edited_index)
              && LowerAscii(headers[index].name) == lowered )
          {
            QT::QMessageBox::warning(
                &editor, "Duplicate Header", "A header with that name already exists.");
            return;
          }
        }
        header.name = candidate_name;
        header.value = candidate_value;
        editor.accept();
      });
  name->setFocus();
  return editor.exec() == QT::QDialog::Accepted;
}

} // namespace

void DialogController::BuildAdvancedPage()
{
  auto *advanced_page = new QT::QWidget(tabs_);
  auto *advanced_layout = new QT::QVBoxLayout(advanced_page);
  advanced_layout->setContentsMargins(8, 8, 8, 8);
  auto *headers_group = new QT::QGroupBox("Headers", advanced_page);
  auto *headers_layout = new QT::QVBoxLayout(headers_group);
  headers_ = new QT::QTableWidget(headers_group);
  headers_->setObjectName("idaAgentProviderHeaders");
  headers_->setColumnCount(3);
  headers_->setHorizontalHeaderLabels({"Enabled", "Name", "Value"});
  headers_->setSelectionBehavior(QT::QAbstractItemView::SelectRows);
  headers_->setSelectionMode(QT::QAbstractItemView::SingleSelection);
  headers_->verticalHeader()->setVisible(false);
  headers_->horizontalHeader()->setSectionResizeMode(0, QT::QHeaderView::ResizeToContents);
  headers_->horizontalHeader()->setSectionResizeMode(1, QT::QHeaderView::Stretch);
  headers_->horizontalHeader()->setSectionResizeMode(2, QT::QHeaderView::Stretch);
  headers_layout->addWidget(headers_);
  auto *header_buttons = new QT::QHBoxLayout();
  add_header_ = new QT::QPushButton("Add...", headers_group);
  edit_header_ = new QT::QPushButton("Edit...", headers_group);
  remove_header_ = new QT::QPushButton("Remove", headers_group);
  header_buttons->addWidget(add_header_);
  header_buttons->addWidget(edit_header_);
  header_buttons->addWidget(remove_header_);
  header_buttons->addStretch(1);
  headers_layout->addLayout(header_buttons);
  advanced_layout->addWidget(headers_group, 1);

  auto *proxy_group = new QT::QGroupBox("Proxy", advanced_page);
  auto *proxy_form = new QT::QFormLayout(proxy_group);
  proxy_mode_ = new QT::QComboBox(proxy_group);
  proxy_mode_->addItems({"System Proxy", "Direct Connection", "HTTP(S) Proxy"});
  proxy_host_ = new QT::QLineEdit(proxy_group);
  proxy_port_ = new QT::QSpinBox(proxy_group);
  proxy_port_->setRange(0, 65535);
  proxy_username_ = new QT::QLineEdit(proxy_group);
  auto *proxy_password_row = new QT::QWidget(proxy_group);
  auto *proxy_password_layout = new QT::QHBoxLayout(proxy_password_row);
  proxy_password_layout->setContentsMargins(0, 0, 0, 0);
  proxy_password_ = new QT::QLineEdit(proxy_password_row);
  proxy_password_->setEchoMode(QT::QLineEdit::Password);
  show_proxy_password_ = new QT::QCheckBox("Show", proxy_password_row);
  proxy_password_layout->addWidget(proxy_password_, 1);
  proxy_password_layout->addWidget(show_proxy_password_);
  proxy_bypass_local_ = new QT::QCheckBox(
      "Bypass proxy for local addresses", proxy_group);
  auto *proxy_note = new QT::QLabel(
      "HTTP proxies can carry HTTPS through CONNECT. SOCKS and TLS-to-proxy are not supported.",
      proxy_group);
  proxy_note->setWordWrap(true);
  proxy_form->addRow("Mode:", proxy_mode_);
  proxy_form->addRow("Host:", proxy_host_);
  proxy_form->addRow("Port:", proxy_port_);
  proxy_form->addRow("Username:", proxy_username_);
  proxy_form->addRow("Password:", proxy_password_row);
  proxy_form->addRow("", proxy_bypass_local_);
  proxy_form->addRow("", proxy_note);
  advanced_layout->addWidget(proxy_group);
  tabs_->addTab(advanced_page, "Advanced");
}

void DialogController::UpdateHeaderActions()
{
  ProviderProfileDraft *profile = CurrentProfile();
  const int row = headers_->currentRow();
  const bool selected = profile != nullptr
      && row >= 0
      && static_cast<std::size_t>(row) < profile->custom_headers.size();
  edit_header_->setEnabled(selected && !active_request_.has_value());
  remove_header_->setEnabled(selected && !active_request_.has_value());
}

void DialogController::RefreshHeadersTable()
{
  const QT::QSignalBlocker blocker(headers_);
  headers_->clearContents();
  ProviderProfileDraft *profile = CurrentProfile();
  const int row_count = profile == nullptr
      ? 0
      : static_cast<int>(profile->custom_headers.size());
  headers_->setRowCount(row_count);
  for ( int row = 0; row < row_count; ++row )
  {
    const ProviderHeaderDraft &header = profile->custom_headers[static_cast<std::size_t>(row)];
    auto *enabled = new QT::QTableWidgetItem();
    enabled->setFlags(
        (enabled->flags() | QT::Qt::ItemIsUserCheckable) & ~QT::Qt::ItemIsEditable);
    enabled->setCheckState(header.enabled ? QT::Qt::Checked : QT::Qt::Unchecked);
    auto *name = new QT::QTableWidgetItem(ToQString(header.name));
    auto *value = new QT::QTableWidgetItem("********");
    SetReadOnlyItem(*name);
    SetReadOnlyItem(*value);
    headers_->setItem(row, 0, enabled);
    headers_->setItem(row, 1, name);
    headers_->setItem(row, 2, value);
  }
  UpdateHeaderActions();
}

void DialogController::EditSelectedHeader()
{
  ProviderProfileDraft *profile = CurrentProfile();
  const int row = headers_->currentRow();
  if ( profile == nullptr
      || row < 0
      || static_cast<std::size_t>(row) >= profile->custom_headers.size() )
    return;
  ProviderHeaderDraft edited = profile->custom_headers[static_cast<std::size_t>(row)];
  if ( EditHeader(
           dialog_, profile->custom_headers, static_cast<std::size_t>(row), edited) )
  {
    profile->custom_headers[static_cast<std::size_t>(row)] = std::move(edited);
    RefreshHeadersTable();
    headers_->selectRow(row);
  }
}

void DialogController::ConnectAdvanced()
{
  QT::QObject::connect(add_header_, &QT::QPushButton::clicked, &dialog_, [this]()
  {
    ProviderProfileDraft *profile = CurrentProfile();
    if ( profile == nullptr )
      return;
    ProviderHeaderDraft added;
    if ( EditHeader(dialog_, profile->custom_headers, std::nullopt, added) )
    {
      profile->custom_headers.push_back(std::move(added));
      RefreshHeadersTable();
      headers_->selectRow(headers_->rowCount() - 1);
    }
  });
  QT::QObject::connect(edit_header_, &QT::QPushButton::clicked, &dialog_, [this]()
  {
    EditSelectedHeader();
  });
  QT::QObject::connect(remove_header_, &QT::QPushButton::clicked, &dialog_, [this]()
  {
    ProviderProfileDraft *profile = CurrentProfile();
    const int row = headers_->currentRow();
    if ( profile == nullptr
        || row < 0
        || static_cast<std::size_t>(row) >= profile->custom_headers.size() )
      return;
    profile->custom_headers.erase(profile->custom_headers.begin() + row);
    RefreshHeadersTable();
  });
  QT::QObject::connect(
      headers_, &QT::QTableWidget::itemChanged, &dialog_, [this](QT::QTableWidgetItem *item)
      {
        if ( loading_ || item == nullptr || item->column() != 0 )
          return;
        ProviderProfileDraft *profile = CurrentProfile();
        const int row = item->row();
        if ( profile != nullptr
            && row >= 0
            && static_cast<std::size_t>(row) < profile->custom_headers.size() )
        {
          profile->custom_headers[static_cast<std::size_t>(row)].enabled =
              item->checkState() == QT::Qt::Checked;
        }
      });
  QT::QObject::connect(
      headers_, &QT::QTableWidget::itemSelectionChanged, &dialog_, [this]()
      {
        UpdateHeaderActions();
      });
  QT::QObject::connect(
      headers_, &QT::QTableWidget::cellDoubleClicked, &dialog_, [this](int, int)
      {
        EditSelectedHeader();
      });

  QT::QObject::connect(proxy_mode_, &QT::QComboBox::activated, &dialog_, [this](int index)
  {
    if ( loading_ )
      return;
    if ( ProviderProfileDraft *profile = CurrentProfile() )
    {
      profile->proxy.mode = ProxyModeFromIndex(index);
      if ( profile->proxy.mode != ProviderProxyMode::Http )
      {
        profile->proxy.host.clear();
        profile->proxy.port = 0;
        profile->proxy.username.clear();
        profile->proxy.password.clear();
        profile->proxy.bypass_local = true;
      }
      RefreshProfile();
    }
  });
  QT::QObject::connect(
      proxy_host_, &QT::QLineEdit::textEdited, &dialog_, [this](const QT::QString &text)
      {
        if ( !loading_ )
          if ( ProviderProfileDraft *profile = CurrentProfile() )
            profile->proxy.host = ToString(text);
      });
  QT::QObject::connect(
      proxy_port_, &QT::QSpinBox::valueChanged, &dialog_, [this](int value)
      {
        if ( !loading_ )
          if ( ProviderProfileDraft *profile = CurrentProfile() )
            profile->proxy.port = static_cast<std::uint16_t>(value);
      });
  QT::QObject::connect(
      proxy_username_, &QT::QLineEdit::textEdited, &dialog_, [this](const QT::QString &text)
      {
        if ( !loading_ )
          if ( ProviderProfileDraft *profile = CurrentProfile() )
            profile->proxy.username = ToString(text);
      });
  QT::QObject::connect(
      proxy_password_, &QT::QLineEdit::textEdited, &dialog_, [this](const QT::QString &text)
      {
        if ( !loading_ )
          if ( ProviderProfileDraft *profile = CurrentProfile() )
            profile->proxy.password = ToString(text);
      });
  QT::QObject::connect(
      show_proxy_password_, &QT::QCheckBox::toggled, &dialog_, [this](bool checked)
      {
        proxy_password_->setEchoMode(
            checked ? QT::QLineEdit::Normal : QT::QLineEdit::Password);
      });
  QT::QObject::connect(
      proxy_bypass_local_, &QT::QCheckBox::toggled, &dialog_, [this](bool checked)
      {
        if ( !loading_ )
          if ( ProviderProfileDraft *profile = CurrentProfile() )
            profile->proxy.bypass_local = checked;
      });
}

} // namespace ida_agent::ai::provider_settings
