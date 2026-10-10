#include "ai/provider_settings/dialog_controller.hpp"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <system_error>

namespace ida_agent::ai::provider_settings
{
namespace
{

constexpr int EnabledColumn = 0;
constexpr int ModelIdColumn = 1;
constexpr int CapabilitiesColumn = 2;
constexpr int ContextColumn = 3;
constexpr int MaxOutputColumn = 4;
constexpr int DefaultColumn = 5;

constexpr const char *ModelMetadataTooltip =
    "Double-click Capabilities, Context, or Max Output to edit. "
    "Standard comma-separated capabilities: reasoning, vision, tools, "
    "structured-output, web-search, parallel-tools, audio, image-generation. "
    "The tools capability is added automatically.";
constexpr const char *InvalidNumberStatus =
    "Invalid model metadata: enter an unsigned decimal value from 0 to 4294967295.";
constexpr const char *InvalidCapabilitiesStatus =
    "Invalid model capabilities: remove control characters and keep within 1024 bytes.";

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

bool ParseMetadataNumber(
    const QT::QString &text,
    std::uint32_t default_value,
    std::uint32_t &value)
{
  const std::string input = ToString(text.trimmed());
  if ( input.empty() )
  {
    value = default_value;
    return true;
  }
  std::uint32_t parsed = 0;
  const auto result = std::from_chars(
      input.data(),
      input.data() + input.size(),
      parsed,
      10);
  if ( result.ec != std::errc{} || result.ptr != input.data() + input.size() )
    return false;
  value = parsed == 0 ? default_value : parsed;
  return true;
}

QT::QString NumericValue(std::uint32_t value)
{
  return QT::QString::number(value);
}

bool EditModelMetadata(
    QT::QDialog &parent,
    const ProviderModelDraft &current,
    ProviderModelDraft &updated)
{
  QT::QDialog editor(&parent);
  editor.setWindowTitle("Edit Model Metadata");
  editor.setWindowFlag(QT::Qt::WindowContextHelpButtonHint, false);
  editor.setModal(true);
  editor.setMinimumWidth(560);

  auto *layout = new QT::QVBoxLayout(&editor);
  auto *form = new QT::QFormLayout();
  auto *model_id = new QT::QLabel(ToQString(current.id), &editor);
  model_id->setTextInteractionFlags(QT::Qt::TextSelectableByMouse);
  auto *capabilities = new QT::QLineEdit(ToQString(current.capabilities), &editor);
  capabilities->setClearButtonEnabled(true);
  capabilities->setToolTip(ModelMetadataTooltip);
  auto *context = new QT::QLineEdit(NumericValue(current.context_length), &editor);
  auto *max_output = new QT::QLineEdit(NumericValue(current.max_output_tokens), &editor);
  auto *reasoning_effort = new QT::QComboBox(&editor);
  reasoning_effort->addItem("Provider default", "default");
  reasoning_effort->addItem("None", "none");
  reasoning_effort->addItem("Low", "low");
  reasoning_effort->addItem("Medium", "medium");
  reasoning_effort->addItem("High", "high");
  reasoning_effort->addItem("XHigh", "xhigh");
  reasoning_effort->addItem("Max", "max");
  reasoning_effort->setCurrentIndex(reasoning_effort->findData(
      ToQString(ProviderReasoningEffortName(current.reasoning_effort))));
  auto *reasoning_summary = new QT::QComboBox(&editor);
  reasoning_summary->addItem("Hidden", "hidden");
  reasoning_summary->addItem("Visible (no request field)", "visible");
  reasoning_summary->addItem("Auto", "auto");
  reasoning_summary->addItem("Concise", "concise");
  reasoning_summary->addItem("Detailed", "detailed");
  reasoning_summary->setCurrentIndex(reasoning_summary->findData(
      ToQString(ProviderReasoningSummaryName(current.reasoning_summary))));
  form->addRow("Model ID:", model_id);
  form->addRow("Capabilities:", capabilities);
  form->addRow("Context Length:", context);
  form->addRow("Max Output:", max_output);
  form->addRow("Reasoning Effort:", reasoning_effort);
  form->addRow("Reasoning Summary/Display:", reasoning_summary);
  layout->addLayout(form);

  auto *capability_help = new QT::QLabel(
      "Standard capabilities: reasoning, vision, tools, structured-output, "
      "web-search, parallel-tools, audio, image-generation. Use commas to separate values. "
      "Tools is added automatically. "
      "Hidden suppresses thinking; Visible shows provider output without adding a request field; "
      "Auto/Concise/Detailed requests an OpenAI Responses summary and keeps [Thinking].",
      &editor);
  capability_help->setWordWrap(true);
  layout->addWidget(capability_help);

  auto *buttons = new QT::QDialogButtonBox(
      QT::QDialogButtonBox::Ok | QT::QDialogButtonBox::Cancel,
      &editor);
  layout->addWidget(buttons);
  QT::QObject::connect(buttons, &QT::QDialogButtonBox::rejected, &editor, &QT::QDialog::reject);
  QT::QObject::connect(buttons, &QT::QDialogButtonBox::accepted, &editor, [&]()
  {
    const std::string candidate_capabilities = ToString(capabilities->text().trimmed());
    if ( candidate_capabilities.size() > MaxCapabilitiesLength
        || HasControlCharacter(candidate_capabilities) )
    {
      QT::QMessageBox::warning(&editor, "Edit Model Metadata", InvalidCapabilitiesStatus);
      return;
    }
    std::uint32_t candidate_context = 0;
    std::uint32_t candidate_output = 0;
    if ( !ParseMetadataNumber(
             context->text(), DefaultModelContextLength, candidate_context)
        || !ParseMetadataNumber(
            max_output->text(), DefaultModelMaxOutputTokens, candidate_output) )
    {
      QT::QMessageBox::warning(&editor, "Edit Model Metadata", InvalidNumberStatus);
      return;
    }
    updated = current;
    updated.capabilities = candidate_capabilities;
    updated.context_length = candidate_context;
    updated.max_output_tokens = candidate_output;
    if ( !ParseProviderReasoningEffort(
             ToString(reasoning_effort->currentData().toString()),
             updated.reasoning_effort)
        || !ParseProviderReasoningSummary(
            ToString(reasoning_summary->currentData().toString()),
            updated.reasoning_summary) )
    {
      QT::QMessageBox::warning(
          &editor, "Edit Model Metadata", "Invalid reasoning configuration.");
      return;
    }
    ApplyDefaultModelMetadata(updated);
    editor.accept();
  });
  return editor.exec() == QT::QDialog::Accepted;
}

} // namespace

void DialogController::BuildModelsPage()
{
  auto *models_page = new QT::QWidget(tabs_);
  auto *models_layout = new QT::QVBoxLayout(models_page);
  models_layout->setContentsMargins(8, 8, 8, 8);
  models_layout->setSpacing(7);
  auto *models_toolbar = new QT::QHBoxLayout();
  models_toolbar->addWidget(new QT::QLabel("Models:", models_page));
  models_toolbar->addStretch(1);
  refresh_models_ = new QT::QPushButton("Refresh Models", models_page);
  add_model_ = new QT::QPushButton("Add Model...", models_page);
  edit_model_ = new QT::QPushButton("Edit Metadata...", models_page);
  remove_model_ = new QT::QPushButton("Remove Model", models_page);
  set_default_model_ = new QT::QPushButton("Set Default", models_page);
  models_toolbar->addWidget(refresh_models_);
  models_toolbar->addWidget(add_model_);
  models_toolbar->addWidget(edit_model_);
  models_toolbar->addWidget(remove_model_);
  models_toolbar->addWidget(set_default_model_);
  models_layout->addLayout(models_toolbar);

  models_ = new QT::QTableWidget(models_page);
  models_->setObjectName("idaAgentProviderModels");
  models_->setColumnCount(6);
  models_->setHorizontalHeaderLabels(
      {"Enabled", "Model ID", "Capabilities", "Context", "Max Output", "Default"});
  models_->setSelectionBehavior(QT::QAbstractItemView::SelectItems);
  models_->setSelectionMode(QT::QAbstractItemView::SingleSelection);
  models_->setEditTriggers(
      QT::QAbstractItemView::DoubleClicked
      | QT::QAbstractItemView::SelectedClicked
      | QT::QAbstractItemView::EditKeyPressed
      | QT::QAbstractItemView::AnyKeyPressed);
  models_->setAlternatingRowColors(true);
  models_->setSortingEnabled(false);
  models_->verticalHeader()->setVisible(false);
  models_->horizontalHeader()->setSectionResizeMode(
      EnabledColumn, QT::QHeaderView::ResizeToContents);
  models_->horizontalHeader()->setSectionResizeMode(ModelIdColumn, QT::QHeaderView::Stretch);
  models_->horizontalHeader()->setSectionResizeMode(
      CapabilitiesColumn, QT::QHeaderView::Stretch);
  models_->horizontalHeader()->setSectionResizeMode(
      ContextColumn, QT::QHeaderView::ResizeToContents);
  models_->horizontalHeader()->setSectionResizeMode(
      MaxOutputColumn, QT::QHeaderView::ResizeToContents);
  models_->horizontalHeader()->setSectionResizeMode(
      DefaultColumn, QT::QHeaderView::ResizeToContents);
  models_->setToolTip(ModelMetadataTooltip);
  models_layout->addWidget(models_, 1);

  auto *model_details = new QT::QGroupBox("Selected Model", models_page);
  auto *details_form = new QT::QFormLayout(model_details);
  detail_id_ = new QT::QLabel("-", model_details);
  detail_capabilities_ = new QT::QLabel("-", model_details);
  detail_context_ = new QT::QLabel("-", model_details);
  detail_output_ = new QT::QLabel("-", model_details);
  detail_reasoning_effort_ = new QT::QLabel("-", model_details);
  detail_reasoning_summary_ = new QT::QLabel("-", model_details);
  for ( QT::QLabel *label : {
            detail_id_, detail_capabilities_, detail_context_, detail_output_,
            detail_reasoning_effort_, detail_reasoning_summary_} )
  {
    label->setTextInteractionFlags(QT::Qt::TextSelectableByMouse);
  }
  details_form->addRow("Model ID:", detail_id_);
  details_form->addRow("Capabilities:", detail_capabilities_);
  details_form->addRow("Context Length:", detail_context_);
  details_form->addRow("Max Output:", detail_output_);
  details_form->addRow("Reasoning Effort:", detail_reasoning_effort_);
  details_form->addRow("Reasoning Summary/Display:", detail_reasoning_summary_);
  models_layout->addWidget(model_details);
  tabs_->addTab(models_page, "Models");

  auto *defaults_page = new QT::QWidget(tabs_);
  auto *defaults_form = new QT::QFormLayout(defaults_page);
  defaults_form->setContentsMargins(12, 12, 12, 12);
  default_model_ = new QT::QComboBox(defaults_page);
  defaults_form->addRow("Default Model:", default_model_);
  tabs_->addTab(defaults_page, "Defaults");
}

void DialogController::EnsureDefaultModel(ProviderProfileDraft &profile)
{
  const auto current = std::find_if(
      profile.models.begin(),
      profile.models.end(),
      [&profile](const ProviderModelDraft &model)
      {
        return model.enabled && model.id == profile.settings.model;
      });
  if ( current != profile.models.end() )
    return;
  const auto first = std::find_if(
      profile.models.begin(),
      profile.models.end(),
      [](const ProviderModelDraft &model) { return model.enabled; });
  profile.settings.model = first == profile.models.end() ? std::string{} : first->id;
}

void DialogController::UpdateModelDetails()
{
  ProviderProfileDraft *profile = CurrentProfile();
  const int row = models_->currentRow();
  if ( profile == nullptr
      || row < 0
      || static_cast<std::size_t>(row) >= profile->models.size() )
  {
    detail_id_->setText("-");
    detail_capabilities_->setText("-");
    detail_context_->setText("-");
    detail_output_->setText("-");
    detail_reasoning_effort_->setText("-");
    detail_reasoning_summary_->setText("-");
    return;
  }
  const ProviderModelDraft &model = profile->models[static_cast<std::size_t>(row)];
  detail_id_->setText(ToQString(model.id));
  detail_capabilities_->setText(
      model.capabilities.empty() ? QT::QString("Not reported") : ToQString(model.capabilities));
  detail_context_->setText(NumericValue(model.context_length));
  detail_output_->setText(NumericValue(model.max_output_tokens));
  detail_reasoning_effort_->setText(
      ToQString(ProviderReasoningEffortName(model.reasoning_effort)));
  detail_reasoning_summary_->setText(
      ToQString(ProviderReasoningSummaryName(model.reasoning_summary)));
}

void DialogController::UpdateModelActions()
{
  ProviderProfileDraft *profile = CurrentProfile();
  const int row = models_->currentRow();
  const bool selected = profile != nullptr
      && row >= 0
      && static_cast<std::size_t>(row) < profile->models.size();
  remove_model_->setEnabled(selected && !active_request_.has_value());
  edit_model_->setEnabled(selected && !active_request_.has_value());
  set_default_model_->setEnabled(
      selected
      && profile->models[static_cast<std::size_t>(row)].enabled
      && !active_request_.has_value());
  UpdateModelDetails();
}

void DialogController::RefreshDefaultModels()
{
  const QT::QSignalBlocker blocker(default_model_);
  default_model_->clear();
  default_model_->addItem("No default model", QT::QString());
  ProviderProfileDraft *profile = CurrentProfile();
  if ( profile == nullptr )
    return;
  int selected_index = 0;
  for ( const ProviderModelDraft &model : profile->models )
  {
    if ( !model.enabled )
      continue;
    default_model_->addItem(ToQString(model.id), ToQString(model.id));
    if ( model.id == profile->settings.model )
      selected_index = default_model_->count() - 1;
  }
  default_model_->setCurrentIndex(selected_index);
}

void DialogController::RefreshModelsTable()
{
  const QT::QSignalBlocker blocker(models_);
  models_->clearContents();
  ProviderProfileDraft *profile = CurrentProfile();
  const int row_count = profile == nullptr ? 0 : static_cast<int>(profile->models.size());
  models_->setRowCount(row_count);
  for ( int row = 0; row < row_count; ++row )
  {
    const ProviderModelDraft &model = profile->models[static_cast<std::size_t>(row)];
    auto *enabled = new QT::QTableWidgetItem();
    enabled->setFlags(
        (enabled->flags() | QT::Qt::ItemIsUserCheckable) & ~QT::Qt::ItemIsEditable);
    enabled->setCheckState(model.enabled ? QT::Qt::Checked : QT::Qt::Unchecked);
    auto *model_id = new QT::QTableWidgetItem(ToQString(model.id));
    auto *capabilities = new QT::QTableWidgetItem(ToQString(model.capabilities));
    auto *context = new QT::QTableWidgetItem(NumericValue(model.context_length));
    auto *max_output = new QT::QTableWidgetItem(NumericValue(model.max_output_tokens));
    auto *is_default = new QT::QTableWidgetItem(
        model.id == profile->settings.model ? QT::QString("*") : QT::QString());
    SetReadOnlyItem(*model_id);
    SetReadOnlyItem(*is_default);
    capabilities->setFlags(capabilities->flags() | QT::Qt::ItemIsEditable);
    context->setFlags(context->flags() | QT::Qt::ItemIsEditable);
    max_output->setFlags(max_output->flags() | QT::Qt::ItemIsEditable);
    capabilities->setToolTip(ModelMetadataTooltip);
    context->setToolTip(ModelMetadataTooltip);
    max_output->setToolTip(ModelMetadataTooltip);
    is_default->setTextAlignment(QT::Qt::AlignCenter);
    models_->setItem(row, EnabledColumn, enabled);
    models_->setItem(row, ModelIdColumn, model_id);
    models_->setItem(row, CapabilitiesColumn, capabilities);
    models_->setItem(row, ContextColumn, context);
    models_->setItem(row, MaxOutputColumn, max_output);
    models_->setItem(row, DefaultColumn, is_default);
  }
  if ( row_count > 0 )
    models_->selectRow(0);
  RefreshDefaultModels();
  UpdateModelActions();
}

void DialogController::HandleModelItemChanged(QT::QTableWidgetItem *item)
{
  if ( loading_ || item == nullptr )
    return;
  ProviderProfileDraft *profile = CurrentProfile();
  const int row = item->row();
  if ( profile == nullptr
      || row < 0
      || static_cast<std::size_t>(row) >= profile->models.size() )
    return;
  ProviderModelDraft &model = profile->models[static_cast<std::size_t>(row)];

  if ( item->column() == EnabledColumn )
  {
    model.enabled = item->checkState() == QT::Qt::Checked;
    EnsureDefaultModel(*profile);
    RefreshModelsTable();
    models_->selectRow(row);
    return;
  }
  if ( item->column() == CapabilitiesColumn )
  {
    const std::string candidate = ToString(item->text().trimmed());
    if ( candidate.size() > MaxCapabilitiesLength || HasControlCharacter(candidate) )
    {
      const QT::QSignalBlocker blocker(models_);
      item->setText(ToQString(model.capabilities));
      connection_status_->setText(InvalidCapabilitiesStatus);
      UpdateModelDetails();
      return;
    }
    model.capabilities = candidate;
    ApplyDefaultModelMetadata(model);
    const QT::QSignalBlocker blocker(models_);
    item->setText(ToQString(model.capabilities));
    UpdateModelDetails();
    return;
  }
  if ( item->column() != ContextColumn && item->column() != MaxOutputColumn )
    return;

  const bool context = item->column() == ContextColumn;
  const std::uint32_t old_value = context
      ? model.context_length
      : model.max_output_tokens;
  std::uint32_t value = 0;
  if ( !ParseMetadataNumber(
           item->text(),
           context ? DefaultModelContextLength : DefaultModelMaxOutputTokens,
           value) )
  {
    const QT::QSignalBlocker blocker(models_);
    item->setText(NumericValue(old_value));
    connection_status_->setText(InvalidNumberStatus);
    UpdateModelDetails();
    return;
  }
  if ( context )
    model.context_length = value;
  else
    model.max_output_tokens = value;
  const QT::QSignalBlocker blocker(models_);
  item->setText(NumericValue(value));
  UpdateModelDetails();
}

void DialogController::EditSelectedModelMetadata(int row)
{
  ProviderProfileDraft *profile = CurrentProfile();
  if ( profile == nullptr
      || row < 0
      || static_cast<std::size_t>(row) >= profile->models.size() )
    return;
  ProviderModelDraft updated;
  if ( !EditModelMetadata(
           dialog_, profile->models[static_cast<std::size_t>(row)], updated) )
    return;
  profile->models[static_cast<std::size_t>(row)] = std::move(updated);
  RefreshModelsTable();
  models_->setCurrentCell(row, CapabilitiesColumn);
  connection_status_->setText("Model metadata updated. Apply to save.");
}

void DialogController::SetSelectedModelDefault(int row, bool show_disabled_message)
{
  ProviderProfileDraft *profile = CurrentProfile();
  if ( profile == nullptr
      || row < 0
      || static_cast<std::size_t>(row) >= profile->models.size() )
    return;
  if ( !profile->models[static_cast<std::size_t>(row)].enabled )
  {
    if ( show_disabled_message )
    {
      QT::QMessageBox::information(
          &dialog_, "Default Model", "Enable the model before making it the default.");
    }
    return;
  }
  profile->settings.model = profile->models[static_cast<std::size_t>(row)].id;
  RefreshModelsTable();
  models_->selectRow(row);
}

void DialogController::ConnectModels()
{
  QT::QObject::connect(add_model_, &QT::QPushButton::clicked, &dialog_, [this]()
  {
    ProviderProfileDraft *profile = CurrentProfile();
    if ( profile == nullptr )
      return;
    bool accepted = false;
    const QT::QString model_id = QT::QInputDialog::getText(
        &dialog_, "Add Model", "Model ID:", QT::QLineEdit::Normal, {}, &accepted).trimmed();
    if ( !accepted || model_id.isEmpty() )
      return;
    const std::string id = ToString(model_id);
    if ( std::any_of(
             profile->models.begin(),
             profile->models.end(),
             [&id](const ProviderModelDraft &model) { return model.id == id; }) )
    {
      QT::QMessageBox::warning(&dialog_, "Add Model", "That model ID already exists.");
      return;
    }
    ProviderModelDraft added;
    added.id = id;
    ApplyDefaultModelMetadata(added);
    profile->models.push_back(std::move(added));
    EnsureDefaultModel(*profile);
    RefreshModelsTable();
    models_->selectRow(models_->rowCount() - 1);
  });
  QT::QObject::connect(remove_model_, &QT::QPushButton::clicked, &dialog_, [this]()
  {
    ProviderProfileDraft *profile = CurrentProfile();
    const int row = models_->currentRow();
    if ( profile == nullptr
        || row < 0
        || static_cast<std::size_t>(row) >= profile->models.size() )
      return;
    profile->models.erase(profile->models.begin() + row);
    EnsureDefaultModel(*profile);
    RefreshModelsTable();
  });
  QT::QObject::connect(edit_model_, &QT::QPushButton::clicked, &dialog_, [this]()
  {
    EditSelectedModelMetadata(models_->currentRow());
  });
  QT::QObject::connect(set_default_model_, &QT::QPushButton::clicked, &dialog_, [this]()
  {
    SetSelectedModelDefault(models_->currentRow(), false);
  });
  QT::QObject::connect(
      models_, &QT::QTableWidget::itemChanged, &dialog_, [this](QT::QTableWidgetItem *item)
      {
        HandleModelItemChanged(item);
      });
  QT::QObject::connect(
      models_, &QT::QTableWidget::itemSelectionChanged, &dialog_, [this]()
      {
        UpdateModelActions();
      });
  QT::QObject::connect(
      models_, &QT::QTableWidget::cellDoubleClicked, &dialog_, [this](int row, int column)
      {
        if ( column == CapabilitiesColumn
            || column == ContextColumn
            || column == MaxOutputColumn )
          return;
        SetSelectedModelDefault(row, true);
      });
  models_->setContextMenuPolicy(QT::Qt::CustomContextMenu);
  QT::QObject::connect(
      models_, &QT::QTableWidget::customContextMenuRequested, &dialog_, [this](const QT::QPoint &position)
      {
        QT::QTableWidgetItem *item = models_->itemAt(position);
        if ( item == nullptr || active_request_.has_value() )
          return;
        const int row = item->row();
        models_->setCurrentCell(row, item->column());
        QT::QMenu menu(models_);
        QT::QAction *edit = menu.addAction("Edit Model Metadata...");
        if ( menu.exec(models_->viewport()->mapToGlobal(position)) == edit )
          EditSelectedModelMetadata(row);
      });
  QT::QObject::connect(
      default_model_, &QT::QComboBox::activated, &dialog_, [this](int index)
      {
        if ( !loading_ )
          if ( ProviderProfileDraft *profile = CurrentProfile() )
          {
            profile->settings.model = ToString(default_model_->itemData(index).toString());
            RefreshModelsTable();
          }
      });
}

} // namespace ida_agent::ai::provider_settings
