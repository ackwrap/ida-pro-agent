#include "ai/chat_message_view.hpp"
#include <cstdio>
#include <stdexcept>

using ida_agent::ai::ChatEntry;
using ida_agent::ai::ChatMessageView;
using ida_agent::ai::ChatSpeaker;

namespace
{
const std::string Markdown =
    "Before table\n\n| Name | Value |\n| --- | --- |\n"
    "| alpha | 123 |\n| beta | 456 |\n\nAfter table\n";

void Require(bool condition, const char *message)
{
  if ( !condition )
    throw std::runtime_error(message);
}

void CheckTableLayout(QT::QTextFrame *frame, ChatMessageView &view, int &tables)
{
  for (auto *child : frame->childFrames())
  {
    if (auto *table = QT::qobject_cast<QT::QTextTable *>(child))
    {
      ++tables;
      for (int row = 0; row < table->rows(); ++row)
        for (int column = 0; column < table->columns(); ++column)
        {
          const auto block = table->cellAt(row, column).firstCursorPosition().block();
          // Check before asking for cell geometry: Qt 6.8.2 dereferences empty
          // table coordinate arrays when highlighting interrupted insertion.
          Require(block.layout()->lineCount() > 0, "table cells were not laid out after highlighting");
          const auto bounds = view.document()->documentLayout()->blockBoundingRect(block);
          Require(bounds.isValid(), "table cell has no visible bounds");
        }
      auto cursor = table->cellAt(0, 0).firstCursorPosition();
      view.setTextCursor(cursor);
      view.ensureCursorVisible();
      const auto point = view.cursorRect(cursor).center() + QT::QPoint(2, 0);
      Require(view.cursorForPosition(point).currentTable() == table,
          "visible table cannot be hit tested");
      for (const auto type : {QT::QEvent::MouseButtonPress, QT::QEvent::MouseButtonRelease,
          QT::QEvent::MouseButtonDblClick, QT::QEvent::MouseButtonRelease})
      {
        const bool release = type == QT::QEvent::MouseButtonRelease;
        QT::QMouseEvent event(type, QT::QPointF(point),
            QT::QPointF(view.viewport()->mapToGlobal(point)), QT::Qt::LeftButton,
            release ? QT::Qt::NoButton : QT::Qt::LeftButton, QT::Qt::NoModifier);
        QT::QApplication::sendEvent(view.viewport(), &event);
      }
      QT::QInputMethodQueryEvent query(QT::Qt::ImCursorRectangle | QT::Qt::ImAnchorRectangle);
      QT::QApplication::sendEvent(&view, &query);
      Require(query.value(QT::Qt::ImCursorRectangle).isValid(),
          "table cursor input-method query failed");
      Require(view.CopyMessageAt(cursor).contains("Name"), "table lost original copy text");
    }
    CheckTableLayout(child, view, tables);
  }
}

void CheckHighlightedTables(ChatMessageView &view, int expected)
{
  view.document()->documentLayout()->documentSize();
  int tables = 0;
  CheckTableLayout(view.document()->rootFrame(), view, tables);
  Require(tables == expected, "highlighting changed the number of tables");
  int highlighted = 0;
  for (auto block = view.document()->begin(); block.isValid(); block = block.next())
    if (block.text().contains("int answer"))
    {
      Require(!block.layout()->formats().isEmpty(), "code syntax colors were lost");
      Require(view.CopyCodeAt(QT::QTextCursor(block)).contains("return answer;"),
          "syntax highlighting changed code copying");
      ++highlighted;
    }
  Require(highlighted > 0, "highlighted code block missing");
}

void TestHighlightedTables()
{
  const std::string table = "| Name | Value |\n| --- | --- |\n| alpha | `123` |\n| beta | 456 |\n\n";
  const std::string code = "```cpp\nint answer = 42;\nreturn answer;\n```\n\n";
  // A plain table does not expose this bug. A fenced code block in the same
  // message used to invalidate newly inserted tables before the edit ended.
  const std::vector<std::string> fixtures{table + code, code + table, table + code + table};
  for (std::size_t index = 0; index < fixtures.size(); ++index)
  {
    ChatMessageView view(nullptr);
    view.setAttribute(QT::Qt::WA_DontShowOnScreen);
    view.resize(650, 450);
    view.show();
    QT::QApplication::processEvents();
    const int expected = index == 2 ? 2 : 1;
    view.ResetMessages({{ChatSpeaker::Assistant, fixtures[index]}});
    CheckHighlightedTables(view, expected);
    view.ResetMessages({});
    view.BeginPreview(ChatSpeaker::Assistant);
    const auto &text = fixtures[index];
    for (std::size_t end = 10; end < text.size(); end += 10)
      view.FlushPreviews("", std::string_view(text).substr(0, end));
    view.FlushPreviews("", text);
    view.CommitPreview(ChatSpeaker::Assistant, {ChatSpeaker::Assistant, text}, 0);
    CheckHighlightedTables(view, expected);
    for (bool dark : {true, false})
    {
      auto colors = view.palette();
      colors.setColor(QT::QPalette::Base, dark ? QT::QColor("#202020") : QT::QColor("#ffffff"));
      colors.setColor(QT::QPalette::Text, dark ? QT::QColor("#eeeeee") : QT::QColor("#101010"));
      view.setPalette(colors);
      view.resize(dark ? 240 : 650, 450);
      QT::QApplication::processEvents();
      CheckHighlightedTables(view, expected);
    }
    view.AppendMessage({ChatSpeaker::Assistant, text}, 0);
    CheckHighlightedTables(view, expected * 2);
    view.AppendMessage({ChatSpeaker::Assistant, text}, 2);
    CheckHighlightedTables(view, expected);
  }
}

void Focus(ChatMessageView &view, QT::QEvent::Type type)
{
  QT::QFocusEvent event(type, QT::Qt::OtherFocusReason);
  QT::QApplication::sendEvent(&view, &event);
}

QT::QTextTable *Table(ChatMessageView &view)
{
  for ( auto *message : view.document()->rootFrame()->childFrames() )
    for ( auto *child : message->childFrames() )
      if ( auto *table = QT::qobject_cast<QT::QTextTable *>(child) )
        return table;
  throw std::runtime_error("Markdown table missing");
}

void SelectTable(ChatMessageView &view, int kind)
{
  auto *table = Table(view);
  auto cursor = table->cellAt(0, 0).firstCursorPosition();
  if ( kind == 3 )
    cursor.setPosition(table->firstPosition() - 1);
  const int start = cursor.position();
  const int end = kind == 3 ? table->lastPosition() + 1
      : table->cellAt(kind == 0 ? 0 : table->rows() - 1,
          kind == 0 ? 0 : table->columns() - 1).lastCursorPosition().position();
  if ( kind == 2 )
  {
    cursor.setPosition(end);
    cursor.setPosition(start, QT::QTextCursor::KeepAnchor);
  }
  else if ( kind != 4 )
    cursor.setPosition(end, QT::QTextCursor::KeepAnchor);
  view.setTextCursor(cursor);
  if ( kind == 1 || kind == 2 )
    Require(view.textCursor().hasComplexSelection(), "cross-cell selection missing");
}

// Model the dump's precondition: cell geometry is unavailable until a complete
// document layout. Fail safely instead of dereferencing Qt's empty cell arrays.
class DeferredLayout final : public QT::QAbstractTextDocumentLayout
{
public:
  explicit DeferredLayout(QT::QTextDocument *document)
      : QT::QAbstractTextDocumentLayout(document) {}
  void draw(QT::QPainter *, const PaintContext &) override {}
  int hitTest(const QT::QPointF &, QT::Qt::HitTestAccuracy) const override { return 0; }
  int pageCount() const override { return 1; }
  QT::QSizeF documentSize() const override
  {
    pending = false;
    return {580, 400};
  }
  QT::QRectF frameBoundingRect(QT::QTextFrame *) const override
  {
    documentSize();
    return {0, 0, 580, 400};
  }
  QT::QRectF blockBoundingRect(const QT::QTextBlock &) const override
  {
    ++geometry_queries;
    unsafe_query |= pending;
    return {0, 0, 100, 20};
  }
  mutable bool pending = false;
  mutable bool unsafe_query = false;
  mutable int geometry_queries = 0;

protected:
  void documentChanged(int, int, int) override { pending = true; }
};

void TestDeferredFocusLayout()
{
  QT::QWidget parent;
  ChatMessageView view(&parent);
  view.resize(600, 400);
  for ( int kind = 0; kind != 5; ++kind )
  {
    view.ResetMessages({{ChatSpeaker::Assistant, Markdown}});
    SelectTable(view, kind);
    auto *layout = new DeferredLayout(view.document());
    view.document()->setDocumentLayout(layout);
    Focus(view, QT::QEvent::FocusIn);
    const auto selected = view.textCursor();
    layout->pending = true;
    layout->unsafe_query = false;
    layout->geometry_queries = 0;
    Focus(view, QT::QEvent::FocusOut);
    Require(layout->geometry_queries > 0, "focus-out did not query selection geometry");
    Require(!layout->unsafe_query, "focus-out queried cells before completing layout");
    Require(view.textCursor().position() == selected.position()
        && view.textCursor().anchor() == selected.anchor(), "focus-out changed selection");
    // Restore Qt's real layout before rendering the next case.
    auto *replacement = new QT::QTextDocument(&view);
    view.setDocument(replacement);
  }
}

void CheckFocusSelection(ChatMessageView &view)
{
  Focus(view, QT::QEvent::FocusIn);
  const auto cursor = view.textCursor();
  const auto text = cursor.selectedText();
  Focus(view, QT::QEvent::FocusOut);
  Require(view.textCursor().position() == cursor.position()
      && view.textCursor().anchor() == cursor.anchor()
      && view.textCursor().selectedText() == text, "focus change lost table selection");
}

void TestTableUpdates()
{
  QT::QWidget parent, other;
  ChatMessageView view(&parent);
  view.resize(600, 400);
  for ( int kind = 0; kind != 5; ++kind )
    for ( int cycle = 0; cycle != 5; ++cycle )
    {
      std::vector<ChatEntry> entries(60, {ChatSpeaker::System, std::string(3000, 'x')});
      entries.push_back({ChatSpeaker::Assistant, Markdown});
      view.ResetMessages(entries);
      SelectTable(view, kind);
      const auto selected = view.textCursor().selectedText();
      view.BeginPreview(ChatSpeaker::Assistant);
      view.FlushPreviews("", Markdown);
      view.CommitPreview(ChatSpeaker::Assistant, {ChatSpeaker::Assistant, Markdown}, 1);
      Require(view.textCursor().selectedText() == selected, "reply update lost selection");
      CheckFocusSelection(view);
      view.resize(cycle % 2 == 0 ? 1 : 600, 400);
      CheckFocusSelection(view);
      view.setParent(&other);
      CheckFocusSelection(view);
      view.setParent(&parent);
      // Prune the selected message, then replace the entire history.
      view.AppendMessage({ChatSpeaker::System, "prune selected table"}, entries.size() - 1);
      CheckFocusSelection(view);
      view.ResetMessages({{ChatSpeaker::Assistant, Markdown}});
      SelectTable(view, kind);
      CheckFocusSelection(view);
      QT::QApplication::processEvents();
    }
}
} // namespace

int main(int argc, char **argv)
{
  QT::QApplication app(argc, argv);
  try
  {
    TestHighlightedTables();
    TestDeferredFocusLayout();
    TestTableUpdates();
    std::printf("PASS: highlighted tables, mouse/input queries and focus/update regression (Qt %s)\n", QT::qVersion());
    return 0;
  }
  catch ( const std::exception &error )
  {
    std::fprintf(stderr, "%s\n", error.what());
    return 1;
  }
}
