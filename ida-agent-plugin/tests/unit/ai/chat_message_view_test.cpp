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
    TestDeferredFocusLayout();
    TestTableUpdates();
    std::printf("PASS: table selection and focus/update regression (Qt %s)\n", QT::qVersion());
    return 0;
  }
  catch ( const std::exception &error )
  {
    std::fprintf(stderr, "%s\n", error.what());
    return 1;
  }
}
