#include "ai/chat_output_menu.hpp"

#include "ai/chat_output_view.hpp"
#include "ai/jump_target_text.hpp"

#include <bytes.hpp>
#include <ida.hpp>
#include <kernwin.hpp>
#include <name.hpp>

#include <cstdint>
#include <sstream>
#include <string>

namespace ida_agent::ai
{
namespace
{

std::string HexText(std::uint64_t value)
{
  std::ostringstream out;
  out << "0x" << std::hex << value;
  return out.str();
}

ea_t ResolveTarget(const JumpTargetText &candidate) noexcept
{
  if ( candidate.is_address )
  {
    const ea_t target = static_cast<ea_t>(candidate.address);
    return is_mapped(target) ? target : BADADDR;
  }
  if ( candidate.name.empty() )
    return BADADDR;
  const ea_t target = get_name_ea(BADADDR, candidate.name.c_str());
  return target;
}

void JumpInIda(ea_t target) noexcept
{
  if ( target == BADADDR )
    return;
  if ( !jumpto(target, -1, UIJMP_ACTIVATE | UIJMP_IDAVIEW) )
    jumpto(target, -1, UIJMP_ACTIVATE | UIJMP_IDAVIEW_NEW);
}

std::string ActionLabel(const JumpTargetText &candidate)
{
  return candidate.is_address ? HexText(candidate.address) : candidate.name;
}

} // namespace

void AttachChatOutputJumpMenu(ChatMessageView *output)
{
  if ( output == nullptr )
    return;
  output->setContextMenuPolicy(QT::Qt::CustomContextMenu);
  QT::QObject::connect(
      output,
      &QT::QWidget::customContextMenuRequested,
      output,
      [output](const QT::QPoint &pos)
      {
        QT::QMenu *menu = output->createStandardContextMenu();
        const auto under_pointer = output->cursorForPosition(pos);
        const auto message = output->CopyMessageAt(under_pointer);
        const auto code = output->CopyCodeAt(under_pointer);
        if ( !message.isNull() || !code.isNull() )
        {
          menu->addSeparator();
          const auto add_copy = [menu](const char *label, const char *name, const QT::QString &text)
          {
            auto *copy = menu->addAction(QT::QString::fromLatin1(label));
            copy->setObjectName(QT::QString::fromLatin1(name));
            QT::QObject::connect(copy, &QT::QAction::triggered, menu, [text]()
            {
              QT::QApplication::clipboard()->setText(text);
            });
          };
          if ( !code.isNull() )
            add_copy("Copy Code", "idaAgentCopyCode", code);
          if ( !message.isNull() )
            add_copy("Copy Message", "idaAgentCopyMessage", message);
        }

        const std::string selected = output->textCursor().selectedText().toStdString();
        if ( !selected.empty() )
        {
          const auto candidate = ExtractJumpTarget(selected);
          if ( candidate.has_value() )
          {
            const ea_t target = ResolveTarget(*candidate);
            if ( target != BADADDR )
            {
              QT::QAction *jump = new QT::QAction(
                  ToQString("Jump To " + ActionLabel(*candidate)),
                  menu);
              QT::QObject::connect(
                  jump,
                  &QT::QAction::triggered,
                  menu,
                  [target](bool) { JumpInIda(target); });
              QT::QAction *first = menu->actions().isEmpty()
                  ? nullptr
                  : menu->actions().first();
              if ( first == nullptr )
                menu->addAction(jump);
              else
              {
                menu->insertAction(first, jump);
                menu->insertSeparator(first);
              }
            }
          }
        }
        menu->exec(output->viewport()->mapToGlobal(pos));
        delete menu;
      });
}

} // namespace ida_agent::ai
