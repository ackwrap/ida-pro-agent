#include "changeset_service.hpp"
#include "changeset_annotations.hpp"
#include "changeset_integer.hpp"
#include "changeset_operands.hpp"
#include "changeset_types.hpp"

#include "address.hpp"

#include <bytes.hpp>
#include <funcs.hpp>
#include <frame.hpp>
#include <hexrays.hpp>
#include <kernwin.hpp>
#include <name.hpp>
#include <segment.hpp>
#include <typeinf.hpp>
#include <ua.hpp>
#include <xref.hpp>

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <sstream>

#include "changeset_internal.hpp"

namespace ida_agent::services::changeset_detail
{
bool SameSavedInfo(const lvar_saved_info_t &left, const lvar_saved_info_t &right)
{
  return left.ll == right.ll && left.name == right.name && left.type == right.type
      && left.cmt == right.cmt && left.size == right.size && left.flags == right.flags;
}

bool SameLocalState(const LocalState &left, const LocalState &right)
{
  return left.entry == right.entry && left.locator == right.locator
      && left.saved_exists == right.saved_exists
      && (!left.saved_exists || SameSavedInfo(left.saved, right.saved))
      && left.current_name == right.current_name && left.current_declaration == right.current_declaration
      && left.has_user_name == right.has_user_name && left.has_user_type == right.has_user_type;
}

std::optional<LocalState> CaptureLocal(
    std::uint64_t address,
    const std::optional<std::string_view> &subject,
    const lvar_locator_t *expected_locator)
{
  const ea_t ea = static_cast<ea_t>(address);
  if ( static_cast<std::uint64_t>(ea) != address || ea == BADADDR || !is_mapped(ea) ) return std::nullopt;
  const ea_t entry = get_func_start(ea);
  if ( entry == BADADDR ) return std::nullopt;
  cfuncptr_t function(nullptr);
  try
  {
    function = decompile_function(entry, nullptr, DECOMP_NO_WAIT | DECOMP_GXREFS_NOUPD);
  }
  catch ( const vd_failure_t & ) { return std::nullopt; }
  if ( function == nullptr || function->get_lvars() == nullptr ) return std::nullopt;
  lvar_t *variable = nullptr;
  if ( expected_locator != nullptr )
  {
    variable = function->get_lvars()->find(*expected_locator);
  }
  else if ( subject )
  {
    for ( lvar_t &candidate : *function->get_lvars() )
    {
      if ( std::string_view(candidate.name.c_str(), candidate.name.length()) == *subject )
      {
        if ( variable != nullptr ) return std::nullopt;
        variable = &candidate;
      }
    }
  }
  if ( variable == nullptr ) return std::nullopt;
  LocalState state;
  state.entry = static_cast<std::uint64_t>(entry);
  state.locator = static_cast<const lvar_locator_t &>(*variable);
  state.saved_exists = false;
  state.current_name.assign(variable->name.c_str(), variable->name.length());
  qstring declaration;
  if ( !variable->type().print(&declaration, variable->name.c_str(), PRTYPE_1LINE | PRTYPE_SEMI) )
    return std::nullopt;
  state.current_declaration.assign(declaration.c_str(), declaration.length());
  state.has_user_name = variable->has_user_name();
  state.has_user_type = variable->has_user_type();
  lvar_uservec_t settings;
  const bool restored = restore_user_lvar_settings(&settings, entry);
  if ( !restored && variable->has_user_info() ) return std::nullopt;
  if ( restored )
  {
    if ( lvar_saved_info_t *saved = settings.find_info(state.locator) )
    {
      state.saved_exists = true;
      state.saved = *saved;
    }
  }
  return state;
}

bool SavedInfoNeeded(const lvar_saved_info_t &info)
{
  return !info.name.empty() || !info.type.empty() || !info.cmt.empty() || info.flags != 0;
}

bool WriteLocalAttribute(const LocalState &state, ChangeKind kind)
{
  const ea_t entry = static_cast<ea_t>(state.entry);
  lvar_saved_info_t info;
  info.ll = state.locator;
  uint flags = 0;
  if ( kind == ChangeKind::LocalRename )
  {
    if ( state.saved_exists ) info.name = state.saved.name;
    flags = MLI_NAME;
  }
  else
  {
    if ( state.saved_exists )
    {
      info.type = state.saved.type;
      info.size = state.saved.size;
    }
    flags = MLI_TYPE;
  }
  if ( !modify_user_lvar_info(entry, flags, info) ) return false;
  static_cast<void>(mark_cfunc_dirty(entry, false));
  return true;
}

bool ApplyLocal(
    const ChangeOperation &operation,
    const std::string &after,
    LocalSnapshot *snapshot)
{
  if ( !operation.subject || snapshot == nullptr ) return false;
  const auto before = CaptureLocal(operation.address, std::string_view(*operation.subject));
  if ( !before ) return false;
  LocalState desired = *before;
  desired.saved_exists = true;
  if ( !before->saved_exists )
  {
    lvar_saved_info_t empty;
    desired.saved = empty;
    desired.saved.ll = before->locator;
  }
  if ( operation.kind == ChangeKind::LocalRename )
  {
    desired.saved.name = after.c_str();
  }
  else
  {
    if ( after.empty() )
    {
      desired.saved.type.clear();
      desired.saved.size = BADSIZE;
    }
    else
    {
      tinfo_t type;
      if ( !type.parse(after.c_str(), nullptr, PT_SIL) || type.empty() ) return false;
      desired.saved.type = type;
      desired.saved.size = type.get_size();
    }
  }
  desired.saved_exists = SavedInfoNeeded(desired.saved);
  if ( !WriteLocalAttribute(desired, operation.kind) ) return false;
  const auto applied = CaptureLocal(desired.entry, std::nullopt, &desired.locator);
  bool matches = applied.has_value();
  if ( matches && operation.kind == ChangeKind::LocalRename )
    matches = after.empty() ? !applied->has_user_name : applied->has_user_name && applied->current_name == after;
  if ( matches && operation.kind == ChangeKind::LocalType )
    matches = after.empty() ? !applied->has_user_type
        : applied->has_user_type;
  if ( matches )
    matches = applied->saved_exists == desired.saved_exists && (!desired.saved_exists
        || applied->saved.ll == desired.saved.ll
        && applied->saved.name == desired.saved.name
        && applied->saved.type == desired.saved.type
        && applied->saved.cmt == desired.saved.cmt
        && applied->saved.flags == desired.saved.flags);
  if ( !matches )
  {
    static_cast<void>(WriteLocalAttribute(*before, operation.kind));
    return false;
  }
  snapshot->before = *before;
  snapshot->after = *applied;
  return true;
}

bool RestoreLocal(const LocalState &expected, const LocalState &target, ChangeKind kind)
{
  const auto current = CaptureLocal(expected.entry, std::nullopt, &expected.locator);
  if ( !current || !SameLocalState(*current, expected) ) return false;
  if ( !WriteLocalAttribute(target, kind) ) return false;
  const auto restored = CaptureLocal(target.entry, std::nullopt, &target.locator);
  return restored && SameLocalState(*restored, target);
}

}
