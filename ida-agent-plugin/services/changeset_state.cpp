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
bool LocalKind(ChangeKind kind)
{
  return kind == ChangeKind::LocalRename || kind == ChangeKind::LocalType;
}

std::optional<int> SegmentPermissions(std::string_view value)
{
  if ( value.size() != 3 || (value[0] != 'r' && value[0] != '-')
    || (value[1] != 'w' && value[1] != '-') || (value[2] != 'x' && value[2] != '-') )
    return std::nullopt;
  int permissions = 0;
  if ( value[0] == 'r' ) permissions |= SEGPERM_READ;
  if ( value[1] == 'w' ) permissions |= SEGPERM_WRITE;
  if ( value[2] == 'x' ) permissions |= SEGPERM_EXEC;
  return permissions;
}

std::string SegmentPermissions(int permissions)
{
  std::string result = "---";
  if ( (permissions & SEGPERM_READ) != 0 ) result[0] = 'r';
  if ( (permissions & SEGPERM_WRITE) != 0 ) result[1] = 'w';
  if ( (permissions & SEGPERM_EXEC) != 0 ) result[2] = 'x';
  return result;
}


std::optional<uint64> FunctionFlags(std::string_view value)
{
  uint64 flags = 0;
  while ( !value.empty() )
  {
    const std::size_t separator = value.find(',');
    const std::string_view item = value.substr(0, separator);
    uint64 flag = 0;
    if ( item == "noreturn" ) flag = FUNC_NORET;
    else if ( item == "library" ) flag = FUNC_LIB;
    else if ( item == "static" ) flag = FUNC_STATICDEF;
    else if ( item == "hidden" ) flag = FUNC_HIDDEN;
    else if ( item == "thunk" ) flag = FUNC_THUNK;
    else return std::nullopt;
    if ( (flags & flag) != 0 ) return std::nullopt;
    flags |= flag;
    if ( separator == std::string_view::npos ) break;
    value.remove_prefix(separator + 1);
    if ( value.empty() ) return std::nullopt;
  }
  return flags;
}

std::string FunctionFlags(uint64 flags)
{
  std::string result;
  const std::pair<uint64, const char *> values[] = {
      {FUNC_NORET, "noreturn"}, {FUNC_LIB, "library"}, {FUNC_STATICDEF, "static"},
      {FUNC_HIDDEN, "hidden"}, {FUNC_THUNK, "thunk"},
  };
  for ( const auto &[flag, name] : values )
  {
    if ( (flags & flag) == 0 ) continue;
    if ( !result.empty() ) result.push_back(',');
    result.append(name);
  }
  return result;
}

std::optional<unsigned char> XrefType(std::string_view value, bool code)
{
  if ( code )
  {
    if ( value == "call_far" ) return fl_CF;
    if ( value == "call_near" ) return fl_CN;
    if ( value == "jump_far" ) return fl_JF;
    if ( value == "jump_near" ) return fl_JN;
  }
  else
  {
    if ( value == "offset" ) return dr_O;
    if ( value == "write" ) return dr_W;
    if ( value == "read" ) return dr_R;
    if ( value == "text" ) return dr_T;
    if ( value == "informational" ) return dr_I;
  }
  return std::nullopt;
}

std::string XrefState(ea_t from, ea_t to, unsigned char type, bool code)
{
  xrefblk_t xref;
  for ( bool found = xref.first_from(from, XREF_ALL); found; found = xref.next_from() )
    if ( xref.to == to && xref.iscode == code && (xref.type & XREF_MASK) == type )
      return xref.user ? "user" : "automatic";
  return "absent";
}

std::optional<std::pair<ea_t, ea_t>> FunctionChunkRange(const ChangeOperation &operation)
{
  if ( !operation.subject ) return std::nullopt;
  ea_t start;
  ea_t end;
  try
  {
    start = static_cast<ea_t>(rpc::ParseAddress(operation.value));
    end = static_cast<ea_t>(rpc::ParseAddress(*operation.subject));
  }
  catch ( const std::invalid_argument & )
  {
    return std::nullopt;
  }
  if ( start == BADADDR || end == BADADDR || start >= end || end - start > 16 * 1024 * 1024
    || !is_mapped(start) || !is_mapped(end - 1) || !is_code_ea(start) )
    return std::nullopt;
  return std::pair<ea_t, ea_t>{start, end};
}

std::optional<std::string> FunctionChunkState(ea_t owner, ea_t start, ea_t end)
{
  if ( !is_function_entry(owner) ) return std::nullopt;
  function_tail_iterator_t iterator(owner);
  range_t chunk;
  for ( bool found = iterator.first(); found; found = iterator.next() )
  {
    iterator.chunk(&chunk);
    if ( chunk.start_ea != start ) continue;
    if ( chunk.end_ea != end ) return std::string("conflict");
    fchunk_info_t info;
    if ( !get_fchunk_info(&info, start) ) return std::nullopt;
    if ( (info.get_flags() & FUNC_HIDDEN) != 0 ) return std::string("hidden");
    eavec_t referers;
    if ( !get_tail_referers(&referers, start) ) return std::nullopt;
    if ( referers.size() <= 1 ) return std::string("owned");
    return get_tail_owner(start) == owner ? std::optional<std::string>("owned_shared_owner")
                                          : std::optional<std::string>("owned_shared");
  }
  fchunk_info_t existing;
  if ( get_fchunk_info(&existing, start) )
  {
    if ( existing.start_ea != start || existing.end_ea != end || existing.is_entry() )
      return std::string("conflict");
    if ( (existing.get_flags() & FUNC_HIDDEN) != 0 ) return std::string("hidden");
    return std::string("absent_shared");
  }
  return std::string("absent");
}

std::string Hex(const std::vector<unsigned char> &bytes)
{
  std::ostringstream output; output << std::hex << std::setfill('0');
  for ( unsigned char value : bytes ) output << std::setw(2) << static_cast<unsigned>(value);
  return output.str();
}

std::optional<std::vector<unsigned char>> DecodeHex(std::string_view value)
{
  if ( value.empty() || value.size() % 2 != 0 || value.size() > 131072 ) return std::nullopt;
  std::vector<unsigned char> bytes; bytes.reserve(value.size() / 2);
  for ( std::size_t index = 0; index < value.size(); index += 2 )
  {
    unsigned parsed = 0; std::istringstream input(std::string(value.substr(index, 2))); input >> std::hex >> parsed;
    if ( input.fail() || !input.eof() ) return std::nullopt;
    bytes.push_back(static_cast<unsigned char>(parsed));
  }
  return bytes;
}

const char *Kind(ChangeKind kind)
{
  switch ( kind )
  {
    case ChangeKind::Rename: return "rename";
    case ChangeKind::CommentSet: return "comment.set";
    case ChangeKind::CommentAppend: return "comment.append";
    case ChangeKind::PseudocodeComment: return "comment.pseudocode";
    case ChangeKind::Bookmark: return "bookmark.add";
    case ChangeKind::TypeApply: return "type.apply";
    case ChangeKind::PatchBytes: return "patch.bytes";
    case ChangeKind::PatchInteger: return "patch.integer";
    case ChangeKind::DefineFunction: return "define.function";
    case ChangeKind::DefineCode: return "define.code";
    case ChangeKind::Undefine: return "undefine";
    case ChangeKind::ForceRecompile: return "decompiler.invalidate";
    case ChangeKind::MakeData: return "define.data";
    case ChangeKind::OperandHex: return "operand.hex";
    case ChangeKind::OperandDec: return "operand.decimal";
    case ChangeKind::OperandChar: return "operand.character";
    case ChangeKind::OperandBinary: return "operand.binary";
    case ChangeKind::OperandOctal: return "operand.octal";
    case ChangeKind::OperandOffset: return "operand.offset";
    case ChangeKind::OperandStructOffset: return "operand.struct_offset";
    case ChangeKind::OperandStackVariable: return "operand.stack_variable";
    case ChangeKind::DeclareType: return "type.declare";
    case ChangeKind::EnumUpsert: return "enum.upsert";
    case ChangeKind::InvalidateAllDecompilations: return "decompiler.invalidate_all";
    case ChangeKind::StackDeclare: return "stack.declare";
    case ChangeKind::StackDelete: return "stack.delete";
    case ChangeKind::LocalRename: return "local.rename";
    case ChangeKind::LocalType: return "local.type";
    case ChangeKind::SegmentRename: return "segment.rename";
    case ChangeKind::SegmentPermissions: return "segment.permissions";
    case ChangeKind::XrefCodeAdd: return "xref.code.add";
    case ChangeKind::XrefCodeDelete: return "xref.code.delete";
    case ChangeKind::XrefDataAdd: return "xref.data.add";
    case ChangeKind::XrefDataDelete: return "xref.data.delete";
    case ChangeKind::FunctionFlags: return "function.flags";
    case ChangeKind::FunctionEnd: return "function.end";
    case ChangeKind::FunctionChunkAdd: return "function.chunk.add";
    case ChangeKind::FunctionChunkDelete: return "function.chunk.delete";
  }
  return "unknown";
}

std::optional<std::string> Current(const ChangeOperation &operation)
{
  if ( operation.kind == ChangeKind::DeclareType || operation.kind == ChangeKind::EnumUpsert )
    return detail::CurrentTypeDeclaration(operation.kind, operation.value);
  if ( operation.kind == ChangeKind::InvalidateAllDecompilations ) return std::string("cached");
  const ea_t ea = static_cast<ea_t>(operation.address);
  if ( static_cast<std::uint64_t>(ea) != operation.address || ea == BADADDR || !is_mapped(ea) ) return std::nullopt;
  qstring text;
  switch ( operation.kind )
  {
    case ChangeKind::Rename:
      get_name(&text, ea); return std::string(text.c_str(), text.length());
    case ChangeKind::CommentSet:
    case ChangeKind::CommentAppend:
      get_cmt(&text, ea, operation.repeatable); return std::string(text.c_str(), text.length());
    case ChangeKind::PseudocodeComment:
      return detail::CurrentPseudocodeComment(operation.address);
    case ChangeKind::Bookmark:
      return detail::CurrentBookmark(operation.address);
    case ChangeKind::TypeApply:
    {
      tinfo_t type; if ( !get_tinfo(&type, ea) ) return std::string{};
      if ( !type.print(&text, nullptr, PRTYPE_1LINE | PRTYPE_SEMI) ) return std::string{};
      return std::string(text.c_str(), text.length());
    }
    case ChangeKind::PatchBytes:
    {
      const auto bytes = DecodeHex(operation.value); if ( !bytes ) return std::nullopt;
      std::vector<unsigned char> current(bytes->size());
      if ( get_bytes(current.data(), current.size(), ea) != static_cast<ssize_t>(current.size()) ) return std::nullopt;
      return Hex(current);
    }
    case ChangeKind::PatchInteger:
    {
      if ( !operation.subject ) return std::nullopt;
      const auto bytes = detail::EncodeInteger(operation.value, *operation.subject); if ( !bytes ) return std::nullopt;
      std::vector<unsigned char> current(bytes->size());
      if ( get_bytes(current.data(), current.size(), ea) != static_cast<ssize_t>(current.size()) ) return std::nullopt;
      return Hex(current);
    }
    case ChangeKind::DefineFunction:
      return get_func_start(ea) == ea ? "function" : "undefined";
    case ChangeKind::DefineCode:
      return is_code_ea(ea) ? "code" : "undefined";
    case ChangeKind::Undefine:
    case ChangeKind::MakeData:
      return is_head_ea(ea) ? "defined" : "undefined";
    case ChangeKind::ForceRecompile:
      return "cached";
    case ChangeKind::OperandHex:
    case ChangeKind::OperandDec:
    case ChangeKind::OperandChar:
    case ChangeKind::OperandBinary:
    case ChangeKind::OperandOctal:
    case ChangeKind::OperandOffset:
    case ChangeKind::OperandStructOffset:
    case ChangeKind::OperandStackVariable:
      return detail::CurrentOperandState(operation);
    case ChangeKind::DeclareType:
    case ChangeKind::EnumUpsert:
    case ChangeKind::InvalidateAllDecompilations:
      break;
    case ChangeKind::StackDeclare:
    case ChangeKind::StackDelete:
    {
      if ( !operation.offset || *operation.offset < 0 ) return std::nullopt;
      tinfo_t frame;
      if ( !get_func_frame_ea(&frame, ea) ) return std::string("absent");
      return frame.find_udm(static_cast<std::uint64_t>(*operation.offset) * 8, STRMEM_OFFSET) >= 0
          ? std::optional<std::string>("present")
          : std::optional<std::string>("absent");
    }
    case ChangeKind::LocalRename:
    {
      if ( !operation.subject ) return std::nullopt;
      const auto state = CaptureLocal(operation.address, std::string_view(*operation.subject));
      return state ? std::optional<std::string>(state->current_name) : std::nullopt;
    }
    case ChangeKind::LocalType:
    {
      if ( !operation.subject ) return std::nullopt;
      const auto state = CaptureLocal(operation.address, std::string_view(*operation.subject));
      if ( !state ) return std::nullopt;
      return state->current_declaration;
    }
    case ChangeKind::SegmentRename:
    {
      segment_t *segment = getseg(ea); if ( segment == nullptr ) return std::nullopt;
      if ( get_segm_name(&text, segment) <= 0 ) return std::nullopt;
      return std::string(text.c_str(), text.length());
    }
    case ChangeKind::SegmentPermissions:
    {
      segment_t *segment = getseg(ea); if ( segment == nullptr ) return std::nullopt;
      return SegmentPermissions(segment->perm);
    }
    case ChangeKind::FunctionFlags:
    {
      func_t *function = get_func(ea); if ( function == nullptr ) return std::nullopt;
      return FunctionFlags(function->flags & ManagedFunctionFlags);
    }
    case ChangeKind::FunctionEnd:
    {
      if ( !is_function_entry(ea) ) return std::nullopt;
      fchunk_info_t entry;
      if ( !get_fchunk_info(&entry, ea) || !entry.is_entry() ) return std::nullopt;
      return rpc::FormatAddress(entry.end_ea);
    }
    case ChangeKind::FunctionChunkAdd:
    case ChangeKind::FunctionChunkDelete:
    {
      const auto range = FunctionChunkRange(operation);
      if ( !range ) return std::nullopt;
      return FunctionChunkState(ea, range->first, range->second);
    }
    case ChangeKind::XrefCodeAdd:
    case ChangeKind::XrefCodeDelete:
    case ChangeKind::XrefDataAdd:
    case ChangeKind::XrefDataDelete:
    {
      if ( !operation.subject ) return std::nullopt;
      ea_t target;
      try { target = static_cast<ea_t>(rpc::ParseAddress(operation.value)); }
      catch ( const std::invalid_argument & ) { return std::nullopt; }
      if ( target == BADADDR || !is_mapped(target) ) return std::nullopt;
      const bool code = operation.kind == ChangeKind::XrefCodeAdd || operation.kind == ChangeKind::XrefCodeDelete;
      const bool add = operation.kind == ChangeKind::XrefCodeAdd || operation.kind == ChangeKind::XrefDataAdd;
      const auto type = XrefType(*operation.subject, code); if ( !type ) return std::nullopt;
      if ( code && (!is_code_ea(ea) || !is_code_ea(target)) ) return std::nullopt;
      if ( code && add && (*type == fl_CF || *type == fl_CN) && get_func(target) == nullptr ) return std::nullopt;
      return XrefState(ea, target, *type, code);
    }
  }
  return std::nullopt;
}

std::optional<std::string> After(const ChangeOperation &operation, const std::string &before)
{
  if ( operation.value.size() > 65536 || operation.value.find('\0') != std::string::npos
    || !is_valid_utf8(operation.value.c_str()) ) return std::nullopt;
  if ( operation.kind == ChangeKind::InvalidateAllDecompilations ) return std::string("invalidated");
  if ( operation.kind == ChangeKind::EnumUpsert ) return detail::DesiredTypeDeclaration(operation.kind, operation.value);
  if ( operation.kind == ChangeKind::CommentAppend )
    return before.empty() ? operation.value : before + "\n" + operation.value;
  if ( operation.kind == ChangeKind::PatchBytes )
  {
    const auto bytes = DecodeHex(operation.value);
    return bytes ? std::optional<std::string>(Hex(*bytes)) : std::nullopt;
  }
  if ( operation.kind == ChangeKind::PatchInteger )
  {
    if ( !operation.subject ) return std::nullopt;
    const auto encoded = detail::EncodeInteger(operation.value, *operation.subject);
    if ( !encoded ) return std::nullopt;
    return Hex(*encoded);
  }
  if ( operation.kind == ChangeKind::OperandHex || operation.kind == ChangeKind::OperandDec
    || operation.kind == ChangeKind::OperandChar || operation.kind == ChangeKind::OperandBinary
    || operation.kind == ChangeKind::OperandOctal || operation.kind == ChangeKind::OperandOffset
    || operation.kind == ChangeKind::OperandStructOffset || operation.kind == ChangeKind::OperandStackVariable )
    return detail::DesiredOperandState(operation);
  if ( operation.kind == ChangeKind::SegmentPermissions )
    return SegmentPermissions(operation.value) ? std::optional<std::string>(operation.value) : std::nullopt;
  if ( operation.kind == ChangeKind::FunctionFlags )
  {
    const auto flags = FunctionFlags(operation.value);
    return flags ? std::optional<std::string>(FunctionFlags(*flags)) : std::nullopt;
  }
  if ( operation.kind == ChangeKind::XrefCodeAdd || operation.kind == ChangeKind::XrefDataAdd )
    return before == "absent" ? std::optional<std::string>("user") : std::nullopt;
  if ( operation.kind == ChangeKind::XrefCodeDelete || operation.kind == ChangeKind::XrefDataDelete )
    return before == "user" ? std::optional<std::string>("absent") : std::nullopt;
  if ( operation.kind == ChangeKind::SegmentRename )
    return !operation.value.empty() && operation.value.size() <= 255 ? std::optional<std::string>(operation.value) : std::nullopt;
  if ( operation.kind == ChangeKind::FunctionEnd )
  {
    ea_t target;
    try { target = static_cast<ea_t>(rpc::ParseAddress(operation.value)); }
    catch ( const std::invalid_argument & ) { return std::nullopt; }
    fchunk_info_t entry;
    if ( target == BADADDR || !is_function_entry(operation.address) || !get_fchunk_info(&entry, operation.address)
      || !entry.is_entry() || target <= entry.start_ea || target - entry.start_ea > 16 * 1024 * 1024
      || !is_mapped(target - 1) || getseg(entry.start_ea) != getseg(target - 1) ) return std::nullopt;
    return rpc::FormatAddress(target);
  }
  if ( operation.kind == ChangeKind::FunctionChunkAdd )
    return before == "absent" ? std::optional<std::string>("owned")
        : before == "absent_shared" ? std::optional<std::string>("owned_shared") : std::nullopt;
  if ( operation.kind == ChangeKind::FunctionChunkDelete )
    return before == "owned_shared" ? std::optional<std::string>("absent_shared") : std::nullopt;
  return operation.value;
}

}
