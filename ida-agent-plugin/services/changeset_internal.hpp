#pragma once
#include "changeset_service.hpp"
#include <hexrays.hpp>
#include <funcs.hpp>
namespace ida_agent::services
{
struct LocalState
{
  std::uint64_t entry;
  lvar_locator_t locator;
  bool saved_exists;
  lvar_saved_info_t saved;
  std::string current_name;
  std::string current_declaration;
  bool has_user_name;
  bool has_user_type;
};
struct LocalSnapshot { LocalState before; LocalState after; };

namespace changeset_detail
{
inline constexpr uint64 ManagedFunctionFlags = FUNC_NORET | FUNC_LIB | FUNC_STATICDEF | FUNC_HIDDEN | FUNC_THUNK;
bool LocalKind(ChangeKind kind);
std::optional<int> SegmentPermissions(std::string_view value);
std::string SegmentPermissions(int permissions);
std::optional<uint64> FunctionFlags(std::string_view value);
std::string FunctionFlags(uint64 flags);
std::optional<unsigned char> XrefType(std::string_view value, bool code);
std::string XrefState(ea_t from, ea_t to, unsigned char type, bool code);
std::optional<std::pair<ea_t, ea_t>> FunctionChunkRange(const ChangeOperation &operation);
std::optional<std::string> FunctionChunkState(ea_t owner, ea_t start, ea_t end);
bool SameLocalState(const LocalState &left, const LocalState &right);
std::optional<LocalState> CaptureLocal(std::uint64_t address,
    const std::optional<std::string_view> &subject, const lvar_locator_t *expected_locator = nullptr);
bool ApplyLocal(const ChangeOperation &operation, const std::string &after, LocalSnapshot *snapshot);
bool RestoreLocal(const LocalState &expected, const LocalState &target, ChangeKind kind);
std::string Hex(const std::vector<unsigned char> &bytes);
std::optional<std::vector<unsigned char>> DecodeHex(std::string_view value);
const char *Kind(ChangeKind kind);
std::optional<std::string> Current(const ChangeOperation &operation);
std::optional<std::string> After(const ChangeOperation &operation, const std::string &before);
}
}
