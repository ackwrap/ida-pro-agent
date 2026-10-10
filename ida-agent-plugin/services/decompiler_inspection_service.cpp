#include "decompiler_inspection_service.hpp"
#include "query_helpers.hpp"
#include "address.hpp"
#include <bytes.hpp>
#include <funcs.hpp>
#include <hexrays.hpp>
#include <algorithm>
#include <limits>

namespace ida_agent::services
{
using namespace query;
namespace
{
constexpr std::uint32_t MaxNameBytes = 4096;
constexpr std::uint32_t MaxTextBytes = 16 * 1024;
constexpr std::uint32_t MaxLocatorBytes = 4096;
QueryStatus ClassifyDecompilerFailure(merror_t code)
{
  if ( code == MERR_BUSY ) return QueryStatus::Busy;
  if ( code == MERR_LICENSE || code == MERR_BADARCH || code == MERR_BITNESS
    || code == MERR_ONLY32 || code == MERR_ONLY64 )
    return QueryStatus::CapabilityUnavailable;
  return QueryStatus::DecompileFailed;
}

nlohmann::json LvarFlags(const lvar_t &variable)
{
  nlohmann::json flags = nlohmann::json::array();
  const auto add = [&flags](bool enabled, const char *name) { if ( enabled ) flags.push_back(name); };
  add(variable.used(), "used");
  add(variable.typed(), "typed");
  add(variable.has_nice_name(), "nice_name");
  add(variable.has_user_name(), "user_name");
  add(variable.has_user_type(), "user_type");
  add(variable.is_result_var(), "result");
  add(variable.is_arg_var(), "argument");
  add(variable.is_fake_var(), "fake");
  add(variable.is_overlapped_var(), "overlapped");
  add(variable.is_partialy_typed(), "partial_type");
  add(variable.is_thisarg(), "this_argument");
  add(variable.is_dummy_arg(), "dummy_argument");
  add(variable.is_used_byref(), "address_taken");
  add(variable.is_shared(), "shared");
  return flags;
}

std::optional<std::string> PrintType(const tinfo_t &type, const char *name)
{
  qstring printed;
  if ( !type.print(&printed, name, PRTYPE_1LINE | PRTYPE_SEMI) )
    return std::nullopt;
  std::string result(printed.c_str(), printed.length());
  if ( !BoundedUtf8(result, MaxTextBytes) )
    return std::nullopt;
  return result;
}

class BoundedCtreeVisitor final : public ctree_visitor_t
{
public:
  BoundedCtreeVisitor(cfunc_t &function, std::uint32_t max_depth, std::uint32_t max_nodes)
      : ctree_visitor_t(CV_PARENTS), function_(function), max_depth_(max_depth), max_nodes_(max_nodes)
  {
  }

  int idaapi visit_insn(cinsn_t *item) override { return Visit(item, nullptr); }
  int idaapi visit_expr(cexpr_t *item) override { return Visit(item, item); }

  nlohmann::json nodes = nlohmann::json::array();
  bool truncated = false;

private:
  int Visit(citem_t *item, cexpr_t *expression)
  {
    if ( nodes.size() >= max_nodes_ )
    {
      truncated = true;
      return 1;
    }
    const std::uint32_t depth = static_cast<std::uint32_t>(parents.size());
    const char *operation = get_ctype_name(item->op);
    nlohmann::json node{
        {"ordinal", nodes.size()},
        {"depth", depth},
        {"kind", expression == nullptr ? "statement" : "expression"},
        {"op", operation == nullptr ? "unknown" : operation},
        {"ea", item->ea == BADADDR ? nlohmann::json(nullptr) : nlohmann::json(rpc::FormatAddress(item->ea))},
    };
    const int32 user_flags = function_.get_user_iflags(citem_locator_t(item));
    nlohmann::json flags = nlohmann::json::array();
    if ( (user_flags & CIT_COLLAPSED) != 0 ) flags.push_back("collapsed");
    if ( (user_flags & CIT_INVERTED) != 0 ) flags.push_back("inverted");
    if ( (user_flags & CIT_THEN_COLLAPSED) != 0 ) flags.push_back("then_collapsed");
    if ( (user_flags & CIT_ELSE_COLLAPSED) != 0 ) flags.push_back("else_collapsed");
    node["userFlags"] = std::move(flags);
    if ( expression != nullptr )
    {
      const auto type = PrintType(expression->type, nullptr);
      if ( type ) node["type"] = *type;
      if ( expression->op == cot_var )
      {
        const int index = expression->v.idx;
        lvars_t *variables = function_.get_lvars();
        if ( variables != nullptr && index >= 0 && static_cast<std::size_t>(index) < variables->size() )
        {
          node["lvarIndex"] = index;
          const lvar_t &variable = variables->at(index);
          std::string name(variable.name.c_str(), variable.name.length());
          if ( BoundedUtf8(name, MaxNameBytes) ) node["name"] = std::move(name);
        }
      }
    }
    nodes.push_back(std::move(node));
    if ( depth >= max_depth_ )
    {
      prune_now();
      truncated = true;
    }
    return 0;
  }

  cfunc_t &function_;
  std::uint32_t max_depth_;
  std::uint32_t max_nodes_;
};

class BoundedLocalXrefVisitor final : public ctree_visitor_t
{
public:
  BoundedLocalXrefVisitor(
      std::uint32_t local_index,
      std::uint32_t max_depth,
      std::uint32_t max_nodes,
      std::uint32_t max_items)
      : ctree_visitor_t(CV_PARENTS), local_index_(local_index), max_depth_(max_depth),
        max_nodes_(max_nodes), max_items_(max_items)
  {
  }

  int idaapi visit_insn(cinsn_t *item) override { return Visit(item, nullptr); }
  int idaapi visit_expr(cexpr_t *item) override { return Visit(item, item); }

  nlohmann::json items = nlohmann::json::array();
  std::uint32_t visited_nodes = 0;
  bool truncated = false;

private:
  int Visit(citem_t *item, cexpr_t *expression)
  {
    if ( visited_nodes >= max_nodes_ )
    {
      truncated = true;
      return 1;
    }
    ++visited_nodes;
    if ( visited_nodes == max_nodes_ ) truncated = true;
    const std::uint32_t depth = static_cast<std::uint32_t>(parents.size());
    if ( expression != nullptr && expression->op == cot_var
      && expression->v.idx >= 0
      && static_cast<std::uint32_t>(expression->v.idx) == local_index_ )
    {
      if ( items.size() >= max_items_ )
      {
        truncated = true;
        return 1;
      }
      nlohmann::json parent = nullptr;
      if ( !parents.empty() )
      {
        const char *name = get_ctype_name(parents.back()->op);
        parent = name == nullptr ? "unknown" : name;
      }
      nlohmann::json type = nullptr;
      const auto printed = PrintType(expression->type, nullptr);
      if ( printed ) type = *printed;
      items.push_back({
          {"ordinal", items.size()}, {"depth", depth},
          {"ea", item->ea == BADADDR ? nlohmann::json(nullptr) : nlohmann::json(rpc::FormatAddress(item->ea))},
          {"parentOp", std::move(parent)}, {"type", std::move(type)},
      });
      if ( items.size() == max_items_ )
      {
        truncated = true;
        return 1;
      }
    }
    if ( depth >= max_depth_ )
    {
      prune_now();
      truncated = true;
    }
    return visited_nodes == max_nodes_ ? 1 : 0;
  }

  std::uint32_t local_index_;
  std::uint32_t max_depth_;
  std::uint32_t max_nodes_;
  std::uint32_t max_items_;
};
}

QueryResult DecompilerInspectionService::DecompilerLocals(
    std::uint64_t address,
    std::uint32_t max_items) const
{
  if ( !decompiler_available_ ) return {QueryStatus::CapabilityUnavailable, {}};
  ea_t ea = BADADDR;
  if ( !StableAddress(address, &ea) || !is_mapped(ea) ) return {QueryStatus::InvalidAddress, {}};
  const ea_t entry = get_func_start(ea);
  if ( entry == BADADDR ) return {QueryStatus::NotFound, {}};
  hexrays_failure_t failure;
  cfuncptr_t function(nullptr);
  try
  {
    function = decompile_function(entry, &failure, DECOMP_NO_WAIT | DECOMP_GXREFS_NOUPD);
  }
  catch ( const vd_failure_t &exception )
  {
    return {ClassifyDecompilerFailure(exception.hf.code), {}};
  }
  if ( function == nullptr ) return {ClassifyDecompilerFailure(failure.code), {}};
  lvars_t *variables = function->get_lvars();
  if ( variables == nullptr ) return {QueryStatus::DecompileFailed, {}};
  const std::size_t count = variables->size();
  const std::size_t returned = (std::min)(count, static_cast<std::size_t>(max_items));
  nlohmann::json items = nlohmann::json::array();
  const sval_t stack_delta = function->get_stkoff_delta();
  for ( std::size_t index = 0; index < returned; ++index )
  {
    const lvar_t &variable = variables->at(index);
    std::string name(variable.name.c_str(), variable.name.length());
    if ( !BoundedUtf8(name, MaxNameBytes) ) return {QueryStatus::OutputLimit, {}};
    const auto declaration = PrintType(variable.type(), variable.name.c_str());
    if ( !declaration ) return {QueryStatus::OutputLimit, {}};
    qstring locator_text;
    print_vdloc(&locator_text, variable.location, (std::max)(variable.width, 0));
    std::string text(locator_text.c_str(), locator_text.length());
    if ( !BoundedUtf8(text, MaxLocatorBytes) ) return {QueryStatus::OutputLimit, {}};
    const char *kind = variable.is_stk_var() ? "stack"
        : variable.is_reg_var() ? "register"
        : variable.is_scattered() ? "scattered" : "other";
    nlohmann::json locator{{"kind", kind}, {"text", std::move(text)}};
    if ( variable.is_stk_var() )
    {
      const sval_t vd_offset = variable.get_stkoff();
      locator["vdStackOffset"] = vd_offset;
      locator["idaStackOffset"] = vd_offset - stack_delta;
    }
    items.push_back({
        {"index", index}, {"name", std::move(name)}, {"declaration", *declaration},
        {"width", (std::max)(variable.width, 0)},
        {"defBlock", variable.defblk < 0 ? nlohmann::json(nullptr) : nlohmann::json(variable.defblk)},
        {"defEa", variable.defea == BADADDR ? nlohmann::json(nullptr) : nlohmann::json(rpc::FormatAddress(variable.defea))},
        {"locator", std::move(locator)}, {"flags", LvarFlags(variable)},
    });
  }
  return {QueryStatus::Success, {
      {"entryAddress", rpc::FormatAddress(entry)}, {"totalCount", count},
      {"truncated", returned < count}, {"items", std::move(items)},
  }};
}

QueryResult DecompilerInspectionService::DecompilerCtree(
    std::uint64_t address,
    std::uint32_t max_depth,
    std::uint32_t max_nodes) const
{
  if ( !decompiler_available_ ) return {QueryStatus::CapabilityUnavailable, {}};
  ea_t ea = BADADDR;
  if ( !StableAddress(address, &ea) || !is_mapped(ea) ) return {QueryStatus::InvalidAddress, {}};
  const ea_t entry = get_func_start(ea);
  if ( entry == BADADDR ) return {QueryStatus::NotFound, {}};
  hexrays_failure_t failure;
  cfuncptr_t function(nullptr);
  try
  {
    function = decompile_function(entry, &failure, DECOMP_NO_WAIT | DECOMP_GXREFS_NOUPD);
  }
  catch ( const vd_failure_t &exception )
  {
    return {ClassifyDecompilerFailure(exception.hf.code), {}};
  }
  if ( function == nullptr ) return {ClassifyDecompilerFailure(failure.code), {}};
  BoundedCtreeVisitor visitor(*function, max_depth, max_nodes);
  visitor.apply_to(&function->body, nullptr);
  const std::size_t count = visitor.nodes.size();
  return {QueryStatus::Success, {
      {"entryAddress", rpc::FormatAddress(entry)}, {"count", count},
      {"truncated", visitor.truncated}, {"nodes", std::move(visitor.nodes)},
  }};
}

QueryResult DecompilerInspectionService::DecompilerLocalXrefs(
    std::uint64_t address,
    std::uint32_t local_index,
    std::uint32_t max_depth,
    std::uint32_t max_nodes,
    std::uint32_t max_items) const
{
  if ( !decompiler_available_ ) return {QueryStatus::CapabilityUnavailable, {}};
  ea_t ea = BADADDR;
  if ( !StableAddress(address, &ea) || !is_mapped(ea) ) return {QueryStatus::InvalidAddress, {}};
  const ea_t entry = get_func_start(ea);
  if ( entry == BADADDR ) return {QueryStatus::NotFound, {}};
  hexrays_failure_t failure;
  cfuncptr_t function(nullptr);
  try
  {
    function = decompile_function(entry, &failure, DECOMP_NO_WAIT | DECOMP_GXREFS_NOUPD);
  }
  catch ( const vd_failure_t &exception )
  {
    return {ClassifyDecompilerFailure(exception.hf.code), {}};
  }
  if ( function == nullptr ) return {ClassifyDecompilerFailure(failure.code), {}};
  lvars_t *variables = function->get_lvars();
  if ( variables == nullptr || local_index >= variables->size() )
    return {QueryStatus::InvalidArgument, {}};
  const lvar_t &variable = variables->at(local_index);
  std::string name(variable.name.c_str(), variable.name.length());
  if ( !BoundedUtf8(name, MaxNameBytes) ) return {QueryStatus::OutputLimit, {}};
  BoundedLocalXrefVisitor visitor(local_index, max_depth, max_nodes, max_items);
  visitor.apply_to(&function->body, nullptr);
  return {QueryStatus::Success, {
      {"entryAddress", rpc::FormatAddress(entry)}, {"localIndex", local_index},
      {"name", std::move(name)}, {"visitedNodes", visitor.visited_nodes},
      {"totalReturned", visitor.items.size()}, {"truncated", visitor.truncated},
      {"items", std::move(visitor.items)},
  }};
}
}
