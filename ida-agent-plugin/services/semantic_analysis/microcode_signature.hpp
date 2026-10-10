#pragma once
#include "model.hpp"
#include <hexrays.hpp>

namespace ida_agent::services::semantic
{
template <class Arguments>
std::string SignatureKey(const tinfo_t &returns, callcnv_t convention, const Arguments &args)
{
  if (convention == CM_CC_INVALID || convention == CM_CC_UNKNOWN || is_vararg_cc(convention)
      || is_user_cc(convention) || args.size() > 256) return {};
  qstring type;
  returns.print(&type);
  if (type.empty() || type.length() > 4096) return {};
  std::string key = std::to_string(convention) + ":" + type.c_str();
  for (const auto &arg : args)
  {
    const auto width = arg.type.get_size();
    if (width == 0 || width > 16 || (!arg.argloc.is_reg1() && !arg.argloc.is_stkoff())) return {};
    arg.type.print(&type);
    if (type.empty() || type.length() > 4096) return {};
    char location[256]{};
    auto count = print_argloc(location, sizeof(location), arg.argloc, static_cast<int>(width), PRALOC_STKOFF);
    if (count == 0 || count >= sizeof(location) - 1) return {};
    key += ";" + std::to_string(width) + ":" + type.c_str() + "@" + location;
  }
  return key;
}
inline std::string ParameterSignature(mba_t &mba, const Snapshot &snapshot)
{
  func_type_data_t args;
  if (!mba.idb_type.get_func_details(&args) || args.size() != snapshot.parameters.size()) return {};
  for (std::size_t i = 0; i < args.size(); ++i)
  {
    const auto width = args[i].type.get_size();
    if (width == 0 || width > 16) return {};
    auto loc = mba.idaloc2vd(args[i].argloc, static_cast<int>(width));
    Location expected;
    if (loc.is_reg1()) expected = {"register", static_cast<std::uint64_t>(loc.reg1()), static_cast<std::uint32_t>(width)};
    else if (loc.is_stkoff()) expected = {"stack", static_cast<std::uint64_t>(loc.stkoff()), static_cast<std::uint32_t>(width)};
    else return {};
    if (!(expected == snapshot.parameters[i])) return {};
  }
  return SignatureKey(args.rettype, args.get_cc(), args);
}
}
