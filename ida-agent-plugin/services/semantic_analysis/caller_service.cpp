#include "service.hpp"
#include <bytes.hpp>
#include <funcs.hpp>
#include <ua.hpp>
#include <idp.hpp>
#include <xref.hpp>

namespace ida_agent::services
{
QueryResult SemanticAnalysisService::TraceArgumentCallers(const semantic::CallersRequest &request) const
{
  if (!decompiler_available_) return {QueryStatus::CapabilityUnavailable, {}};
  semantic::CallersProvider provider;
  provider.load = semantic::LoadMicrocodeSnapshot;
  provider.callers = [](std::uint64_t entry, std::uint32_t limit, std::uint32_t max_work) {
    semantic::CallerSites result;
    xrefblk_t ref;
    for (bool ok = ref.first_to(static_cast<ea_t>(entry), XREF_ALL); ok; ok = ref.next_to())
    {
      if (result.work >= max_work) { result.truncated = true; break; }
      ++result.work;
      insn_t ins;
      if (!ref.iscode || (ref.type != fl_CN && ref.type != fl_CF)
          || get_func_start(ref.from) == BADADDR || decode_insn(&ins, ref.from) <= 0 || !is_call_insn(ins))
      { result.unsupported = true; continue; }
      if (result.addresses.size() >= limit) { result.truncated = true; break; }
      result.addresses.push_back(ref.from);
    }
    return result;
  };
  return semantic::TraceCallers(request, provider);
}
}
