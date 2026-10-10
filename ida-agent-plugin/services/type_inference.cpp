#include "type_service_internal.hpp"

#include <frame.hpp>
#include <funcs.hpp>
#include <nalt.hpp>
#include <typeinf.hpp>

#include <utility>

namespace ida_agent::services
{

using type_service_detail::CheckedAddress;
using type_service_detail::Declaration;
using type_service_detail::MaxDetailMembers;

StackFrameOutcome TypeService::StackFrame(std::uint64_t address) const
{
  const auto requested = CheckedAddress(address);
  if ( !requested ) return {TypeStatus::InvalidAddress, std::nullopt};
  const ea_t entry = get_func_start(*requested);
  if ( entry == BADADDR ) return {TypeStatus::NotFound, std::nullopt};
  tinfo_t frame;
  if ( !get_func_frame_ea(&frame, entry) ) return {TypeStatus::NotFound, std::nullopt};
  const int member_count = frame.get_udt_nmembers();
  if ( member_count < 0 || static_cast<std::size_t>(member_count) > MaxDetailMembers )
    return {TypeStatus::OutputLimit, std::nullopt};
  udt_type_data_t members;
  if ( !frame.get_udt_details(&members) ) return {TypeStatus::NotFound, std::nullopt};
  StackFrameResult result{entry, frame.get_size()};
  range_t arguments;
  const bool has_arguments = get_frame_part_ea(&arguments, entry, FPC_ARGS);
  for ( const udm_t &member : members )
  {
    std::string role = member.is_retaddr() ? "return_address" : member.is_savregs() ? "saved_register" : "local";
    if ( has_arguments && member.offset / 8 >= arguments.start_ea && member.offset / 8 < arguments.end_ea ) role = "argument";
    result.variables.push_back({
        member.name.c_str(), Declaration(member.type, member.name.c_str()).text,
        static_cast<std::int64_t>(member.offset), member.size, std::move(role)});
  }
  return {TypeStatus::Success, std::move(result)};
}

TypeInferenceOutcome TypeService::Infer(std::uint64_t address) const
{
  const auto ea = CheckedAddress(address);
  if ( !ea ) return {TypeStatus::InvalidAddress, std::nullopt};
  tinfo_t type;
  if ( guess_tinfo(&type, *ea) != GUESS_FUNC_FAILED && !type.empty() )
  {
    const std::string declaration = Declaration(type).text;
    if ( !declaration.empty() )
      return {TypeStatus::Success, TypeInferenceResult{address, declaration, "guess_tinfo"}};
  }
  if ( get_tinfo(&type, *ea) )
    return {TypeStatus::Success, TypeInferenceResult{address, Declaration(type).text, "existing"}};
  const asize_t size = get_item_size(*ea);
  if ( size == 0 ) return {TypeStatus::NotFound, std::nullopt};
  const std::string declaration = size == 1 ? "uint8_t"
      : size == 2 ? "uint16_t"
      : size == 4 ? "uint32_t"
      : size == 8 ? "uint64_t"
      : "uint8_t[" + std::to_string(size) + "]";
  return {TypeStatus::Success, TypeInferenceResult{address, declaration, "item_size"}};
}

} // namespace ida_agent::services
