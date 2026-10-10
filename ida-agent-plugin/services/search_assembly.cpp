#include "search_service.hpp"

#include <ida.hpp>
#include <idp.hpp>
#include <segment.hpp>

#include <array>
#include <cctype>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ida_agent::services
{
namespace
{

constexpr std::size_t MaxAssemblyBytes = 4096;
constexpr std::size_t MaxAssemblyInstructions = 128;

std::string TrimInstruction(std::string_view instruction)
{
  std::size_t first = 0, last = instruction.size();
  while ( first < last && std::isspace(static_cast<unsigned char>(instruction[first])) ) ++first;
  while ( last > first && std::isspace(static_cast<unsigned char>(instruction[last - 1])) ) --last;
  return std::string(instruction.substr(first, last - first));
}

} // namespace

AssemblyOutcome SearchService::Assemble(std::uint64_t address, std::string_view instruction) const
{
  const ea_t start = static_cast<ea_t>(address);
  const std::string input(instruction);
  if ( static_cast<std::uint64_t>(start) != address || start == BADADDR || !is_mapped(start) )
    return {SearchStatus::InvalidAddress, std::nullopt};
  if ( input.empty() || input.size() > 4096 || !is_valid_utf8(input.c_str()) )
    return {SearchStatus::InvalidPattern, std::nullopt};

  std::vector<std::string> instructions;
  std::size_t begin = 0;
  while ( begin <= input.size() )
  {
    const std::size_t separator = input.find(';', begin);
    const std::size_t end = separator == std::string::npos ? input.size() : separator;
    std::string part = TrimInstruction(std::string_view(input).substr(begin, end - begin));
    if ( part.empty() ) return {SearchStatus::InvalidPattern, std::nullopt};
    if ( instructions.size() == MaxAssemblyInstructions ) return {SearchStatus::OutputLimit, std::nullopt};
    instructions.push_back(std::move(part));
    if ( separator == std::string::npos ) break;
    begin = separator + 1;
  }

  std::vector<unsigned char> bytes;
  std::vector<AssemblyInstructionResult> boundaries;
  ea_t current = start;
  for ( const std::string &item : instructions )
  {
    segment_info_t segment;
    if ( !get_segment_info(&segment, current) ) return {SearchStatus::InvalidAddress, std::nullopt};
    std::array<unsigned char, 1024> assembled{};
    const ea_t base = segment.base();
    if ( current < base ) return {SearchStatus::InvalidAddress, std::nullopt};
    const ssize_t size = processor_t::assemble(
        assembled.data(), current, segment.get_sel(), current - base, !segment.is_16bit(), item.c_str());
    if ( size <= 0 || size > static_cast<ssize_t>(assembled.size()) )
      return {SearchStatus::InvalidPattern, std::nullopt};
    if ( static_cast<std::size_t>(size) > MaxAssemblyBytes - bytes.size() )
      return {SearchStatus::OutputLimit, std::nullopt};
    if ( current > (std::numeric_limits<ea_t>::max)() - static_cast<ea_t>(size) )
      return {SearchStatus::InvalidAddress, std::nullopt};
    const ea_t next = current + static_cast<ea_t>(size);
    boundaries.push_back({
        current, next, static_cast<std::uint32_t>(bytes.size()), static_cast<std::uint32_t>(size),
    });
    bytes.insert(bytes.end(), assembled.begin(), assembled.begin() + size);
    current = next;
  }

  std::ostringstream encoded;
  encoded << std::hex << std::setfill('0');
  for ( unsigned char byte : bytes ) encoded << std::setw(2) << static_cast<unsigned>(byte);
  return {
      SearchStatus::Success,
      AssemblyResult{address, encoded.str(), static_cast<std::uint32_t>(bytes.size()), std::move(boundaries)},
  };
}

} // namespace ida_agent::services
