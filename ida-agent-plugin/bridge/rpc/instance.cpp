#include "instance.hpp"

#include "envelope.hpp"
#include "validation.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace ida_agent::rpc
{
namespace
{

bool IsValidUuid(std::string_view value)
{
  if ( value.size() != 36 )
    return false;
  for ( std::size_t index = 0; index < value.size(); ++index )
  {
    if ( index == 8 || index == 13 || index == 18 || index == 23 )
    {
      if ( value[index] != '-' )
        return false;
    }
    else if ( !((value[index] >= '0' && value[index] <= '9')
             || (value[index] >= 'a' && value[index] <= 'f')) )
    {
      return false;
    }
  }
  return value[14] == '4' && (value[19] == '8' || value[19] == '9'
      || value[19] == 'a' || value[19] == 'b');
}

bool IsValidSimpleName(std::string_view value, std::size_t maximum)
{
  return !value.empty() && value.size() <= maximum
      && std::all_of(value.begin(), value.end(), [](unsigned char character)
      {
        return character >= 0x20 && character != 0x7F;
      });
}

void ValidateDescriptor(const InstanceDescriptor &descriptor)
{
  if ( descriptor.version != 1 && descriptor.version != 2 )
    throw std::invalid_argument("instance registry version is unsupported");
  ValidateProtocolVersion(descriptor.protocol_version);
  if ( !IsValidUuid(descriptor.instance_id) )
    throw std::invalid_argument("instance_id is invalid");
  if ( descriptor.pid == 0 )
    throw std::invalid_argument("pid must be greater than zero");
  const std::string expected_pipe = "\\\\.\\pipe\\ida-agent-" + std::to_string(descriptor.pid)
      + "-" + descriptor.instance_id.substr(0, 8);
  if ( descriptor.version == 1 )
  {
    if ( descriptor.pipe != expected_pipe || descriptor.endpoint )
      throw std::invalid_argument("pipe locator is invalid");
  }
  else
  {
    if ( !descriptor.pipe.empty() || !descriptor.endpoint || descriptor.endpoint->kind != "unix" )
      throw std::invalid_argument("Unix endpoint is required for registry v2");
    const auto &path = descriptor.endpoint->path;
    const std::string filename = "ida-agent-" + std::to_string(descriptor.pid)
        + "-" + descriptor.instance_id.substr(0, 8) + ".sock";
    if ( path.empty() || path.front() != '/' || path.size() > 107
      || !IsValidSimpleName(path, 107) || path.find('\\') != std::string::npos
      || path.find("//") != std::string::npos || path.find("/./") != std::string::npos
      || path.find("/../") != std::string::npos
      || path.substr(path.rfind('/') + 1) != filename )
      throw std::invalid_argument("Unix socket locator is invalid");
  }
  if ( !IsValidSimpleName(descriptor.ida_version, 64) )
    throw std::invalid_argument("ida_version is invalid");
  if ( Utf8CodePointCount(descriptor.database) > 1024 )
    throw std::invalid_argument("database is too long");
  if ( Utf8CodePointCount(descriptor.input_file) > 1024 )
    throw std::invalid_argument("input_file is too long");
  if ( !IsValidSimpleName(descriptor.processor, 64) )
    throw std::invalid_argument("processor is invalid");
  if ( descriptor.bitness != 32 && descriptor.bitness != 64 )
    throw std::invalid_argument("bitness must be 32 or 64");
  if ( descriptor.started_at <= 0 )
    throw std::invalid_argument("started_at must be positive");
  if ( !IsValidSimpleName(descriptor.arch, 64) )
    throw std::invalid_argument("arch is invalid");
  if ( descriptor.capabilities.address_bits != descriptor.bitness )
    throw std::invalid_argument("capability bitness mismatch");
}

} // namespace

InstanceDescriptor ParseInstanceDescriptor(std::string_view encoded)
{
  const Json root = ParseRootObject(encoded);
  const auto registry_version = ReadUnsigned(root, "version");
  if ( registry_version == 1 )
    RequireExactFields(root, {
        "version", "protocol_version", "instance_id", "pid", "pipe", "ida_version",
        "database", "input_file", "processor", "bitness", "started_at", "arch", "capabilities"});
  else
    RequireExactFields(root, {
        "version", "protocol_version", "instance_id", "pid", "endpoint", "ida_version",
        "database", "input_file", "processor", "bitness", "started_at", "arch", "capabilities"});
  const Json &capabilities = ReadObject(root, "capabilities");
  RequireExactFields(capabilities, {"decompiler", "debugger", "ui", "address_bits"});
  const std::uint64_t pid = ReadUnsigned(root, "pid");
  const std::uint64_t bitness = ReadUnsigned(root, "bitness");
  const std::uint64_t address_bits = ReadUnsigned(capabilities, "address_bits");
  const std::uint64_t started_at = ReadUnsigned(root, "started_at");
  const std::uint64_t version = ReadUnsigned(root, "version");
  if ( version > std::numeric_limits<std::uint32_t>::max()
    || pid > std::numeric_limits<std::uint32_t>::max()
    || bitness > std::numeric_limits<std::uint8_t>::max()
    || address_bits > std::numeric_limits<std::uint8_t>::max()
    || started_at > static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()) )
  {
    throw std::invalid_argument("instance registry integer is out of range");
  }
  InstanceDescriptor descriptor{
      static_cast<std::uint32_t>(version),
      ReadString(root, "protocol_version"),
      ReadString(root, "instance_id"),
      static_cast<std::uint32_t>(pid),
      registry_version == 1 ? ReadString(root, "pipe") : std::string(),
      ReadString(root, "ida_version"),
      ReadString(root, "database"),
      ReadString(root, "input_file"),
      ReadString(root, "processor"),
      static_cast<std::uint8_t>(bitness),
      static_cast<std::int64_t>(started_at),
      ReadString(root, "arch"),
      Capabilities{
          ReadBool(capabilities, "decompiler"),
          ReadBool(capabilities, "debugger"),
          ReadBool(capabilities, "ui"),
          static_cast<std::uint8_t>(address_bits),
      },
  };
  if ( registry_version == 2 )
  {
    const auto &endpoint = ReadObject(root, "endpoint");
    RequireExactFields(endpoint, {"kind", "path"});
    descriptor.endpoint = LocalEndpoint{ReadString(endpoint, "kind"), ReadString(endpoint, "path")};
  }
  ValidateDescriptor(descriptor);
  return descriptor;
}

std::string SerializeInstanceDescriptor(const InstanceDescriptor &descriptor)
{
  ValidateDescriptor(descriptor);
  Json result{
      {"version", descriptor.version},
      {"protocol_version", descriptor.protocol_version},
      {"instance_id", descriptor.instance_id},
      {"pid", descriptor.pid},
      {"pipe", descriptor.pipe},
      {"ida_version", descriptor.ida_version},
      {"database", descriptor.database},
      {"input_file", descriptor.input_file},
      {"processor", descriptor.processor},
      {"bitness", descriptor.bitness},
      {"started_at", descriptor.started_at},
      {"arch", descriptor.arch},
      {"capabilities", {
          {"decompiler", descriptor.capabilities.decompiler},
          {"debugger", descriptor.capabilities.debugger},
          {"ui", descriptor.capabilities.ui},
          {"address_bits", descriptor.capabilities.address_bits},
      }},
  };
  if ( descriptor.version == 2 )
  {
    result.erase("pipe");
    result["endpoint"] = {{"kind", descriptor.endpoint->kind}, {"path", descriptor.endpoint->path}};
  }
  return result.dump(2) + "\n";
}

} // namespace ida_agent::rpc
