#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace ida_agent::rpc
{

struct Capabilities
{
  bool decompiler;
  bool debugger;
  bool ui;
  std::uint8_t address_bits;
};

struct LocalEndpoint
{
  std::string kind;
  std::string path;
};

struct InstanceDescriptor
{
  std::uint32_t version;
  std::string protocol_version;
  std::string instance_id;
  std::uint32_t pid;
  std::string pipe;
  std::string ida_version;
  std::string database;
  std::string input_file;
  std::string processor;
  std::uint8_t bitness;
  std::int64_t started_at;
  std::string arch;
  Capabilities capabilities;
  std::optional<LocalEndpoint> endpoint;
};

InstanceDescriptor ParseInstanceDescriptor(std::string_view encoded);
std::string SerializeInstanceDescriptor(const InstanceDescriptor &descriptor);

} // namespace ida_agent::rpc
