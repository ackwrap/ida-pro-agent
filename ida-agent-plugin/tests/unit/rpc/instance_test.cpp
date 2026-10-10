#include "instance.hpp"

#include "test_support.hpp"

#include <nlohmann/json.hpp>

#include <string>

int main()
{
  using ida_agent::rpc::ParseInstanceDescriptor;

  const auto unix_descriptor = ParseInstanceDescriptor(ReadFixture("valid", "instance-unix.json"));
  Require(unix_descriptor.endpoint && unix_descriptor.endpoint->kind == "unix", "Unix endpoint missing");
  static_cast<void>(ParseInstanceDescriptor(ida_agent::rpc::SerializeInstanceDescriptor(unix_descriptor)));
  const auto descriptor = ParseInstanceDescriptor(ReadFixture("valid", "instance-named-pipe.json"));
  Require(descriptor.pipe == "\\\\.\\pipe\\ida-agent-4242-8dd304b5", "pipe mismatch");
  Require(descriptor.instance_id == "8dd304b5-8a3e-4d55-94ec-b931924e38fd", "instance ID mismatch");
  Require(descriptor.capabilities.address_bits == 64, "address bits mismatch");
  static_cast<void>(ParseInstanceDescriptor(ida_agent::rpc::SerializeInstanceDescriptor(descriptor)));

  const auto equivalent_integer_descriptor =
      ParseInstanceDescriptor(ReadFixture("valid", "instance-integer-number-forms.json"));
  Require(equivalent_integer_descriptor.pid == 4242, "equivalent integer pid failed");
  Require(
      equivalent_integer_descriptor.capabilities.address_bits == 64,
      "equivalent integer address bits failed");

  for ( const std::string_view fixture :
        {"instance-unix-unknown-field.json", "instance-unix-traversal.json", "instance-unix-relative.json", "instance-mixed-endpoints.json", "instance-v1-unix.json", "instance-invalid-id.json", "instance-missing-capability.json",
         "instance-invalid-pipe.json", "instance-mismatched-pipe.json",
         "instance-overflow-number.json"} )
  {
    RequireFailure(
        [fixture]()
        {
          static_cast<void>(ParseInstanceDescriptor(ReadFixture("invalid", fixture)));
        },
        "invalid instance fixture accepted");
  }

  auto unicode_session = nlohmann::json::parse(ReadFixture("valid", "instance-named-pipe.json"));
  std::string unicode_database;
  for ( std::size_t index = 0; index < 1024; ++index )
    unicode_database += "\xE7\x95\x8C";
  unicode_session["database"] = unicode_database;
  static_cast<void>(ParseInstanceDescriptor(unicode_session.dump()));
  unicode_session["database"] = unicode_database + "\xE7\x95\x8C";
  RequireFailure(
      [&unicode_session]()
      {
        static_cast<void>(ParseInstanceDescriptor(unicode_session.dump()));
      },
      "1025-character database accepted");
  return 0;
}
