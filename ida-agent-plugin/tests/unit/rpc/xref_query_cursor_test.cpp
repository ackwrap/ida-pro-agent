#include "xref_query_cursor.hpp"

#include "test_support.hpp"

#include <string>

int main()
{
  const std::string cursor = ida_agent::rpc::EncodeXrefQueryCursor(
      "0x140001000|outgoing|all|0",
      true,
      42);
  const ida_agent::rpc::XrefQueryCursor decoded = ida_agent::rpc::DecodeXrefQueryCursor(
      cursor,
      "0x140001000|outgoing|all|0");
  Require(decoded.data_phase, "xref cursor phase mismatch");
  Require(decoded.next_index == 42, "xref cursor index mismatch");
  const std::string boundary_cursor = ida_agent::rpc::EncodeXrefQueryCursor(
      "0x140001000|outgoing|all|0",
      false,
      1000000);
  Require(
      ida_agent::rpc::DecodeXrefQueryCursor(
          boundary_cursor,
          "0x140001000|outgoing|all|0").next_index == 1000000,
      "xref boundary cursor mismatch");
  RequireFailure(
      [&cursor]()
      {
        static_cast<void>(ida_agent::rpc::DecodeXrefQueryCursor(
            cursor,
            "0x140001000|incoming|all|0"));
      },
      "xref cursor query mismatch accepted");
  std::string modified = cursor;
  modified.back() = modified.back() == '0' ? '1' : '0';
  RequireFailure(
      [&modified]()
      {
        static_cast<void>(ida_agent::rpc::DecodeXrefQueryCursor(
            modified,
            "0x140001000|outgoing|all|0"));
      },
      "modified xref cursor accepted");
  return 0;
}
