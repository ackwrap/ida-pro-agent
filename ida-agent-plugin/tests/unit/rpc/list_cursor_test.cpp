#include "list_cursor.hpp"
#include "inventory.hpp"

#include "test_support.hpp"

#include <string>

int main()
{
  Require(ida_agent::services::MaxInventoryScan == 4096, "inventory scan limit changed");
  Require(
      ida_agent::services::ValidateInventoryContinuation(1000000)
          == ida_agent::services::InventoryStatus::Success,
      "maximum continuation was rejected");
  Require(
      ida_agent::services::ValidateInventoryContinuation(1000001)
          == ida_agent::services::InventoryStatus::OutputLimit,
      "continuation above maximum was accepted");
  const std::string identity("query\0" "4", 7);
  const std::string cursor = ida_agent::rpc::EncodeListCursor("ss1", identity, 4096);
  Require(cursor.size() == 54, "cursor size mismatch");
  Require(
      ida_agent::rpc::DecodeListCursor("ss1", cursor, identity) == 4096,
      "cursor position mismatch");
  RequireFailure(
      [&cursor]() { ida_agent::rpc::DecodeListCursor("ss1", cursor, "other"); },
      "cursor query mismatch accepted");
  RequireFailure(
      [&cursor, &identity]() { ida_agent::rpc::DecodeListCursor("ds1", cursor, identity); },
      "cursor kind mismatch accepted");
  std::string modified = cursor;
  modified.back() = modified.back() == '0' ? '1' : '0';
  RequireFailure(
      [&modified, &identity]() { ida_agent::rpc::DecodeListCursor("ss1", modified, identity); },
      "modified cursor accepted");
  RequireFailure(
      []() { ida_agent::rpc::EncodeListCursor("bad-kind", "query", 0); },
      "invalid cursor kind accepted");
  const std::string entry_identity("name\0entry", 10);
  const std::string entry_cursor = ida_agent::rpc::EncodeListCursor("ep1", entry_identity, 4096);
  Require(
      ida_agent::rpc::DecodeListCursor("ep1", entry_cursor, entry_identity) == 4096,
      "R1B entry cursor position mismatch");
  RequireFailure(
      [&entry_cursor, &entry_identity]()
      {
        ida_agent::rpc::DecodeListCursor("se1", entry_cursor, entry_identity);
      },
      "R1B cross-method cursor accepted");
  return 0;
}
