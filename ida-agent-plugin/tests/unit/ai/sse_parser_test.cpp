#include "ai/sse_parser.hpp"

#include <stdexcept>
#include <string>
#include <vector>

namespace
{

void Require(bool condition, const char *message)
{
  if ( !condition )
    throw std::runtime_error(message);
}

void AppendEvents(
    std::vector<ida_agent::ai::SseEvent> &events,
    ida_agent::ai::SseParseResult result)
{
  Require(result.status != ida_agent::ai::SseParseStatus::Error, "SSE parse failed");
  for ( ida_agent::ai::SseEvent &event : result.events )
    events.push_back(std::move(event));
}

} // namespace

int main()
{
  using namespace ida_agent::ai;

  const std::string input =
      ": heartbeat\r"
      "event: update\r\n"
      "data: first\n"
      "data: second\r"
      "id: 42\r\n"
      "retry: 1500\r\n"
      "\r\n"
      "data: final";
  SseParser byte_parser;
  std::vector<SseEvent> events;
  for ( const char byte : input )
    AppendEvents(events, byte_parser.Feed(std::string_view(&byte, 1)));
  AppendEvents(events, byte_parser.Finish());
  Require(events.size() == 2, "byte-split event count mismatch");
  Require(events[0].event == "update", "event field mismatch");
  Require(events[0].data == "first\nsecond", "multi-data field mismatch");
  Require(events[0].id == "42", "event id mismatch");
  Require(events[0].retry_ms == 1500, "retry field mismatch");
  Require(events[1].data == "final", "Finish did not dispatch partial event");
  Require(events[1].event == "message", "default event type mismatch");
  Require(events[1].id == "42", "event id did not persist");
  Require(
      byte_parser.Finish().status == SseParseStatus::Finished,
      "Finish was not idempotent");

  SseParser id_parser;
  std::string nul_id = "id: ignored";
  nul_id.push_back('\0');
  nul_id += "value\ndata: one\n\nid:\ndata: two\n\nretry: +5\ndata: three\n\n";
  AppendEvents(events = {}, id_parser.Feed("id: kept\n"));
  AppendEvents(events, id_parser.Feed(nul_id));
  Require(events.size() == 3, "id/retry event count mismatch");
  Require(events[0].id == "kept", "NUL id was not ignored");
  Require(events[1].id.empty(), "empty id did not clear the id buffer");
  Require(!events[2].retry_ms.has_value(), "non-decimal retry was accepted");

  const std::string utf8 = "data: \xF0\x9F\x98\x80\n\n";
  SseParser utf8_parser;
  events.clear();
  for ( const char byte : utf8 )
    AppendEvents(events, utf8_parser.Feed(std::string_view(&byte, 1)));
  Require(events.size() == 1 && events[0].data == "\xF0\x9F\x98\x80", "UTF-8 split mismatch");

  SseParser bom_parser;
  events.clear();
  const std::string bom("\xEF\xBB\xBF", 3);
  for ( const char byte : bom )
    AppendEvents(events, bom_parser.Feed(std::string_view(&byte, 1)));
  AppendEvents(events, bom_parser.Feed("data: after-bom\n\n"));
  Require(events.size() == 1 && events[0].data == "after-bom", "split initial BOM was not ignored");

  SseParser later_bom;
  events.clear();
  AppendEvents(events, later_bom.Feed("data: before\n\n"));
  AppendEvents(events, later_bom.Feed(bom + "data: ignored\n\ndata: after\n\n"));
  Require(events.size() == 2, "later BOM event count mismatch");
  Require(events[0].data == "before" && events[1].data == "after", "later BOM was treated as initial BOM");

  SseParser invalid_utf8;
  Require(
      invalid_utf8.Feed(std::string("data: \xC0\xAF\n", 9)).status
          == SseParseStatus::Error,
      "invalid UTF-8 was accepted");
  SseParser incomplete_utf8;
  incomplete_utf8.Feed(std::string("data: \xE2\x82", 8));
  Require(
      incomplete_utf8.Finish().status == SseParseStatus::Error,
      "incomplete UTF-8 was accepted at EOF");

  SseParser line_limited(SseParserLimits{4, 32, 64});
  Require(
      line_limited.Feed("abcde").status == SseParseStatus::Error,
      "line limit was not enforced");
  SseParser event_limited(SseParserLimits{32, 4, 64});
  Require(
      event_limited.Feed("data: 12345\n").status == SseParseStatus::Error,
      "event limit was not enforced");
  SseParser id_limited(SseParserLimits{32, 4, 64});
  Require(
      id_limited.Feed("id: 12345\n").status == SseParseStatus::Error,
      "id was excluded from the event limit");
  SseParser scratch_limited(SseParserLimits{32, 32, 3});
  Require(
      scratch_limited.Feed("abcd").status == SseParseStatus::Error,
      "scratch limit was not enforced");

  SseParser comment_only;
  const SseParseResult heartbeat = comment_only.Feed(": ping\r\n\r\n");
  Require(heartbeat.events.empty(), "comment heartbeat emitted an event");
  Require(
      comment_only.Finish().status == SseParseStatus::Finished,
      "comment-only Finish status mismatch");
  return 0;
}
