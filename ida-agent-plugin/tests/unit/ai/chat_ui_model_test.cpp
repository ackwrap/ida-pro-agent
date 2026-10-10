#include "ai/agent_effect_policy.hpp"
#include "ai/chat_context.hpp"
#include "ai/chat_display_formatter.hpp"
#include "ai/chat_transcript.hpp"
#include "ai/cli_command.hpp"

#include <algorithm>
#include <stdexcept>
#include <string>
#include <unordered_set>

namespace
{

void Require(bool condition, const char *message)
{
  if ( !condition )
    throw std::runtime_error(message);
}

} // namespace

int main()
{
  using namespace ida_agent::ai;

  Require(ParseCliCommand("  ").kind == CliCommandKind::Empty, "empty input mismatch");
  Require(ParseCliCommand("hello").kind == CliCommandKind::Message, "message input mismatch");
  Require(ParseCliCommand(" /help ").kind == CliCommandKind::Help, "help command mismatch");
  Require(ParseCliCommand("/new").kind == CliCommandKind::NewConversation, "new command mismatch");
  Require(ParseCliCommand("/clear").kind == CliCommandKind::ClearConversation, "clear command mismatch");
  Require(ParseCliCommand("/compact").kind == CliCommandKind::Compact, "compact command mismatch");
  Require(ParseCliCommand("/cancel").kind == CliCommandKind::Cancel, "cancel command mismatch");
  Require(ParseCliCommand("/y").kind == CliCommandKind::AllowSessionEffects,
          "allow-policy command mismatch");
  Require(ParseCliCommand("/n").kind == CliCommandKind::DenySessionEffects,
          "deny-policy command mismatch");
  Require(ParseCliCommand("/y anything").kind == CliCommandKind::Unknown,
          "confirm command accepted arguments");
  Require(ParseCliCommand("/n anything").kind == CliCommandKind::Unknown,
          "reject command accepted arguments");
  Require(ParseCliCommand("/provider").kind == CliCommandKind::Provider, "provider command mismatch");
  Require(ParseCliCommand("/providers").kind == CliCommandKind::Providers, "providers command mismatch");
  Require(ParseCliCommand("/config").kind == CliCommandKind::Providers, "config command mismatch");
  Require(ParseCliCommand("/model").kind == CliCommandKind::Model, "model command mismatch");
  Require(ParseCliCommand("/models").kind == CliCommandKind::Models, "models command mismatch");
  Require(ParseCliCommand("/status").kind == CliCommandKind::Status, "status command mismatch");
  Require(ParseCliCommand("/history").kind == CliCommandKind::History, "history command mismatch");
  const CliCommand selected = ParseCliCommand("/session 2");
  Require(selected.kind == CliCommandKind::SelectSession && selected.text == "2",
          "session command mismatch");
  Require(ParseCliCommand("/ctx").kind == CliCommandKind::Context, "context command mismatch");
  Require(ParseCliCommand("/context").kind == CliCommandKind::Context, "context alias mismatch");
  Require(ParseCliCommand("/missing").kind == CliCommandKind::Unknown, "unknown command mismatch");

  AgentEffectSessionPolicies policies;
  Require(policies.Get("session-a") == AgentEffectApprovalPolicy::Ask,
          "new conversation session policy was not Ask");
  policies.Set("session-a", AgentEffectApprovalPolicy::Allow);
  Require(policies.Get("session-a") == AgentEffectApprovalPolicy::Allow,
          "allow policy could not be set without a pending effect");
  Require(policies.Get("session-b") == AgentEffectApprovalPolicy::Ask,
          "conversation policies were not isolated");
  policies.Set("session-b", AgentEffectApprovalPolicy::Deny);
  Require(policies.Get("session-b") == AgentEffectApprovalPolicy::Deny
              && policies.Get("session-a") == AgentEffectApprovalPolicy::Allow,
          "deny policy leaked across conversation sessions");
  policies.Set("session-a", AgentEffectApprovalPolicy::Deny);
  Require(policies.Get("session-a") == AgentEffectApprovalPolicy::Deny,
          "allow policy could not switch to deny");
  policies.Set("session-a", AgentEffectApprovalPolicy::Allow);
  Require(policies.Get("session-a") == AgentEffectApprovalPolicy::Allow,
          "deny policy could not switch back to allow");
  policies.Move("session-a", "persisted-session-a");
  Require(policies.Get("persisted-session-a") == AgentEffectApprovalPolicy::Allow
              && policies.Get("session-a") == AgentEffectApprovalPolicy::Ask
              && policies.Get("session-b") == AgentEffectApprovalPolicy::Deny,
          "runtime session policy was not promoted in memory");

  const std::vector<CliCommandDefinition> &commands = AvailableCliCommands();
  const std::vector<std::string_view> expected_command_order{
      "/help", "/new", "/clear", "/compact", "/cancel", "/y", "/n", "/provider", "/providers",
      "/config", "/model", "/models", "/status", "/history", "/session", "/ctx", "/context",
  };
  Require(commands.size() == expected_command_order.size(), "command suggestion count mismatch");
  std::unordered_set<std::string_view> command_names;
  for ( std::size_t index = 0; index < commands.size(); ++index )
  {
    const CliCommandDefinition &command = commands[index];
    Require(command.command == expected_command_order[index], "command suggestion order mismatch");
    Require(!command.command.empty() && command.command.front() == '/', "invalid suggested command");
    Require(!command.description.empty(), "command suggestion description is empty");
    if ( command.command == "/y" || command.command == "/n" )
      Require(command.description.find("conversation session") != std::string_view::npos,
              "side-effect policy help is scoped like a one-shot confirmation");
    Require(command_names.insert(command.command).second, "duplicate suggested command");
    Require(ParseCliCommand(command.command).kind == command.kind, "suggestion parser mismatch");
  }

  const std::vector<ChatEntry> context_entries{
      {ChatSpeaker::Context, "summary"},
      {ChatSpeaker::User, "question"},
      {ChatSpeaker::Tool, "Call: ida_database_info"},
      {ChatSpeaker::Assistant, "answer"},
  };
  const std::vector<ProviderChatMessage> context_messages =
      BuildConversationMessages(context_entries);
  Require(context_messages.size() == 3
              && context_messages[0].role == ProviderChatRole::User
              && context_messages[0].text.find("summary") != std::string::npos
              && context_messages[1].text == "question"
              && context_messages[2].role == ProviderChatRole::Assistant,
          "conversation context mapping mismatch");
  ProviderChatBuildResult context_build;
  context_build.context_length = 100000;
  context_build.max_output_tokens = 8000;
  context_build.input_token_budget = 87904;
  context_build.estimated_input_tokens = 25000;
  context_build.request.body.assign(50000, 'r');
  context_build.messages = context_messages;
  const ChatContextUsage usage = MakeChatContextUsage(
      context_build, context_entries, context_messages.size(), true);
  Require(usage.valid && usage.estimated_input_tokens == 25000
              && usage.history_entries == context_entries.size()
              && usage.compacted_summaries == 1
              && FormatChatContextUsage(usage, true).find("25.0%")
                  != std::string::npos,
          "context usage summary mismatch");
  const ChatContextUsage byte_cropped_usage = MakeChatContextUsage(
      context_build,
      context_entries,
      context_messages.size() + 1,
      true);
  Require(byte_cropped_usage.cropped
              && ShouldAutoCompactContext(byte_cropped_usage),
          "provider byte cropping did not trigger automatic context compaction");
  ChatContextUsage near_limit = usage;
  near_limit.input_token_budget = 100;
  near_limit.estimated_input_tokens = 85;
  Require(ShouldAutoCompactContext(near_limit),
          "85-percent context did not trigger automatic compaction");
  near_limit.estimated_input_tokens = 84;
  Require(!ShouldAutoCompactContext(near_limit),
          "sub-threshold context triggered automatic compaction");
  near_limit.cropped = true;
  Require(ShouldAutoCompactContext(near_limit),
          "cropped context did not trigger automatic compaction");
  std::vector<ChatEntry> compactable;
  for ( int index = 0; index < 10; ++index )
  {
    compactable.push_back({
        index % 2 == 0 ? ChatSpeaker::User : ChatSpeaker::Assistant,
        "message-" + std::to_string(index),
    });
  }
  const std::optional<ChatCompactionPlan> compaction =
      PlanChatCompaction(compactable);
  Require(compaction.has_value() && compaction->summarized_entries >= 2
              && compaction->retained_entries.size() >= 6
              && compaction->prompt.find("message-0") != std::string::npos,
          "context compaction plan mismatch");

  ChatTranscript transcript(4);
  Require(transcript.Lines().size() == 2, "welcome lines mismatch");
  Require(
      transcript.Lines()[1]
          == "[System] Provider chat is ready. Configure a provider and model before sending messages.",
      "provider-ready welcome line mismatch");
  transcript.Append(ChatSpeaker::User, "first\nsecond\r");
  Require(transcript.Lines().size() == 4, "multiline append mismatch");
  Require(transcript.Lines()[2] == "[You] first", "first user line mismatch");
  Require(transcript.Lines()[3] == "      second", "continuation line mismatch");
  transcript.Append(ChatSpeaker::System, "third");
  Require(transcript.Lines().size() == 4, "line cap mismatch");
  Require(transcript.Lines().front().find("Provider chat is ready") != std::string::npos,
          "oldest line not trimmed");
  Require(transcript.Lines().back() == "[System] third", "system line mismatch");
  transcript.Reset();
  Require(transcript.Lines().size() == 2, "reset did not restore welcome lines");
  const std::vector<ChatEntry> restored{
      {ChatSpeaker::User, "saved"},
      {ChatSpeaker::Context, "earlier"},
      {ChatSpeaker::Thinking, "summary"},
      {ChatSpeaker::Tool, "ida_function_get: ok"},
      {ChatSpeaker::Assistant, "reply"},
  };
  ChatTranscript restored_transcript;
  restored_transcript.Restore(restored);
  Require(restored_transcript.Entries().size() == 5, "restored entry count mismatch");
  Require(restored_transcript.Lines()[0] == "[You] saved", "restored user line mismatch");
  Require(restored_transcript.Lines()[1] == "[Context] earlier", "restored context line mismatch");
  Require(restored_transcript.Lines()[2] == "[Thinking] summary", "restored thinking line mismatch");
  Require(restored_transcript.Lines()[3] == "[Tool] ida_function_get: ok", "restored tool line mismatch");
  Require(restored_transcript.Lines()[4] == "[AI] reply", "restored assistant line mismatch");
  const std::vector<ChatEntry> before_failed_restore =
      restored_transcript.Entries();
  Require(
      !restored_transcript.Restore({{ChatSpeaker::User, std::string(1, static_cast<char>(0xFF))}}),
      "invalid transcript restore succeeded");
  Require(
      restored_transcript.Entries().size() == before_failed_restore.size()
          && restored_transcript.Entries().front().text
              == before_failed_restore.front().text
          && restored_transcript.Entries().back().text
              == before_failed_restore.back().text,
      "failed transcript restore changed the prior history");

  const std::size_t entry_count = restored_transcript.Entries().size();
  Require(
      !restored_transcript.Append(ChatSpeaker::User, std::string(MaxChatEntryBytes + 1, 'x')),
      "oversized live entry accepted");
  Require(restored_transcript.Entries().size() == entry_count, "rejected entry polluted history");
  const std::string invalid_utf8(1, static_cast<char>(0xFF));
  Require(!restored_transcript.Append(ChatSpeaker::User, invalid_utf8), "invalid UTF-8 live entry accepted");
  Require(restored_transcript.Entries().size() == entry_count, "invalid UTF-8 polluted history");

  ChatTranscript dense(4);
  Require(dense.Append(ChatSpeaker::System, std::string(10000, '\n')), "dense entry rejected");
  Require(dense.Lines().size() == 4, "dense entry exceeded viewer line cap");

  ChatPreview preview;
  preview.Begin();
  Require(preview.HasValue() && preview.Text().empty(), "preview did not begin empty");
  Require(preview.Append("first\nsecond\r"), "valid preview delta rejected");
  Require(preview.Text() == "first\nsecond", "preview control sanitization mismatch");
  Require(!preview.Append(invalid_utf8), "invalid UTF-8 preview accepted");
  Require(
      !preview.Append(std::string(MaxChatEntryBytes, 'x')),
      "oversized cumulative preview accepted");
  preview.Discard();
  Require(!preview.HasValue() && preview.Text().empty(), "preview discard mismatch");

  ChatPreview boundary_preview;
  boundary_preview.Begin();
  Require(
      boundary_preview.Append(std::string(MaxChatResponseBytes - 1, 'p')),
      "near-limit preview was rejected");
  Require(boundary_preview.Append("p"), "exact-limit preview was rejected");
  Require(!boundary_preview.Append("p"), "over-limit preview was accepted");
  ChatTranscript boundary_transcript;
  Require(
      boundary_transcript.Append(
          ChatSpeaker::Assistant,
          std::string(MaxChatResponseBytes, 'a')),
      "exact-limit transcript entry was rejected");
  Require(
      !boundary_transcript.Append(
          ChatSpeaker::Assistant,
          std::string(MaxChatResponseBytes + 1, 'a')),
      "over-limit transcript entry was accepted");

  const std::string long_tool_line(MaxChatDisplayLineBytes * 5 + 7, 't');
  const std::string formatted_tool =
      FormatChatDisplayEntry(ChatSpeaker::Tool, long_tool_line);
  std::string unsegmented_tool;
  for ( const char character : formatted_tool )
  {
    if ( character != '\n' )
      unsegmented_tool.push_back(character);
  }
  Require(
      unsegmented_tool == "[Tool] " + long_tool_line,
      "long display line lost or changed tool characters");
  Require(
      static_cast<std::size_t>(std::count(
          formatted_tool.begin(), formatted_tool.end(), '\n')) == 5,
      "multiple long display segments were not created at the bounded size");

  const std::string emoji = "\xF0\x9F\x98\x80";
  const std::string utf8_boundary(MaxChatDisplayLineBytes - 8, 'u');
  const std::string utf8_source = utf8_boundary + emoji + "tail";
  const std::string utf8_display =
      FormatChatDisplayEntry(ChatSpeaker::Tool, utf8_source);
  const std::size_t utf8_split = utf8_display.find('\n');
  Require(
      utf8_split == MaxChatDisplayLineBytes - 1
          && utf8_display.substr(utf8_split + 1, emoji.size()) == emoji,
      "display segmentation split a UTF-8 code point boundary");
  std::string utf8_unsegmented = utf8_display;
  utf8_unsegmented.erase(utf8_split, 1);
  Require(
      utf8_unsegmented == "[Tool] " + utf8_source,
      "UTF-8 display segmentation lost source bytes");

  ChatTranscript display_blocks_do_not_clip;
  Require(
      display_blocks_do_not_clip.Append(ChatSpeaker::Tool, long_tool_line),
      "long tool transcript setup failed");
  const std::string &stored_long_tool =
      display_blocks_do_not_clip.Entries().back().text;
  const std::string display_only_blocks = FormatChatDisplayLines(
      {display_blocks_do_not_clip.Lines().back()});
  Require(
      stored_long_tool == long_tool_line
          && stored_long_tool.find('\n') == std::string::npos
          && display_only_blocks.find('\n') != std::string::npos,
      "display-only blocks changed the transcript source text");

  ChatDisplayStreamFormatter streamed;
  streamed.Begin(ChatSpeaker::Thinking);
  const std::string first_reasoning = streamed.Append("first\n");
  const std::string second_reasoning = streamed.Append("second");
  Require(
      first_reasoning + second_reasoning == "first\n           second",
      "stream formatter changed reasoning continuation semantics");
  Require(
      streamed.Text() == "[Thinking] first\n           second",
      "stream formatter did not preserve delta order");

  ChatTranscript capped_entries(MaxChatHistoryEntries + 10);
  for ( std::size_t index = capped_entries.Entries().size();
        index < MaxChatHistoryEntries;
        ++index )
  {
    Require(capped_entries.Append(ChatSpeaker::System, "x"), "entry cap setup failed");
  }
  const ChatTranscriptAppendResult trim =
      capped_entries.AppendDetailed(ChatSpeaker::System, "new tail");
  Require(
      trim.appended && trim.trimmed_entries == 1 && trim.display_rebuild_required,
      "entry-cap append did not request a synchronized display rebuild");
  Require(
      capped_entries.Entries().size() == MaxChatHistoryEntries
          && capped_entries.Entries().back().text == "new tail",
      "entry-cap append left the transcript model out of sync");

  const ChatDisplayRemapPlan no_clip =
      PlanChatDisplayRemap("one\ntwo", "one\ntwo\nthree");
  Require(
      no_clip.retained_overlap_utf8_bytes == 7
          && no_clip.removed_utf8_bytes == 0
          && no_clip.removed_utf16_units == 0
          && no_clip.removed_display_blocks == 0,
      "no-clip display overlap mismatch");

  const ChatDisplayRemapPlan partial_clip =
      PlanChatDisplayRemap("one\ntwo\nthree", "two\nthree\nfour");
  Require(
      partial_clip.retained_overlap_utf8_bytes == 9
          && partial_clip.removed_utf8_bytes == 4
          && partial_clip.removed_utf16_units == 4
          && partial_clip.removed_display_blocks == 1,
      "partial display prefix clipping mismatch");
  Require(
      RemapChatDisplayCursor(partial_clip, 2) == 0
          && RemapChatDisplayCursor(partial_clip, 4) == 0
          && RemapChatDisplayCursor(partial_clip, 8) == 4,
      "clipped selection positions were not clamped or shifted");

  const ChatDisplayRemapPlan full_replace =
      PlanChatDisplayRemap("old\ntext", "replacement");
  Require(
      full_replace.retained_overlap_utf8_bytes == 0
          && full_replace.removed_utf8_bytes == 8
          && full_replace.removed_display_blocks == 2
          && RemapChatDisplayCursor(full_replace, 3) == 0,
      "full display replacement remap mismatch");

  const std::string old_utf8 =
      "\xE5\x88\xA0\n\xE4\xBF\x9D\xE7\x95\x99\xF0\x9F\x98\x80";
  const std::string new_utf8 =
      "\xE4\xBF\x9D\xE7\x95\x99\xF0\x9F\x98\x80\nnew";
  const ChatDisplayRemapPlan utf8_remap =
      PlanChatDisplayRemap(old_utf8, new_utf8);
  Require(
      utf8_remap.removed_utf8_bytes == 4
          && utf8_remap.removed_utf16_units == 2
          && utf8_remap.removed_display_blocks == 1,
      "UTF-8 display remap used byte offsets as cursor units");
  Require(
      RemapChatDisplayCursor(utf8_remap, 5) == 3,
      "retained UTF-8 cursor was not shifted in UTF-16 units");

  const std::string reasoning_display =
      "\n[Thinking] reason \xF0\x9F\x98\x80";
  const std::string assistant_display = "\n[AI] answer";
  const std::string old_committed = "old\nkeep";
  const std::string old_both_previews = reasoning_display + assistant_display;
  const std::string reasoning_committed = "keep" + reasoning_display;
  const ChatDisplayRemapPlan reasoning_migration = PlanChatDisplayRemap(
      old_committed,
      reasoning_committed,
      old_both_previews,
      {0, reasoning_display.size()});
  Require(
      reasoning_migration.migrated_preview_utf16_units != 0
          && reasoning_migration.migrated_preview_utf16_units
              < reasoning_display.size(),
      "UTF-8 reasoning preview migration used byte units");
  Require(
      RemapChatDisplayCursor(
          reasoning_migration,
          reasoning_migration.old_committed_utf16_units + 3)
          == reasoning_migration.new_committed_utf16_units
              - reasoning_migration.migrated_preview_utf16_units + 3,
      "committed reasoning preview cursor mapped after committed text");
  Require(
      RemapChatDisplayCursor(
          reasoning_migration,
          reasoning_migration.old_committed_utf16_units
              + reasoning_migration.migrated_preview_utf16_units + 3)
          == reasoning_migration.new_committed_utf16_units + 3,
      "remaining assistant preview cursor did not follow committed reasoning");

  const std::string assistant_committed =
      reasoning_committed + assistant_display;
  const ChatDisplayRemapPlan assistant_migration = PlanChatDisplayRemap(
      reasoning_committed,
      assistant_committed,
      assistant_display,
      {0, assistant_display.size()});
  Require(
      RemapChatDisplayCursor(
          assistant_migration,
          assistant_migration.old_committed_utf16_units + 4)
          == assistant_migration.new_committed_utf16_units
              - assistant_migration.migrated_preview_utf16_units + 4,
      "sequential assistant preview commit mapped its cursor to document end");

  const ChatDisplayRemapPlan no_preview_migration = PlanChatDisplayRemap(
      "drop\nretained", "retained\nnew");
  Require(
      no_preview_migration.old_preview_utf16_units == 0
          && no_preview_migration.migrated_preview_utf16_units == 0
          && RemapChatDisplayCursor(no_preview_migration, 8) == 3,
      "no-preview clipping changed committed cursor remapping");

  std::string oversized_reasoning;
  for ( std::size_t index = 0; index < MaxChatHistoryEntries + 2; ++index )
  {
    if ( index != 0 )
      oversized_reasoning.push_back('\n');
    oversized_reasoning += "line-" + std::to_string(index);
  }
  ChatDisplayStreamFormatter oversized_formatter;
  oversized_formatter.Begin(ChatSpeaker::Thinking);
  oversized_formatter.Append(oversized_reasoning);
  const std::string oversized_preview =
      FormatChatPreviewFragment(oversized_formatter.Text(), true);
  ChatTranscript clipped_preview_transcript;
  Require(
      clipped_preview_transcript.Restore({{ChatSpeaker::System, "base"}}),
      "oversized preview transcript setup failed");
  const std::string before_oversized_commit =
      FormatChatDisplayLines(clipped_preview_transcript.Lines());
  Require(
      clipped_preview_transcript.Append(ChatSpeaker::Thinking, oversized_reasoning),
      "oversized preview commit failed");
  const std::string after_oversized_commit =
      FormatChatDisplayLines(clipped_preview_transcript.Lines());
  const ChatDisplayRemapPlan oversized_migration = PlanChatDisplayRemap(
      before_oversized_commit,
      after_oversized_commit,
      oversized_preview,
      {0, oversized_preview.size()});
  const std::size_t retained_start =
      oversized_migration.new_committed_utf16_units
      - oversized_migration.migrated_preview_utf16_units;
  Require(
      oversized_migration.removed_migration_prefix_utf16_units != 0
          && oversized_migration.removed_migration_prefix_display_blocks == 2,
      "oversized preview did not report its clipped display prefix");
  Require(
      RemapChatDisplayCursor(
          oversized_migration,
          oversized_migration.old_committed_utf16_units + 5)
          == retained_start,
      "cursor in clipped preview prefix was not clamped to retained suffix");
  Require(
      RemapChatDisplayCursor(
          oversized_migration,
          oversized_migration.old_committed_utf16_units
              + oversized_migration.removed_migration_prefix_utf16_units + 7)
          == retained_start + 7,
      "cursor in retained oversized preview tail was mapped incorrectly");

  const std::string discarded_candidate = "\n[AI] entirely clipped";
  const ChatDisplayRemapPlan no_retained_migration = PlanChatDisplayRemap(
      "old",
      "new committed boundary",
      discarded_candidate,
      {0, discarded_candidate.size()});
  Require(
      no_retained_migration.migrated_preview_utf16_units == 0
          && RemapChatDisplayCursor(
              no_retained_migration,
              no_retained_migration.old_committed_utf16_units + 4)
              == no_retained_migration.new_committed_utf16_units,
      "fully clipped preview candidate did not clamp to committed boundary");
  return 0;
}
