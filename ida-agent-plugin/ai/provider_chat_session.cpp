#include "ai/provider_chat_session.hpp"

#include "ai/network_diagnostics.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace ida_agent::ai
{
namespace
{

ProviderChatSessionEvent MakeEvent(
    ProviderChatSessionEventKind kind,
    std::string text = {})
{
  ProviderChatSessionEvent event;
  event.kind = kind;
  event.safe_message = std::move(text);
  return event;
}

ProviderChatSessionEvent MakeDeltaEvent(
    std::string reasoning,
    std::string text)
{
  ProviderChatSessionEvent event;
  event.kind = ProviderChatSessionEventKind::Delta;
  event.reasoning_delta = std::move(reasoning);
  event.text_delta = std::move(text);
  return event;
}

const char *CodecName(ProviderChatCodec codec)
{
  switch ( codec )
  {
    case ProviderChatCodec::OpenAIResponses: return "openai-responses";
    case ProviderChatCodec::OpenAIChatCompletions: return "openai-chat";
    case ProviderChatCodec::ClaudeMessages: return "claude";
  }
  return "unknown";
}

std::string TransportSafeMessage(const StreamEvent &event)
{
  if ( event.http_status != 0
      && (event.http_status < 200 || event.http_status >= 300) )
  {
    std::string message = "Provider chat request failed with HTTP status "
        + std::to_string(event.http_status);
    if ( !event.message.empty() )
      message += ": " + event.message;
    return message;
  }
  return event.message.empty()
      ? std::string(ProviderChatTransportErrorMessage)
      : std::string(ProviderChatTransportErrorMessage) + " " + event.message;
}

ProviderChatSessionEventKind SelectTerminalKind(
    bool has_pending_error,
    bool codec_completed,
    bool user_cancel_requested,
    bool has_completed_calls) noexcept
{
  if ( has_pending_error )
    return ProviderChatSessionEventKind::Error;
  if ( codec_completed )
  {
    return has_completed_calls
        ? ProviderChatSessionEventKind::ToolCalls
        : ProviderChatSessionEventKind::Completed;
  }
  if ( user_cancel_requested )
    return ProviderChatSessionEventKind::Cancelled;
  return ProviderChatSessionEventKind::Error;
}

enum class UpdateStatus
{
  Success,
  ProtocolError,
  LimitError,
};

struct AccumulatedToolCall
{
  std::size_t index = 0;
  std::string id;
  std::string name;
  std::string arguments;
  bool empty_object_start = false;
  bool done = false;
};

struct ReasoningParts
{
  std::string reasoning;
  std::string text;
};

class LeadingReasoningFilter final
{
public:
  ReasoningParts Push(std::string_view delta)
  {
    if ( state_ == State::Visible )
      return {{}, std::string(delta)};
    pending_.append(delta);
    if ( state_ == State::Prefix )
    {
      const std::size_t first = pending_.find_first_not_of(" \t\r\n");
      if ( first == std::string::npos )
        return {};
      const std::string_view candidate(pending_.data() + first, pending_.size() - first);
      constexpr std::string_view OpenTag = "<think>";
      if ( candidate.size() < OpenTag.size()
          && OpenTag.compare(0, candidate.size(), candidate) == 0 )
      {
        return {};
      }
      if ( candidate.size() < OpenTag.size()
          || candidate.substr(0, OpenTag.size()) != OpenTag )
      {
        state_ = State::Visible;
        return {{}, TakePending()};
      }
      pending_.erase(0, first + OpenTag.size());
      state_ = State::Hidden;
    }
    return PushHidden();
  }

  ReasoningParts Finish()
  {
    ReasoningParts result;
    if ( state_ == State::Prefix )
      result.text = TakePending();
    else if ( state_ == State::Hidden )
      result.reasoning = TakePending();
    else
    {
      pending_.clear();
    }
    state_ = State::Visible;
    return result;
  }

private:
  enum class State
  {
    Prefix,
    Hidden,
    Visible,
  };

  std::string TakePending()
  {
    std::string result = std::move(pending_);
    pending_.clear();
    return result;
  }

  ReasoningParts PushHidden()
  {
    constexpr std::string_view CloseTag = "</think>";
    const std::size_t close = pending_.find(CloseTag);
    if ( close != std::string::npos )
    {
      ReasoningParts result{
          pending_.substr(0, close),
          pending_.substr(close + CloseTag.size()),
      };
      pending_.clear();
      state_ = State::Visible;
      return result;
    }

    std::size_t retained = (std::min)(
        pending_.size(), CloseTag.size() - 1);
    while ( retained > 0
        && pending_.compare(
               pending_.size() - retained,
               retained,
               CloseTag.data(),
               retained) != 0 )
    {
      --retained;
    }
    ReasoningParts result;
    result.reasoning = pending_.substr(0, pending_.size() - retained);
    pending_.erase(0, pending_.size() - retained);
    return result;
  }

  State state_ = State::Prefix;
  std::string pending_;
};

UpdateStatus ApplyField(
    std::string &value,
    const std::optional<std::string> &delta,
    const std::optional<std::string> &snapshot,
    std::size_t limit)
{
  if ( delta.has_value() && snapshot.has_value() )
    return UpdateStatus::ProtocolError;
  if ( delta.has_value() )
  {
    if ( delta->size() > limit - (std::min)(value.size(), limit) )
      return UpdateStatus::LimitError;
    value += *delta;
  }
  if ( snapshot.has_value() )
  {
    if ( snapshot->size() > limit )
      return UpdateStatus::LimitError;
    if ( !value.empty()
        && (snapshot->size() < value.size()
            || snapshot->compare(0, value.size(), value) != 0) )
    {
      return UpdateStatus::ProtocolError;
    }
    value = *snapshot;
  }
  return UpdateStatus::Success;
}

} // namespace

struct ProviderChatSession::Impl
{
  explicit Impl(std::size_t requested_text_limit)
      : text_limit((std::min)(requested_text_limit, MaxProviderChatTextBytes))
  {
  }

  ~Impl()
  {
    Cancel();
  }

  bool Start(StreamClient &new_client, ProviderChatBuildResult build)
  {
    if ( active || build.error )
      return false;
    reasoning_filter = LeadingReasoningFilter{};
    show_reasoning = build.show_reasoning;
    client = &new_client;
    codec = build.codec;
    const std::string diagnostic = std::string("codec=") + CodecName(codec)
        + " bodyBytes=" + std::to_string(build.request.body.size())
        + " reasoning=" + (show_reasoning ? "visible" : "hidden");
    stream_id = client->OpenSse(std::move(build.request));
    if ( stream_id == 0 )
    {
      client = nullptr;
      return false;
    }
    LogAiNetworkDiagnostic("chat.start", diagnostic, 0, stream_id);
    active = true;
    return true;
  }

  void Cancel() noexcept
  {
    if ( !active || terminal_event.has_value() || codec_completed )
      return;
    user_cancel_requested = true;
    RequestTransportCancel();
  }

  void RequestTransportCancel() noexcept
  {
    if ( transport_cancel_requested )
      return;
    transport_cancel_requested = true;
    client->Cancel(stream_id);
  }

  void FailAfterCancel(std::string safe_message)
  {
    if ( pending_error.empty() )
      pending_error = std::move(safe_message);
    RequestTransportCancel();
  }

  void CacheTerminal(
      ProviderChatSessionEventKind kind,
      std::string safe_message = {},
      std::vector<AgentToolCall> calls = {})
  {
    if ( !terminal_event.has_value() )
    {
      terminal_event = MakeEvent(kind, std::move(safe_message));
      terminal_event->calls = std::move(calls);
    }
  }

  void CacheCodecTerminal()
  {
    if ( completed_calls.empty() )
      CacheTerminal(ProviderChatSessionEventKind::Completed);
    else
    {
      CacheTerminal(
          ProviderChatSessionEventKind::ToolCalls, {}, completed_calls);
      terminal_event->assistant_text = assistant_text;
    }
  }

  void CacheTransportTerminal(const StreamEvent &event)
  {
    const ProviderChatSessionEventKind kind = SelectTerminalKind(
        !pending_error.empty(),
        codec_completed,
        user_cancel_requested,
        !completed_calls.empty());
    if ( kind == ProviderChatSessionEventKind::Completed
        || kind == ProviderChatSessionEventKind::ToolCalls )
    {
      CacheCodecTerminal();
    }
    else if ( kind == ProviderChatSessionEventKind::Cancelled )
    {
      CacheTerminal(kind);
    }
    else if ( !pending_error.empty() )
    {
      CacheTerminal(kind, pending_error);
    }
    else if ( event.kind == StreamEventKind::Closed )
    {
      CacheTerminal(kind, ProviderChatEarlyCloseMessage);
    }
    else if ( event.kind == StreamEventKind::Error )
    {
      CacheTerminal(kind, TransportSafeMessage(event));
    }
    else
    {
      CacheTerminal(kind, ProviderChatTransportErrorMessage);
    }
  }

  ProviderChatSessionEvent PublishTerminal()
  {
    if ( !terminal_event.has_value() || !client->Retire(stream_id) )
      return {};
    ProviderChatSessionEvent result = std::move(*terminal_event);
    LogAiNetworkDiagnostic("chat.drain", "peakQueuedEvents=" + std::to_string(peak_queued_events)
        + " peakQueuedBytes=" + std::to_string(peak_queued_bytes), 0, stream_id);
    peak_queued_events = peak_queued_bytes = 0;
    terminal_event.reset();
    active = false;
    client = nullptr;
    stream_id = 0;
    codec_completed = false;
    user_cancel_requested = false;
    transport_cancel_requested = false;
    text_bytes = 0;
    reasoning_bytes = 0;
    displayed_reasoning_bytes = 0;
    assistant_text.clear();
    pending_error.clear();
    accumulated_calls.clear();
    accumulated_call_indexes.clear();
    completed_calls.clear();
    return result;
  }

  ProviderChatSessionEvent Poll()
  {
    if ( !active )
      return {};
    if ( terminal_event.has_value() )
      return PublishTerminal();
    std::optional<StreamEvent> event = client->TryTakeEvent(stream_id);
    if ( !event.has_value() )
      return {};
    peak_queued_events = (std::max)(peak_queued_events, event->queued_events);
    peak_queued_bytes = (std::max)(peak_queued_bytes, event->queued_bytes);

    const auto progress = [] { return MakeEvent(ProviderChatSessionEventKind::Progress); };

    switch ( event->kind )
    {
      case StreamEventKind::Opened:
        return progress();
      case StreamEventKind::Sse:
      {
        auto decoded = Decode(event->sse);
        return decoded.kind == ProviderChatSessionEventKind::None
            ? progress() : std::move(decoded);
      }
      case StreamEventKind::Closed:
        CacheTransportTerminal(*event);
        return progress();
      case StreamEventKind::Cancelled:
        CacheTransportTerminal(*event);
        return progress();
      case StreamEventKind::Error:
        LogAiNetworkDiagnostic(
            "chat.transport.error", event->message, event->http_status, stream_id);
        CacheTransportTerminal(*event);
        return progress();
      case StreamEventKind::WebSocketText:
      case StreamEventKind::WebSocketBinary:
        FailAfterCancel(std::string(ProviderChatProtocolErrorMessage));
        return progress();
    }
    CacheTerminal(
        ProviderChatSessionEventKind::Error,
        ProviderChatTransportErrorMessage);
    return {};
  }

  ProviderChatSessionEvent Decode(const SseEvent &event)
  {
    if ( user_cancel_requested || !pending_error.empty() || codec_completed )
      return {};
    const ProviderChatDecodeResult decoded =
        DecodeProviderChatEvent(codec, event);
    if ( decoded.error )
    {
      LogAiNetworkDiagnostic(
          "chat.protocol.error", decoded.safe_message, 0, stream_id);
      FailAfterCancel(
          decoded.safe_message.empty()
              ? std::string(ProviderChatProtocolErrorMessage)
              : decoded.safe_message);
      return {};
    }
    for ( const ProviderToolCallUpdate &update : decoded.updates )
    {
      const UpdateStatus status = Accumulate(update);
      if ( status != UpdateStatus::Success )
      {
        FailAfterCancel(status == UpdateStatus::LimitError
            ? std::string(ProviderChatToolLimitMessage)
            : std::string(ProviderChatProtocolErrorMessage));
        return {};
      }
    }
    if ( decoded.text_delta.size()
        > text_limit - (std::min)(text_bytes, text_limit) )
    {
      FailAfterCancel(ProviderChatTextLimitMessage);
      return {};
    }
    if ( decoded.reasoning_delta.size()
        > text_limit - (std::min)(reasoning_bytes, text_limit) )
    {
      FailAfterCancel(ProviderChatTextLimitMessage);
      return {};
    }
    text_bytes += decoded.text_delta.size();
    reasoning_bytes += decoded.reasoning_delta.size();
    ReasoningParts visible = reasoning_filter.Push(decoded.text_delta);
    visible.reasoning.insert(0, decoded.reasoning_delta);
    if ( decoded.completed )
    {
      ReasoningParts trailing = reasoning_filter.Finish();
      visible.reasoning += trailing.reasoning;
      visible.text += trailing.text;
      if ( codec == ProviderChatCodec::OpenAIChatCompletions )
      {
        for ( AccumulatedToolCall &call : accumulated_calls )
          call.done = true;
      }
      if ( !FinalizeCalls() )
      {
        FailAfterCancel(std::string(ProviderChatProtocolErrorMessage));
        return {};
      }
      codec_completed = true;
      RequestTransportCancel();
    }
    assistant_text += visible.text;
    if ( show_reasoning
        && visible.reasoning.size()
            > text_limit - (std::min)(displayed_reasoning_bytes, text_limit) )
    {
      FailAfterCancel(ProviderChatTextLimitMessage);
      return {};
    }
    if ( show_reasoning )
      displayed_reasoning_bytes += visible.reasoning.size();
    else
      visible.reasoning.clear();
    if ( !visible.reasoning.empty() || !visible.text.empty() )
    {
      return MakeDeltaEvent(
          std::move(visible.reasoning), std::move(visible.text));
    }
    return {};
  }

  UpdateStatus Accumulate(const ProviderToolCallUpdate &update)
  {
    const auto position = accumulated_call_indexes.find(update.index);
    AccumulatedToolCall *found = position == accumulated_call_indexes.end()
        ? nullptr
        : &accumulated_calls[position->second];
    const bool has_data = update.id_delta.has_value()
        || update.id_snapshot.has_value()
        || update.name_delta.has_value()
        || update.name_snapshot.has_value()
        || update.arguments_delta.has_value()
        || update.arguments_snapshot.has_value()
        || update.empty_object_start;
    if ( found == nullptr )
    {
      // Claude emits block-stop events for text blocks too.
      if ( !has_data )
        return UpdateStatus::Success;
      accumulated_calls.push_back({update.index});
      accumulated_call_indexes.emplace(
          update.index, accumulated_calls.size() - 1);
      found = &accumulated_calls.back();
    }
    else if ( update.initialize )
    {
      return UpdateStatus::ProtocolError;
    }
    if ( found->done )
      return UpdateStatus::ProtocolError;
    UpdateStatus status = ApplyField(
        found->id, update.id_delta, update.id_snapshot,
        MaxAgentToolCallIdBytes);
    if ( status != UpdateStatus::Success )
      return status;
    status = ApplyField(
        found->name, update.name_delta, update.name_snapshot,
        MaxAgentToolNameBytes);
    if ( status != UpdateStatus::Success )
      return status;
    const bool possible_file_mutation = found->name.empty()
        || std::string_view("ida_file_mutate").substr(0, found->name.size()) == found->name;
    const std::size_t argument_limit = possible_file_mutation
        ? MaxAgentFileToolArgumentsBytes : MaxAgentToolArgumentsBytes;
    if ( found->arguments.size() > argument_limit ) return UpdateStatus::LimitError;
    status = ApplyField(
        found->arguments, update.arguments_delta, update.arguments_snapshot,
        argument_limit);
    if ( status != UpdateStatus::Success )
      return status;
    if ( update.empty_object_start )
    {
      if ( !found->arguments.empty() )
        return UpdateStatus::ProtocolError;
      found->empty_object_start = true;
    }
    if ( update.arguments_delta.has_value()
        || update.arguments_snapshot.has_value() )
    {
      found->empty_object_start = false;
    }
    found->done = update.done;

    return UpdateStatus::Success;
  }

  bool FinalizeCalls()
  {
    completed_calls.clear();
    if ( accumulated_calls.empty() )
      return true;
    std::sort(
        accumulated_calls.begin(), accumulated_calls.end(),
        [](const AccumulatedToolCall &left, const AccumulatedToolCall &right)
        {
          return left.index < right.index;
        });
    std::unordered_set<std::string> ids;
    for ( const AccumulatedToolCall &call : accumulated_calls )
    {
      if ( !call.done || call.id.empty() || call.name.empty() )
        return false;
      if ( !ids.insert(call.id).second )
        return false;
      const std::string arguments_text = call.arguments.empty()
          && call.empty_object_start ? "{}" : call.arguments;
      const nlohmann::json arguments =
          nlohmann::json::parse(arguments_text, nullptr, false);
      if ( arguments.is_discarded() || !arguments.is_object() )
        return false;
      completed_calls.push_back({call.id, call.name, arguments_text});
    }
    return true;
  }

  StreamClient *client = nullptr;
  StreamClient::StreamId stream_id = 0;
  ProviderChatCodec codec = ProviderChatCodec::OpenAIResponses;
  std::size_t text_bytes = 0;
  std::size_t peak_queued_events = 0, peak_queued_bytes = 0;
  std::size_t reasoning_bytes = 0;
  std::size_t displayed_reasoning_bytes = 0;
  std::string assistant_text;
  LeadingReasoningFilter reasoning_filter;
  const std::size_t text_limit;
  std::string pending_error;
  std::optional<ProviderChatSessionEvent> terminal_event;
  std::vector<AccumulatedToolCall> accumulated_calls;
  std::unordered_map<std::size_t, std::size_t> accumulated_call_indexes;
  std::vector<AgentToolCall> completed_calls;
  bool active = false;
  bool codec_completed = false;
  bool user_cancel_requested = false;
  bool transport_cancel_requested = false;
  bool show_reasoning = false;
};

ProviderChatSession::ProviderChatSession(std::size_t max_text_bytes)
    : impl_(std::make_unique<Impl>(max_text_bytes))
{
}

ProviderChatSession::~ProviderChatSession() = default;

bool ProviderChatSession::Start(
    StreamClient &client,
    ProviderChatBuildResult request)
{
  return impl_->Start(client, std::move(request));
}

ProviderChatSessionEvent ProviderChatSession::Poll()
{
  return impl_->Poll();
}

void ProviderChatSession::Cancel() noexcept
{
  impl_->Cancel();
}

bool ProviderChatSession::IsActive() const noexcept
{
  return impl_->active;
}

#ifdef IDA_AGENT_PROVIDER_CHAT_SESSION_TESTING
ProviderChatSessionEventKind SelectProviderChatTerminalKindForTesting(
    bool has_pending_error,
    bool codec_completed,
    bool user_cancel_requested,
    bool has_completed_calls) noexcept
{
  return SelectTerminalKind(
      has_pending_error,
      codec_completed,
      user_cancel_requested,
      has_completed_calls);
}
#endif

} // namespace ida_agent::ai
