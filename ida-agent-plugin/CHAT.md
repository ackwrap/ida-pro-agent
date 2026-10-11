# AI Chat reasoning effort

The Effort selector is available in current source builds, beside the chat input. It is not included in the previously published v0.4.8 package.

Configure a provider and enabled default model in **Provider Settings...**, then open **Open AI Chat**. Select an effort before sending a message:

| Choice | Request behavior |
| --- | --- |
| Default | Let the provider/model choose; omit the effort parameter |
| None | Request `none` |
| Low / Medium / High | Request `low`, `medium` or `high` |
| XHigh / Max | Request `xhigh` or `max` |

The available explicit levels depend on your provider and model. The selector reuses the effort values offered by Provider Manager; it does not claim every model accepts every level. If the service rejects an explicit level, choose a supported level or Default.

A selection saves **Reasoning Effort** for the current provider/model and is also visible in Provider Manager. It applies to later messages and every tool round of the next agent request. Other open chats using the same provider/model reflect the saved setting. New conversations and application restarts retain it. Reasoning effort is independent of **Reasoning Summary/Display** and the **Ask / Allow / Deny** side-effect policy.

The selector is disabled while a request, tool round, approval or context compaction is active. A settings/model change made from another window refreshes the selector; a stale selection is rejected instead of being applied to another model. Failed saves restore the previous selection.

OpenAI-style **Responses** and **Chat Completions** use the existing effort request formats. The current Claude **Messages** transport does not send effort configuration, so its selector is disabled with an explanation. Models accessed through a compatible service still require that service to support the selected field/value.

The chat input and Effort selector share one compact bottom row. The selector follows the chat input's Qt style/font height, and the existing bottom margin and spacing are preserved. The choice is saved in global provider settings outside the IDB. All Qt updates run on IDA's UI thread.

For analysis memory and workflows, see [ANALYSIS.md](ANALYSIS.md).

## Validation

The pure `ida_ai_chat_reasoning` test checks active-model identity, settings revisions, busy/unsupported states and save/load persistence. Provider request tests check selector-to-request serialization. The opt-in real Linux panel runner also verifies every tool round, Default omission, close/reopen/restart, native CLI geometry and light/dark colors applied to the disposable panel. These color checks exercise scoped Qt style changes rather than changing the user's IDA theme. Run it with `--scale-factor 1.5` to exercise scaled Qt rendering; it uses an isolated IDA user, test database and loopback provider.
