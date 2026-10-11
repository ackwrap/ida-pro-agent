# AI Chat

The Agent-style message view and Effort selector are available in current source builds. They are not included in the previously published v0.4.8 package.

AI Chat opens as a full-height sidebar on the right of the IDA work area, beside the disassembly and Output panes. Its initial width is approximately one third of the main window, in Qt logical pixels. Drag the divider or dock title to resize or move it; opening an already visible chat activates it without changing its placement.

## Messages and rendering

The native Qt chat separates **You**, **AI**, **Context**, **Thinking**, **Tool** and **System** messages. Body text wraps to the panel width. Completed user, AI and context messages support GitHub-style Markdown, including headings, emphasis, lists, tables, inline code and fenced code blocks. Code uses IDA's fixed-width font; message and code backgrounds follow the panel palette. Compact spacing keeps system, tool and thinking labels on the first body line; user, AI and context messages retain a separate role header. Small card padding and message gaps leave more room for content without reducing the body font size.

Right-click within a message for **Copy Message**, which copies its complete raw text, including Markdown. Right-click a formatted code block for **Copy Code**. Ordinary selection/copy still works across messages. Selecting a mapped hexadecimal address or known symbol continues to offer **Jump To** in the same menu.

During a response, text appears incrementally in the active message. Markdown is parsed once when the message completes. Each timer flush inserts at most 16 KiB across thinking and reply previews; it does not reparse previous messages. Completion replaces only the active body. When you scroll up, new output preserves your viewport and selection in retained messages. Output follows the latest message while you are already at the bottom.

The display keeps the latest messages within **256 messages / 512 KiB of rendered text**. A single body displays at most **64 KiB / 1,000 lines**, with an explicit display-limit notice and complete text available through Copy Message. Markdown parsing is limited to **32 KiB / 500 lines**; larger bodies or lines over 4 KiB use plain text. Plain display splits overlong lines at UTF-8 boundaries into paragraphs of at most 4 KiB to keep Qt layout responsive; Copy Message retains the original lines. These are display limits. Raw transcript/context/history retain their existing policies (up to 4 MiB / 5,000 history entries), and persistent storage still depends on the Save Chat History setting. Older display frames are removed incrementally; opening a stored conversation materializes only the visible tail.

Provider HTML is disabled and image/resource paths and URLs are not loaded. The view uses IDA's bundled Qt and needs no browser runtime.

## Reasoning effort

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

The **ida_ai_chat_ui_model** test also covers lazy line-cache rollback, clipping and UTF-8 boundaries. To exercise Markdown, actual Copy Code/Copy Message actions, 400 restored messages, a roughly 270 KiB response with an unbroken 70,000-character line, bounded renderer operations, selection/scroll preservation and GUI heartbeat timing in the real Linux panel, run:

```shell
python3 ida-agent-plugin/tests/integration/run_linux_panel.py \
  --ida-dir /path/to/ida-pro-9.4 \
  --plugin /path/to/build/ida-runtime/plugins/ida-agent-plugin.so \
  --render-check --scale-factor 1.5
```

The runner records screenshots, geometry, renderer counters and timing in its disposable artifact directory. It reads SQLite only from the outer process while IDA is running. Its HTML/resource fixture and provider use isolated test data; global user settings and databases are unaffected.
