# AI Chat

The Agent-style message view, Effort selector, shared response rules, unavailable-tool recovery and cached project instructions are included in v0.4.9 and later packages.

AI Chat opens as a full-height sidebar on the right of the IDA work area, beside the disassembly and Output panes. Its initial width is approximately one third of the main window, in Qt logical pixels. Drag the divider or dock title to resize or move it; opening an already visible chat activates it without changing its placement.

In current source builds, **Ctrl+Shift+A** invokes **Open AI Chat** and focuses the input. Repeating it reuses the panel without resetting the conversation or draft. The action remains available from **Edit → Plugins → IDA Agent → Open AI Chat**; customize `ida-agent:ai:open` in IDA's shortcut settings if another plugin uses the same key. It is enabled when an IDB is open and will be included in the next release after v0.4.10.

## Messages and rendering

The native Qt chat labels roles with **👤 You**, **🤖 AI**, **📌 Context**, **💭 Thinking**, **🔧 Tool** and **⚙️ System**. Body text wraps to the panel width. Completed user, AI and context messages support GitHub-style Markdown, including headings, emphasis, lists, tables, inline code and fenced code blocks. Code uses IDA's fixed-width font; message and code backgrounds follow the panel palette. Completed code blocks highlight C/C++ (including common Hex-Rays pseudocode types), Python, x86/ARM assembly and JSON keywords, types/registers, strings, comments, numbers and function names. Fence language tags select the syntax; unlabelled blocks use conservative detection, and unknown explicit languages retain plain code styling. Syntax colors adapt to light/dark palettes and code-background contrast. Compact spacing keeps system, tool and thinking labels on the first body line; user, AI and context messages retain a separate role header. Messages are separated by approximately one third of the current font's line spacing, with modest card padding and subdued borders. The gap follows font and display scaling; emoji labels are display decorations and are excluded from Copy Message, saved history and provider content.

Right-click within a message for **Copy Message**, which copies its complete raw text, including Markdown. Right-click a formatted code block for **Copy Code**. Ordinary selection/copy still works across messages. Selecting a mapped hexadecimal address or known symbol continues to offer **Jump To** in the same menu.

During a response, text appears incrementally in the active message. Markdown is parsed once when the message completes; code highlighting is then applied as native display overlays. Multiline comments and strings retain state within each code group. Highlighting is limited to 256 spans per line and 4,096 per message, without changing the original text or clipboard data. Each timer flush inserts at most 16 KiB across thinking and reply previews; it does not reparse previous messages. Completion replaces only the active body. When you scroll up, new output preserves your viewport and selection in retained messages. Output follows the latest message while you are already at the bottom.

The display keeps the latest messages within **256 messages / 512 KiB of rendered text**. A single body displays at most **64 KiB / 1,000 lines**, with an explicit display-limit notice and complete text available through Copy Message. Markdown parsing is limited to **32 KiB / 500 lines**; larger bodies or lines over 4 KiB use plain text. Plain display splits overlong lines at UTF-8 boundaries into paragraphs of at most 4 KiB to keep Qt layout responsive; Copy Message retains the original lines. These are display limits. Raw transcript/context/history retain their existing policies (up to 4 MiB / 5,000 history entries), and persistent storage still depends on the Save Chat History setting. Older display frames are removed incrementally; opening a stored conversation materializes only the visible tail.

Provider HTML is disabled and image/resource paths and URLs are not loaded. The view uses IDA's bundled Qt and needs no browser runtime.

## Response and tool behavior

Ordinary chat and tool-enabled chat share instructions to answer in the user's language, lead with the finding and explain the evidence and uncertainty using compact Markdown. Fenced code should include a language such as `cpp`, `python`, `asm` or `json`, so the renderer can select its syntax. Role labels already come from the UI. With Tools disabled, the assistant receives explicit instructions to explain supplied material and identify questions that require IDA tools; it must not claim to have inspected or changed the database.

Project instructions are checked once on first use in the current IDB directory, in this order: `AGENTS.md`, `Agents.md`, then `agents.md`. The project session caches the result, including a missing or unreadable file; later requests, context accounting, new conversations and compaction reuse it. Changes are read after switching projects, reopening the database or running `/instructions reload`. Use `/instructions` to inspect the cached file status. Both commands require an idle chat. Discovery uses the existing safe file service and stays inside the IDB directory.

A complete UTF-8 instruction file up to **32 KiB** accompanies the latest user request as designated project context, with only its path/status metadata in the system prompt. It is retained as required context, so an insufficient model budget rejects the request instead of silently cropping project rules. The on-screen user message and saved transcript retain the original question. Applicable project conventions take priority over historical notes and model assumptions; current user instructions and the live **Ask / Allow / Deny** policy retain priority. For files in a subdirectory, the agent is instructed to read more specific instruction files and apply their scope. Files above the automatic-read cap receive an explicit `needs_read` marker for bounded file-tool reads when their instructions are not already known; detected non-text or unreadable files receive an `unavailable` marker.

The built-in agent initially advertises a compact core catalog. Its instructions route discovery through `ida_tool_search` using short English capability terms or an exact underscore-named tool, including for non-English questions. Newly discovered schemas become callable in the next round. Unknown or unloaded tool calls return `unknown_tool` or `tool_not_loaded` errors without dispatching an operation, so the model can correct its search and retry. A search and an unloaded write in the same batch still leave that write unexecuted. At most three rounds containing unavailable calls are allowed per request; a fourth stops before any call in that round executes. Corrected writes still follow the conversation's **Ask / Allow / Deny** policy.

Analysis instructions ask the model to confirm the binary and target, collect relevant code and references within bounded queries, and distinguish observations, inferences and hypotheses. Protection assessments should explain attacker goals, observed checks, coverage and bypass prerequisites; imports or strings alone do not prove execution. When decompilation is unavailable, the model is directed to discover disassembly tools and state the resulting limits. These instructions guide the provider; they do not guarantee a model's conclusions are correct.

The complete tool-enabled system prompt, project file metadata, active workflow and retrieved memory share the existing **8 KiB UTF-8 byte limit**. Built-in rules and workflow steps take priority; memory uses the remaining bytes as complete records. Ordinary-chat rules also count toward the displayed context usage. Context compaction has dedicated system instructions to retain goals, constraints, concrete symbols and addresses, successful observations, failed or denied actions, evidence limits and unresolved hypotheses. Remembered approvals do not replace the live session policy.

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

Add `--recovery-check` to verify the assembled system prompt and a same-round search, unloaded write and unknown call against the real plugin. The loopback provider checks the returned errors, absence of the blocked file, later tool advertisement and a normal approved write. This checks runtime recovery and request assembly using deterministic provider responses; it does not measure live-model analysis quality.

Add `--instructions-check` to verify project guidance is already present in the first request, later independent requests reuse the original cached text after the file changes, and `/instructions reload` supplies the updated text.

The runner records screenshots, geometry, renderer counters and timing in its disposable artifact directory. It reads SQLite only from the outer process while IDA is running. Its HTML/resource fixture and provider use isolated test data; global user settings and databases are unaffected.
