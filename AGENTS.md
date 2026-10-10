# Repository Guidelines

## Directory Boundaries

- `ida-sdk/` is a pinned Hex-Rays SDK submodule, not project-owned source code. Initialize it with `git submodule update --init ida-sdk`; do not modify it unless the task explicitly targets the SDK.
- `ida-mcp/` is a Go 1.25 MCP server. `main.go` connects stdio or loopback-only Streamable HTTP to the discovery and bridge code in `ida/` and the 12 direct tools plus 11 domain tools in `mcp/`.
- `ida-agent-plugin/` is a C++17 IDA plugin: Windows includes AI/Qt by default; Linux x86_64 supports basic MCP and an opt-in AI/Qt panel (`IDA_AGENT_ENABLE_AI=ON`). `plugin.cpp` assembles services and RPC handlers; Named Pipe/Unix socket workers must not call IDA APIs directly. All IDA/Hex-Rays operations must go through `IdaExecutor`.
- `protocol/` is the sole language-independent source of truth for the protocol between Go and C++. Protocol objects reject unknown fields, addresses use hexadecimal strings, and both implementations must share the fixtures in `protocol/testdata`.

## Documentation Boundaries

- Maintain architecture designs, development and implementation plans, and internal capability plans locally; do not commit them to Git. Place new documents of these types in `docs/local/`. The root `docs/` directory is ignored by default; `.gitignore` currently allows only `docs/UPGRADING.md`. Explicitly allow any new required public documents and their assets before linking to or committing them.
- Continue tracking READMEs, upgrade notes, interface contracts in `protocol/`, testing instructions, and reference documentation in `skills/`.

## C/C++ Source Organization

- Each project-owned `.c`, `.cc`, `.cpp`, `.h`, or `.hpp` file must not exceed 800 physical lines. Split files by responsibility before they approach the limit. Files for the same feature, such as models, stores, transports, and UI components, may be grouped in a dedicated directory for easier navigation and maintenance.
- C++ source and header files matching `ida-agent-plugin/ai/agent_*` have a limit of 1500 physical lines per file. This exception applies only to Agent implementations whose filenames start with `agent_`; all other project-owned C/C++ files remain subject to the 800-line limit.
- Apply this rule to new code and subsequent changes. Do not refactor existing files that already exceed 800 lines solely to meet the limit. When a later task requires modifying such a file, first split the relevant responsibilities along functional boundaries; do not keep adding implementation to a file that exceeds the limit.
- Splitting files must preserve behavior and include running the documented builds and tests for the affected scope. Do not split functions mechanically just to meet a line count, or use this rule as a reason to modify `ida-sdk/`, generated code, or third-party source code.
- Once the split and its validation are complete, commit the split immediately before continuing with feature changes. Do not leave large refactors mixed with subsequent feature work in the same working tree for an extended period.

## Review and Commits

- After completing a coding task, perform a final review and run the required validation for the affected scope. If the final review has no P0/P1/P2 findings and validation passes, commit the files involved in the task directly without asking for confirmation again. Do not commit if there are blocking issues or validation failures.

## Changes Across Boundaries

- When adding an RPC, update the protocol schemas and fixtures, C++ services and handler registration, Go bridge DTO and client validation, backend interfaces, and MCP catalog, schema, and typed handler tests together. Do not add a generic RPC forwarding path that lets callers specify the method.
- Keep MCP separate from Internal RPC: the plugin accepts only inline source code for `script.execute`. The gateway's optional file-path reading and client permission policies must never cross the Pipe boundary.
- Externally exposed opaque cursors are wrapped with HMAC by the gateway and bound to the instance, method, and normalized filters. Cursors intentionally become invalid when the gateway restarts; do not expose raw Internal RPC cursors.

## Gateway Validation

Run from the repository root:

```shell
gofmt -w <changed-go-files>
go -C ida-mcp vet ./...
go -C ida-mcp test ./...
go -C ida-mcp build ./...
```

- Use `go -C ida-mcp test ./mcp -run '^TestName$'` to target a single package or test, replacing `./mcp` as needed.
- `mcp-test-project/verify_stdio.py <gateway-executable>` verifies stdio initialization, all 23 underscore-named direct and domain tools, empty discovery with an isolated instance directory, and clean exit after stdin EOF; no IDA installation is required. Run `mcp-test-project/verify_compatibility.py <gateway-executable> --http` for isolated protocol-version, error-recovery, text/structured result and HTTP checks.

## Plugin Validation

- Build in an MSVC 2022 environment with CMake >= 3.25 and Ninja available:

```shell
cmake -S ida-agent-plugin -B build/ida-agent-plugin -G Ninja
cmake --build build/ida-agent-plugin
ctest --test-dir build/ida-agent-plugin --output-on-failure
```

- Use `ctest --test-dir build/ida-agent-plugin -R '^ida_rpc_envelope$' --output-on-failure` to target a single CTest; see `ida-agent-plugin/CMakeLists.txt` for registered test names.
- By default, CTest covers only pure unit tests. Tests with a real IDA installation require a separate configuration with `-DIDA_AGENT_ENABLE_INTEGRATION_TESTS=ON -DIDA_INSTALL_DIR=<ida-dir>`, plus `idat.exe`, PowerShell 7, Go, Python, and a valid IDA/Hex-Rays license. These tests use the labels `integration;slow`.
- A live RPC smoke test requires an enabled plugin instance: `go -C ida-mcp run ./cmd/ida-agent-rpc-ping -database-info`. Use `-instance-dir` or `IDA_AGENT_INSTANCE_DIR` to override the discovery directory only in tests; production uses `%LOCALAPPDATA%\ida-agent\instances`.

## IDA Qt UI

- Linux build/test instructions are in `ida-agent-plugin/README-LINUX.md`. Linux uses registry v2 and private Unix sockets in `/tmp/ida-agent-<uid>/instances`; Windows retains registry v1. Both implementations must continue accepting the shared protocol fixtures. Linux real-IDAT integration is opt-in and uses an isolated `IDAUSR` and test IDB. The Linux panel links IDA 9.4's Qt 6.8.2 in namespace `QT` and uses official Linux headers under the ignored `qt-sdk/qt-6.8.2-linux` (or `IDA_AGENT_QT_SDK_DIR`); never bundle Qt `.so` files. Real panel tests use `IDA_AGENT_ENABLE_GUI_TESTS=ON` and a working GUI session. Linux libcurl/SQLite stay static and private, while OpenSSL 3 stays a system dependency.

- The AI UI supports only Qt 6.8.2 bundled with IDA Professional 9.4 and uses IDA's `QT` namespace. `qt-sdk/qt-6.8.2-win` provides only headers and configuration. Default builds link the official Qt import libraries in the pinned `ida-sdk/src/lib/x64_win_qt` submodule; no IDA installation is required to compile or package. An explicit `IDA_AGENT_IDA_QT_RUNTIME_DIR` overrides those imports by generating them from the installed IDA DLLs and validating IDA 9.4, Qt 6.8.2, and the `QT` namespace. Builds and releases must not copy or bundle `Qt6*.dll`.
- IDA's bundled Qt uses the Release DLL CRT. When the Qt AI Console is enabled, Debug builds of the plugin and its static dependencies must also use `/MD` (`MultiThreadedDLL`), never `/MDd`. Otherwise, objects passed across module boundaries and owned and freed by Qt containers, such as `QTreeWidgetItem` and `QTableWidgetItem`, can trigger `_CrtIsValidHeapPointer`.
- Convert the `TWidget` returned by `create_empty_widget()` to `QT::QWidget` for use in the Qt UI. All Qt and IDA UI operations must run on IDA's main thread; Named Pipe workers must not access widgets.
- Global Plugin Settings reside in `%LOCALAPPDATA%\ida-agent\ai\settings.json` and must not be written to the IDB. Automatically opening AI Chat must wait for `ui_ready_to_run`; do not create Qt widgets during plugin construction.
- Do not infer layout offsets from screenshots. With IDA 9.4's default style, the measured baseline for side-by-side docks of equal height is `y=0, h=486` for the native Output content area and `y=488, h=21` for `CLILineEdit`. The AI Console should preserve the same relative geometry. `ChatPanel` currently uses a bottom margin of `2` and spacing of `2` for this purpose. After changing the layout, use PySide6's `ida_kernwin.PluginForm.TWidgetToPyQtWidget()` to compare the relative geometry of widgets on both sides, and verify DPI and theme behavior in a real IDA instance.
- Global AI actions must use the global `plugin_t PLUGIN` as their owner and include `ADF_OT_PLUGIN | ADF_GLOBAL`. During `ui_about_to_exit`, only call `ai_menu_.Stop(false)` to close the panel and detach/delete the menu, allowing IDA to reclaim the actions through their owner. A normal `ui_database_closed` must still perform the full `Stop(true)`. Do not manually unregister global actions again during exit, as this can cause `0xC0000374` heap corruption.
- A previously confirmed exit failure was caused by global AI actions using `owner=nullptr`: IDA encountered `0xC0000374` heap corruption while cleaning up actions on exit, and the abnormal termination appeared as a very slow shutdown. Pipe shutdown measured only `0-1ms` at the time and was not the source of the delay. If slow exits recur, first check `%LOCALAPPDATA%\ida-agent\diagnostics\shutdown.log` and the process exit code; do not attribute the problem to Named Pipe again without evidence.
- Debug builds deploy automatically to `%APPDATA%\Hex-Rays\IDA Pro\plugins\ida-agent-plugin.dll` by default; Release builds and release packaging do not deploy automatically. For validation with a real Release build, explicitly copy the DLL after IDA has fully exited, and compare the SHA-256 hashes of the build artifact and the deployed file. Do not claim deployment succeeded based only on a successful build.

## Releases

- Use `python release/build_release.py --clean` to build the complete Windows x64 release package. This script intentionally disables plugin tests and builds a stripped `windows/amd64` gateway with CGO disabled, so validation must run first.
- Intermediate release artifacts go in `build/release/`; the final directory and ZIP go in the ignored `release/dist/` directory. Do not commit files from either location.
