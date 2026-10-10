# Linux / WSL2 MCP and AI panel

> **This Linux version has not been comprehensively tested. Please [report bugs](https://github.com/ackwrap/ida-pro-agent/issues) with your distribution, CPU architecture, IDA version, and reproduction steps.**
>
> **Linux 版本尚未经过全面测试。如遇问题，请[提交 Bug / Issue](https://github.com/ackwrap/ida-pro-agent/issues)，附上发行版、CPU 架构、IDA 版本和复现步骤。**

This is a preview for **Ubuntu 24.04 x86_64 and Linux IDA Professional 9.4**.
The published `*-linux-x64.tar.gz` includes the Gateway and full AI Chat plugin;
see the [package installation guide](../release/linux/INSTALL.md).
It provides the native `.so` plugin and Linux Gateway, using Unix domain sockets.
Linux also supports the docked AI Chat, Provider Manager, settings, Agent tools,
approval and conversation history with `IDA_AGENT_ENABLE_AI=ON`.
The default Linux build remains basic MCP (`IDA_AGENT_ENABLE_AI=OFF`), so it needs
no Qt SDK or installed IDA to compile. Windows builds the AI/Qt plugin by default.
WSL1 and connecting this Linux Gateway to Windows IDA are not supported. For macOS, see [Universal 2 build and usage](README-MACOS.md).

## Linux environment requirements

The baseline below is the project's tested development environment, not a claim
about the minimum requirements of IDA or every Linux distribution.

| Component | Requirement | Locally verified |
| --- | --- | --- |
| OS / architecture | Ubuntu 24.04 LTS, x86_64; WSL2 for Windows-hosted development | Ubuntu 24.04.1 LTS in WSL2, distribution `Ubuntu-24.04` |
| IDA runtime | Linux IDA Professional 9.4 with a valid license; matching Hex-Rays license for decompilation | IDA / IDAT 9.4, real ELF analysis and local debugger tests |
| C/C++ toolchain | C and C++17 compiler, CMake 3.25+, Ninja | GCC 13.3.0, CMake 3.28.3, Ninja 1.11.1 |
| Gateway | Go 1.25+ | Go 1.25.0 vet/test/build; development toolchain 1.26.5 |
| Test scripts / IDAPython | Python 3 and IDA's configured Python runtime | Python 3.12.3; `idapyswitch --auto-apply` |
| SDK | Pinned `ida-sdk` submodule initialized | SDK commit recorded by the repository; do not substitute an unrelated SDK |
| Optional AI backend | System OpenSSL 3 development files and CA certificates; pinned libcurl and SQLite sources are fetched and built statically | Embedded libcurl 8.22.0 and SQLite 3.53.4; system OpenSSL 3.0.13 |
| AI networking tests | OpenSSL CLI, Python `websockets` with its legacy server API, and `readelf` | Ubuntu `openssl`, `python3-websockets` 10.4, `binutils` |
| AI panel development | Official Linux Qt 6.8.2 headers/mkspecs, `libgl-dev`, and IDA 9.4's `QT`-namespaced Qt runtime | Qt 6.8.2 from the official Qt archive; IDA's `libQt6{Core,Gui,Widgets}.so.6` |
| Filesystem | Native Linux filesystem supporting Unix sockets, permissions, file locking and atomic rename | Build, temporary IDBs, configuration and state under Linux `/home` or `/tmp` |

Install basic build dependencies in Ubuntu:

```sh
sudo apt-get update
sudo apt-get install -y build-essential cmake ninja-build git python3 python3-dev pkg-config ca-certificates
```

Install Go 1.25 or newer separately if `go version` reports an older version.
For the optional, independent AI backend:

```sh
sudo apt-get install -y libssl-dev ca-certificates
# Additional local test fixtures when BUILD_TESTING=ON:
sudo apt-get install -y openssl python3-websockets binutils
pkg-config --modversion openssl
```

The AI backend does not require system libcurl or SQLite development packages.
The basic MCP build does not require these AI development packages or a Qt SDK.
GUI use requires a functioning X11/Wayland session; WSLg is sufficient for the
tested WSL2 setup, without installing a full desktop environment. Runtime XCB,
XKB and OpenGL dependencies must be available for the installed IDA. Check missing
libraries with `ldd /absolute/path/to/ida` and the bundled Qt platform plugin.
For the tested Ubuntu installation, the additional GUI runtime packages are:

```sh
sudo apt-get install -y libxcb-cursor0 libxkbcommon-x11-0 libxcb-xinerama0 \
  libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-render-util0 libegl1 libopengl0
# Required for Chinese/Japanese/Korean text on minimal WSL installations:
sudo apt-get install -y fonts-noto-cjk
```

Headless IDAT still requires an IDA license and a configured Python runtime for
the integration tests. Keep all licenses in the installed IDA environment.

Build from the repository root with Linux tools. In WSL, explicitly select the
correct distribution and Linux user; Windows Go/CMake/Python executables are not
a substitute for the Linux toolchain. Prefer a Linux build directory over `/mnt/c`
or `/mnt/h`, and keep private state and socket directories on the Linux filesystem.

## Build and validate

Use CMake 3.25+, Ninja, a C++17 compiler, Go 1.25+, and the pinned SDK submodule.
The basic plugin needs no Qt development package and must not ship IDA/Qt binaries.
Prefer a checkout and build directory on the WSL Linux filesystem.

```sh
git submodule update --init ida-sdk
export IDASDK="$PWD/ida-sdk/src"
cmake -S ida-agent-plugin -B build/linux-plugin -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DIDA_AGENT_ENABLE_AI=OFF \
  -DIDA_AGENT_DEPLOY_DEBUG_USER_PLUGIN=OFF -DBUILD_TESTING=ON
cmake --build build/linux-plugin --parallel "$(nproc)"
ctest --test-dir build/linux-plugin --output-on-failure
go -C ida-mcp vet ./...
go -C ida-mcp test ./...
go -C ida-mcp build ./...
mkdir -p build/linux
go -C ida-mcp build -o ../build/linux/ida-mcp .
```

Plugin output: `build/linux-plugin/ida-runtime/plugins/ida-agent-plugin.so`.
Stop IDA before replacing an installed plugin. Install for the current Linux user:

```sh
install -Dm755 build/linux-plugin/ida-runtime/plugins/ida-agent-plugin.so \
  "${IDAUSR:-$HOME/.idapro}/plugins/ida-agent-plugin.so"
sha256sum build/linux-plugin/ida-runtime/plugins/ida-agent-plugin.so \
  "${IDAUSR:-$HOME/.idapro}/plugins/ida-agent-plugin.so"
```

Open a database in Linux IDA; the plugin publishes its instance automatically.
The plugin menu action can also start the bridge. IDA and required decompilers need
valid licenses. Configure IDAPython with the installation's `idapyswitch` if needed.

## Build the AI panel

Install the AI backend dependencies above, plus `libgl-dev` for the Qt headers
and `7zip` to extract the official development archive. Download **only the matching
6.8.2 Linux development files**; Ubuntu's stock Qt version is not a substitute.
Run from the repository root:

```sh
sudo apt-get install -y libgl-dev 7zip curl
mkdir -p build qt-sdk/qt-6.8.2-linux
curl --fail --location --proto '=https' --proto-redir '=https' \
  -o build/qtbase-6.8.2-linux.7z \
  'https://download.qt.io/online/qtsdkrepository/linux_x64/desktop/qt6_682/qt6_682/qt.qt6.682.linux_gcc_64/6.8.2-0-202501260838qtbase-Linux-RHEL_8_10-GCC-Linux-RHEL_8_10-X86_64.7z'
printf '%s\n' '3283e68b777f42bc1f9eb05dfd7d5a6543714472a25c79ae559cd9f12d50b8d7  build/qtbase-6.8.2-linux.7z' | sha256sum -c -
7zz x build/qtbase-6.8.2-linux.7z -oqt-sdk/qt-6.8.2-linux 'include/*' 'mkspecs/*'
cmake -S ida-agent-plugin -B build/linux-panel -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DIDA_AGENT_ENABLE_AI=ON \
  -DIDA_AGENT_IDA_QT_RUNTIME_DIR=/absolute/path/to/ida-pro-9.4 \
  -DBUILD_TESTING=ON -DIDA_AGENT_DEPLOY_DEBUG_USER_PLUGIN=OFF
cmake --build build/linux-panel --parallel "$(nproc)"
ctest --test-dir build/linux-panel --output-on-failure
```

`IDA_AGENT_QT_SDK_DIR` overrides the header directory. These development files stay
local and ignored by Git. CMake checks the exact Qt version and `QT` namespace and
links the **installed IDA runtime**; never copy stock Qt libraries into IDA or bundle
IDA's Qt libraries with the plugin. The AI backend is enabled automatically for this
build, retaining static libcurl/SQLite and system OpenSSL. This development build is
linked to the selected IDA installation; reconfigure if that installation moves.

Install `build/linux-panel/ida-runtime/plugins/ida-agent-plugin.so` in the same user
plugin directory shown above after closing IDA, and compare hashes. Open a database,
then use **Edit → Plugins → IDA Agent → Open AI Chat** or **Provider Settings...**.
The panel supports streaming replies, cancellation, `/history`, `/session`, and the
same Agent tool approval flow as Windows. Provider settings and history stay outside
the IDB in the XDG locations below.

File tools operate relative to the current IDB directory, which must be on a native
Linux filesystem, owned by the current user, and not writable by group/others.
Paths are case-sensitive. Symlinks, hard-linked files, devices/FIFOs, IDA database
components and sensitive configuration paths are rejected. Writes revalidate the
approved identity/content and parent directory; recursive deletion is bounded.
Linux file locks are advisory: avoid editing, renaming or moving these files while
an approved operation runs. Failures after a partial effect report uncertain state.

For the real GUI regression, use a working WSLg/X11/Wayland session and licensed IDA:

```sh
cmake -S ida-agent-plugin -B build/linux-panel -DIDA_AGENT_ENABLE_GUI_TESTS=ON
ctest --test-dir build/linux-panel -R '^ida_linux_panel_integration$' --output-on-failure
```

This test launches disposable IDA windows with isolated `IDAUSR`, XDG configuration,
state and IDBs. It saves screenshots and measured widget geometry in the printed
temporary artifact directory; exercises settings, a loopback streaming provider,
an IDA read tool, file approval, cancellation, dock reopening, history restoration,
and normal GUI shutdown. It never uses real provider credentials. The shared Agent,
file-service and UI-model tests also run in backend-only CI without Qt or an IDA license.

## Independent AI backend development

Add `-DIDA_AGENT_BUILD_AI_BACKEND=ON` to the CMake configure command to build
`ida_ai_backend` and its tests while keeping `IDA_AGENT_ENABLE_AI=OFF`. This is a
non-UI development library: it does not enable AI Chat in the installed plugin.
The backend currently includes provider configuration, plugin settings, history
serialization, SQLite conversation/session persistence, HTTP requests, provider
model discovery, SSE and WS/WSS streaming, and provider chat request/decoder/session
logic (OpenAI Responses, Chat Completions, and Claude Messages). It needs no Qt SDK.

[`LinuxAiDependencies.cmake`](cmake/LinuxAiDependencies.cmake) pins the official
[libcurl 8.22.0 source](https://curl.se/download/curl-8.22.0.tar.xz) and
[SQLite 3.53.4 amalgamation](https://sqlite.org/2026/sqlite-amalgamation-3530400.zip)
with SHA-256 checksums. CMake downloads them into the build tree and compiles private
static libraries. OpenSSL 3 (`libssl.so.3` / `libcrypto.so.3`) and the CA store remain
system dependencies. No system libcurl/SQLite is replaced, and no Qt/IDA SDK files
are modified. A first configure needs access to these official source archives;
offline builds can supply verified extracted sources through
`FETCHCONTENT_SOURCE_DIR_IDA_CURL` and `FETCHCONTENT_SOURCE_DIR_IDA_SQLITE`.

libcurl enables only **HTTP, HTTPS, WS and WSS**, with HTTP/1.1, IPv6, threaded DNS,
HTTP proxy/CONNECT and Basic/Digest/NTLM authentication. Unused protocols, SSH,
Cookie storage, netrc, MIME, DoH, HTTP/2/3 and compression libraries are disabled.
SSE uses the HTTP transport. SQLite retains serialized threading, transactions,
foreign keys and WAL; dynamic extension loading is disabled. Third-party symbols
are hidden from shared consumers to avoid collisions with host libraries.
The curl archive includes its `COPYING` license; SQLite is
[in the public domain](https://sqlite.org/copyright.html).

```sh
ctest --test-dir build/linux-plugin -R '^ida_ai_' --output-on-failure
```

Settings use `${XDG_CONFIG_HOME:-$HOME/.config}/ida-agent/ai/{settings,providers}.json`;
history uses `${XDG_STATE_HOME:-$HOME/.local/state}/ida-agent/ai/chat.db`.
Relative XDG values are ignored, following the
[XDG Base Directory Specification](https://specifications.freedesktop.org/basedir/latest/).
The backend creates private directories (`0700`) and files (`0600`), rejects
unsafe permissions, symlinks and hard-linked storage files, and writes settings
by atomic replacement. API keys and proxy credentials remain plaintext within
the private provider file. Linux database identity preserves case and resolves
symlink aliases. The history schema and legacy-session migration match Windows.

HTTP requests use libcurl with certificate and hostname verification, bounded
response sizes, separate connect/send/receive timeouts, and responsive cancellation.
Redirects are returned to the caller without being followed. `System` proxy mode
uses libcurl's proxy environment variables; `Direct` ignores them. Explicit HTTP
proxies support authentication and HTTPS CONNECT. The explicit proxy's local bypass
covers `localhost`, `127.0.0.1` and `::1`. For a custom trust store, absolute
`SSL_CERT_FILE` / `SSL_CERT_DIR` paths override the CA file/directory; verification
remains enabled. These backend settings do not change the installed IDA's Qt runtime.

The loopback HTTP test creates its own temporary CA/certificate and proxy fixtures;
it does not use real API keys, modify system trust, or call an external provider.
It checks trusted/untrusted TLS, wrong hostnames, HTTP status handling, credential
separation, timeouts, cancellation, request bodies and provider model discovery.
Streaming tests cover fragmented UTF-8, SSE metadata and multiline events, WS text
and binary messages, PING/PONG between fragments, close handshakes, invalid frames,
bounded queues and payloads, connect/send/idle/overall deadlines, cancellation,
shutdown, TLS validation and authenticated proxies. SSE POST requests are not
automatically replayed or reconnected. Provider session tests exercise incremental
text/reasoning, tool calls, completion, error handling and nonblocking retirement.

Optional logs use `${XDG_STATE_HOME:-$HOME/.local/state}/ida-agent/logs` with private
directories/files. Network exchange logs are opt-in and contain request/response
content, matching the Windows logging model.

## MCP clients

For a Linux client, configure the absolute path to the built `ida-mcp` executable as
the stdio command. For a Windows client connecting to IDA in Ubuntu WSL2:

```json
{
  "mcpServers": {
    "ida-linux": {
      "command": "wsl.exe",
      "args": ["-d", "Ubuntu-24.04", "--exec", "/absolute/linux/path/ida-mcp"]
    }
  }
}
```

The Gateway must run in the same distribution and Linux user account as IDA.
Both stdio and explicit loopback HTTP (`-transport http -listen 127.0.0.1:8743`) are
supported. `-web` prints the local manager URL and remains in the foreground until
Ctrl+C/SIGTERM; Linux has no system tray integration. Windows-side configuration
files should use the WSL command above, rather than a raw ELF executable path.

Discovery reads only `/tmp/ida-agent-<uid>/instances`, not the whole `/tmp` tree.
It contains private registry JSON files and `ida-agent-<pid>-<uuid-short>.sock` sockets.
Directory mode is `0700`, files/sockets are `0600`; symlinks and unsafe ancestors
are rejected. The server checks the client UID, and the Gateway checks server UID
and PID with `SO_PEERCRED` before sending hello. Registry v1 remains Windows-only;
Linux publishes v2 `endpoint: {kind: "unix", path: "..."}` with unchanged `ida-rpc/1`.
`IDA_AGENT_INSTANCE_DIR` is a test override shared by both sides. Keep it short enough
for a socket path of at most 107 UTF-8 bytes, private, and on a Linux filesystem.
Normal exit removes registry/socket files; discovery reaps entries for dead/stale
processes after validation. Live but temporarily unresponsive instances are retained.
The discovery guard permits at most 64 directory entries, including sockets, so a
clean Linux directory currently holds at most 32 discoverable instances.

## Real IDA integration tests

After activating IDA and accepting its license agreement interactively:

```sh
python3 ida-agent-plugin/tests/integration/run_linux_smoke.py \
  --ida-dir "$HOME/ida-pro-9.4" \
  --plugin build/linux-plugin/ida-runtime/plugins/ida-agent-plugin.so \
  --gateway build/linux/ida-mcp
```

Alternatively, add `-DIDA_AGENT_ENABLE_INTEGRATION_TESTS=ON` and
`-DIDA_INSTALL_DIR="$HOME/ida-pro-9.4"` to the CMake configure command above.
The build then also compiles an integration Gateway and disposable debugger and
semantic samples. Run `ctest --test-dir build/linux-plugin -L integration --output-on-failure`
for the six real-IDA tests below. The default and CI builds run only unit tests,
without an IDA installation or license.

The runner builds a small ELF sample, uses a private temporary IDA user directory,
copies the same user's existing `ida.reg` (including previously accepted terms),
configures IDAPython in that copy, and leaves the original settings untouched.
It prints the artifact directory and plugin SHA-256. It verifies the 11 MCP domain
tools, instance selection, database metadata, functions/disassembly, xrefs, strings,
bounded pagination, and pseudocode when the instance reports a decompiler. It also
checks stdio EOF, HTTP SIGTERM, and IDA exit/registry/socket cleanup. No license
file is copied into the repository. Test artifacts are private and retained for diagnosis.

| Test | Coverage |
| --- | --- |
| `ida_linux_mcp_integration` | Read-only stdio/HTTP MCP smoke test described above |
| `ida_linux_functional_integration` | Shared 92-method RPC contract suite over Unix sockets, including success and expected-error paths; stdio/HTTP Python and IDC execution, UTF-8 output limits, file-backed scripts, mutation preview/apply/audit/rollback, byte/integer patches, conflict guards, cursor integrity, database save, and headless debugger denial |
| `ida_linux_recovery_integration` | Kills only the runner's IDAT, then verifies a fresh Gateway removes its stale registry and socket |
| `ida_linux_debugger_integration` | Production local Linux debugger services: selection/configuration, breakpoints, launch, step, run-to, registers/memory reads, continue/suspend/exit, process enumeration, attach/detach |
| `ida_linux_semantic_integration_O0` / `_O2` | ELF argument/guard analysis, caller depth and work limits, recursion, and conservative results for real exception handlers |

The functional and recovery smoke modes can also be run directly by adding
`--functional` or `--crash-recovery` to the Python command above.
The debugger test uses a test-only C entry point into production services; it
does not bypass the shipping plugin's MCP permission gate. Its owned attach target
allows only that IDAT PID to trace it, without changing system ptrace policy.
Do not install the test-only `ida_linux_debugger_driver.so` in your user plugins.
Headless MCP denial is tested separately. GUI approval and remote debugger workflows
still require validation; a 92-method contract pass does not mean every method has
a successful headless execution path.

Native Wayland UI and broader distribution coverage remain outside current
validation. Hosted release jobs run portable unit tests, not licensed IDA GUI
tests. The existing Windows integration suite is not a Linux pass.

WSLg windows that show only a taskbar entry with `[WARN:COPY MODE]` indicate a WSLg
display issue. After saving Linux GUI work, restart that distribution's Weston from
Windows (`wsl -d Ubuntu-24.04 --system --exec pkill -TERM -x weston`) and reopen IDA.
This closes the distribution's Linux GUI windows. Running IDA with
`QT_QPA_PLATFORM=xcb` selects its X11 backend.
