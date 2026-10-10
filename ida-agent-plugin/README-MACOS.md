# macOS Universal 2

> **This macOS version has not been comprehensively tested. Please [report bugs](https://github.com/ackwrap/ida-pro-agent/issues) with your OS, CPU architecture, IDA version, and reproduction steps.**
>
> **macOS 版本尚未经过全面测试。如遇问题，请[提交 Bug / Issue](https://github.com/ackwrap/ida-pro-agent/issues)，附上系统、CPU 架构、IDA 版本和复现步骤。**

The macOS build includes the MCP bridge and optional AI Chat panel for **IDA
Professional 9.4**, using IDA's **Qt 6.8.2 in namespace `QT`**. The gateway and
plugin can each contain both `x86_64` and `arm64` slices. Building either slice
does not require running an IDA executable of that architecture.

The release configuration targets **macOS 15 or later**, matching the pinned IDA
SDK libraries. Intel runtime checks run on macOS 15.7.7; GitHub's Apple Silicon
runner executes arm64 unit and installer tests. Both binary slices are checked
for architecture and linking; licensed IDA UI behavior still needs broader
validation. A matching IDA and Hex-Rays license is required for live analysis.

## Install

1. Close IDA, open `ida-agent-<version>-macos-universal2.dmg`, then run
   **IDA Agent Installer.app** and click **Install**.
2. The default IDA user directory is `~/.idapro`; change it to your `IDAUSR`
   when using a custom directory. The plugin goes into its `plugins` folder.
   The gateway is installed at `~/Library/Application Support/ida-agent/bin/ida-mcp`.
3. Open a database in IDA. Use **Edit → Plugins → IDA Agent** for Provider
   Settings and AI Chat, or configure an MCP client to launch the absolute path
   to `ida-mcp` with no arguments for stdio.

The installer runs as your normal user, validates its payload, refuses to
replace files while IDA is running, and preserves previous files beside their
destinations with a `.backup-UUID` suffix. It restores previous files if a
replacement fails. `Open IDA Agent.command`, installed beside the gateway,
starts the configuration manager; open the local URL printed in its Terminal
window. Restart MCP clients after upgrading. No build tools are needed to install.

The portable ZIP remains available: manually copy its
`plugins/ida-agent-plugin.dylib` to your IDA user plugins folder and keep `ida-mcp`
in a stable location. Installation never changes provider settings or history.

The binaries use ad-hoc signatures, not Developer ID notarization. No IDA, Qt,
OpenSSL or curl libraries are included. IDA supplies its own Qt frameworks.
`ida-mcp -web` opens the local configuration manager and remains in the foreground;
there is no macOS tray integration. The gateway must run as the same user as IDA.

## Native networking and storage

- HTTP/HTTPS and SSE use `NSURLSession` data tasks; WS/WSS uses
  `NSURLSessionWebSocketTask`. TLS uses the macOS trust store through
  `Security.framework`. Neither the Go gateway nor the plugin requires a
  separately installed OpenSSL or libcurl runtime.
- Direct, macOS System Proxy, and explicit HTTP proxy modes are supported.
  System Proxy reads macOS network settings, not shell `http_proxy` variables.
  Explicit proxies use Network.framework's HTTP CONNECT configuration, including
  for plain HTTP/WS destinations; the proxy must permit those destination ports.
  A small static Swift adapter uses Apple's public URLSession proxy API. Proxy
  credentials stay on that configuration, and fallback to direct is disabled.
  URLSession implicitly bypasses loopback/link-local destinations. With local
  bypass disabled, the plugin rejects those routes before sending data; enable
  local bypass or select Direct mode for a local provider.
  Redirects are disabled and credentials/cookies are not persisted by URLSession.
- Native receive-idle timers account for network data even when URLSession
  coalesces callbacks. Providers should declare SSE's UTF-8 charset or
  `X-Content-Type-Options: nosniff` to avoid native encoding detection buffering.
  Connection timers bound the wait for the first response or upload-progress
  callback; WebSocket connection timers cover the handshake.
  WebSocket sends use a subsequent ping/pong to bound URLSession's internal
  send buffering; the configured send timeout includes that round trip.
  Send limits, cancellation, bounded queues and overall stream deadlines remain
  enforced by the transport. A requested WebSocket close reports URLSession's
  local close result; it does not certify receipt of the peer's close reply.
  An absolute `SSL_CERT_FILE` may add a PEM CA bundle
  for that process; hostname and certificate validity checks remain enabled and
  no keychain is modified.
- Configuration, provider credentials and SQLite history default to
  `~/Library/Application Support/ida-agent/ai/`. Credentials remain plaintext in
  user-private files. Absolute `XDG_CONFIG_HOME` / `XDG_STATE_HOME` overrides are
  available for isolated tests. SQLite is statically linked and private.
- Discovery uses registry v2 and private Unix sockets under
  `/private/tmp/ida-agent-<uid>/instances`. The gateway validates filesystem
  ownership, permissions, process start time, and the socket peer's UID/PID.
  Custom `IDA_AGENT_INSTANCE_DIR` paths must be canonical, private, and short
  enough for macOS's 103-byte Unix socket path limit. `/tmp` and `/var` are
  symlinks on macOS; resolve them before configuring a custom path.
- Database history keys follow the volume's case sensitivity and normalize
  Unicode spelling. AI file operations use descriptor-relative traversal,
  reject symlinks and require approval for mutations, as on Linux.

## Build

Install Xcode command line tools, CMake >= 3.25, Ninja, Python >= 3.10 and Go
1.25. Initialize the pinned SDK without editing it:

```sh
git submodule update --init ida-sdk
python3 -m venv build/macos-venv
build/macos-venv/bin/python -m pip install websockets==15.0.1
```

Network tests use the `openssl` **command-line tool only to generate temporary
test certificates**. It is not linked into the product. Test fixtures run on
loopback and never contact a real provider.

For AI Chat, obtain the installed/extracted **application contents** of both
Intel and arm64 IDA 9.4. An installer wrapper is not the application contents.
The ARM application need not be runnable on the build host. Only its
`Contents/Info.plist` and QtCore/QtGui/QtWidgets framework binaries are needed.

```sh
python3 release/prepare_macos_qt.py \
  --x86-ida '/Applications/IDA Professional 9.4.app' \
  --arm-ida '/path/to/extracted-arm64/IDA Professional 9.4.app'
```

This fetches checksum-pinned official Qt 6.8.2 headers into the ignored
`qt-sdk/qt-6.8.2-macos` directory and combines IDA's framework slices in
`build/macos-qt/ida-qt.app`. This bundle is a **link input only**, never a runtime
package. No IDA executable or license is copied. CMake validates both Qt slices,
version 6.8.2 and namespace `QT` without executing target code.

```sh
python3 release/build_macos.py \
  --qt-runtime build/macos-qt/ida-qt.app \
  --python build/macos-venv/bin/python
```

The script runs Go vet/tests/build and CTest, builds both architectures, merges
the Go slices with `lipo`, signs both binaries, checks dynamic dependencies and
portable runtime paths, then creates a ZIP, a graphical installer DMG and
SHA-256 files under `release/dist/`. It tests the mounted installer in temporary
directories, including first install, upgrade backups, damaged payload refusal,
running-IDA protection and the gateway launcher. Nothing is deployed to your
normal IDA user directory or published automatically. Use `--zip-only` for a
portable-only build.

Packaging and installer validation can also run as separate CI steps:

```sh
version=$(cat ida-mcp/VERSION)
python3 release/build_macos_dmg.py --archive "release/dist/ida-agent-$version-macos-universal2.zip"
python3 release/tests/test_macos_installer.py --dmg "release/dist/ida-agent-$version-macos-universal2.dmg"
```

These commands use the version in `ida-mcp/VERSION`. DMG generation and
automated installer tests require no desktop interaction or IDA license.
For GitHub Actions runner prerequisites and commands, see
[release automation](../release/README.md#macos-scripted-packaging).

For a basic MCP-only plugin, Qt, SQLite and the AI network layer are unnecessary:

```sh
cmake -S ida-agent-plugin -B build/macos-core -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_DEPLOYMENT_TARGET=15.0 \
  '-DCMAKE_OSX_ARCHITECTURES=x86_64;arm64' \
  -DIDA_AGENT_ENABLE_AI=OFF -DBUILD_TESTING=ON
cmake --build build/macos-core --parallel "$(sysctl -n hw.logicalcpu)"
ctest --test-dir build/macos-core --output-on-failure
```

Use `IDA_AGENT_BUILD_AI_BACKEND=ON` with AI off for independent native network,
storage and Agent tests without Qt.

## Real IDA validation

Configure an AI build with `IDA_AGENT_ENABLE_INTEGRATION_TESTS=ON`,
`IDA_AGENT_ENABLE_GUI_TESTS=ON`, and
`IDA_INSTALL_DIR='/Applications/IDA Professional 9.4.app/Contents/MacOS'`.
The separate `IDA_AGENT_IDA_QT_RUNTIME_DIR` still points to the link bundle.
GUI tests require a logged-in desktop session; integration tests require an
already licensed IDA. If Python discovery needs an explicit framework, set
`IDA_AGENT_TEST_PYTHON_LIBRARY` to its absolute `Python` library path.

```sh
ctest --test-dir build/release/macos -L integration --output-on-failure
```

The shared fixtures create private `IDAUSR`, configuration, state and IDBs.
They exercise stdio/HTTP MCP, RPC contracts, crash recovery, and the Qt panel's
settings, streamed replies, tools, file approval, cancellation, history restore
and clean exit. macOS local-debugger behavior is not yet covered by these tests;
the Linux debugger integration tests are Linux-specific.
