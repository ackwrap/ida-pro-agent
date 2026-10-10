# Portable plugin tests

Default CTest runs are intended for standard Windows, Linux, and macOS build
machines, including GitHub-hosted runners. WSL is one optional way to obtain a
local Linux environment; no test requires WSL, a Windows mount, a particular
username, or a private machine address.

- Protocol tests use the shared fixtures in `protocol/testdata`.
- Storage and file tests create isolated temporary directories.
- Network tests start their own loopback HTTP/SSE/WebSocket servers on dynamically
  assigned ports and generate temporary TLS certificates. No provider account,
  API key, public network endpoint, or installed IDA is needed at test runtime.
- `run_linux_http.py` and `run_linux_stream.py` are shared by Linux and macOS,
  despite their historical filenames. Python `websockets` and the OpenSSL CLI
  are fixture dependencies; the macOS product does not link OpenSSL.
- Timing tests check behavior and bounded waits with scheduling margin. SQLite
  lock tests also measure the requested sleep budget, so a busy runner's late
  wakeups are not confused with unlimited retries.

Run `ctest --test-dir <build-directory> --output-on-failure` after building.
Keep `IDA_AGENT_ENABLE_INTEGRATION_TESTS=OFF` and `IDA_AGENT_ENABLE_GUI_TESTS=OFF`
for cloud builds. Real IDA integration tests are separately opt-in, use an
explicit `IDA_INSTALL_DIR`, and require a valid license; GUI tests additionally
require a desktop session. The macOS release script explicitly disables both
options, including when reusing an existing CMake build directory.

Build dependencies are separate from runtime test requirements: the full AI
plugin needs matching IDA Qt link inputs, provisioned privately for macOS CI.
Neither those inputs nor IDA licenses are shipped in end-user packages.
