# Linux x64

This package includes the MCP Gateway and full AI Chat plugin for **Ubuntu 24.04
x86_64 and IDA Professional 9.4**, using IDA's bundled Qt 6.8.2. Other distributions
need a compatible glibc/libstdc++ and OpenSSL 3 runtime. No IDA or Qt libraries are
included. curl and SQLite are linked privately into the plugin; curl's license is
included under `licenses/`.

**Linux has not been comprehensively tested. Please [report bugs](https://github.com/ackwrap/ida-pro-agent/issues)
with the distribution, CPU architecture, IDA version, reproduction steps and logs
with secrets removed.**

1. Extract the archive and run `sha256sum -c SHA256SUMS.txt` from its directory.
2. Close IDA. Copy `plugins/ida-agent-plugin.so` to
   `${IDAUSR:-$HOME/.idapro}/plugins/`, creating that directory if necessary.
3. Keep `ida-mcp` and `skills/` together in a stable directory. Configure your MCP
   client to launch the absolute path to `ida-mcp` with no arguments for stdio.
   Run `./ida-mcp -web` for the local client configuration manager.
4. Open a database in IDA, then use **Edit → Plugins → IDA Agent** for Provider
   Settings and AI Chat. The Gateway must run as the same Linux user as IDA.

The plugin uses IDA's already loaded Qt libraries. Install OpenSSL 3 and CA
certificates through your distribution (`libssl3t64` and `ca-certificates` on
Ubuntu 24.04). A matching IDA/Hex-Rays license is required for live analysis.
Settings and chat history remain in the user's XDG configuration/state directories.

For headless use, launch IDAT through the included wrapper:

```sh
./idat-with-agent /absolute/path/to/ida-9.4/idat [your usual IDA arguments]
```

The wrapper selects that installation's Qt libraries for this process. Unlike the
GUI, bare `idat` does not preload Qt; the full AI plugin needs those libraries even
when used only for MCP. The wrapper does not change system library settings.

## 中文

本包包含 Linux x64 MCP Gateway 和完整 AI Chat 插件，面向 **Ubuntu 24.04 x86_64、
IDA Professional 9.4 及其自带的 Qt 6.8.2**。不附带 IDA 或 Qt 库，系统需安装
OpenSSL 3 和 CA 证书。

**Linux 版本尚未经过全面测试。如遇问题，请[提交 Bug / Issue](https://github.com/ackwrap/ida-pro-agent/issues)，
附上发行版、CPU 架构、IDA 版本、复现步骤及已去除密钥的相关日志。**

解压后运行 `sha256sum -c SHA256SUMS.txt` 校验文件。关闭 IDA，将
`plugins/ida-agent-plugin.so` 复制到 `${IDAUSR:-$HOME/.idapro}/plugins/`。
保留 `ida-mcp` 与 `skills/`，使用绝对路径配置 MCP 客户端，或运行 `./ida-mcp -web`
打开本地配置页。IDA 打开数据库后，从 **Edit → Plugins → IDA Agent** 使用内置 AI。

无界面模式请使用包内的 `./idat-with-agent /绝对路径/ida-9.4/idat [原有 IDA 参数]`。
它仅为当前进程指定该 IDA 安装目录中的 Qt 库；直接启动 `idat` 不会像 GUI 一样预加载 Qt。
