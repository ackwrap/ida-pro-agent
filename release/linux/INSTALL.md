# Linux x64 installation

The packages include the MCP Gateway, client skills and full AI Chat plugin for
**Ubuntu 24.04+ or Debian 13+, amd64, and IDA Professional 9.4** with its bundled
Qt 6.8.2. The current source adds the `.deb` installer for the next release after
v0.4.10; earlier releases provide the portable tar.gz only. The plugin requires
glibc 2.38 or newer, so Ubuntu 22.04 and Debian 12 are not supported by these binaries.

IDA and Qt libraries are supplied by your separate IDA installation. curl and
SQLite are linked privately; OpenSSL 3 and CA certificates are system dependencies.
The package contains the project license and third-party notices.

## Ubuntu / Debian desktop package

1. Close IDA and IDAT. Download `ida-agent-VERSION-linux-x64.deb` and its `.sha256`
   file from the same release; replace `VERSION` below with the downloaded version.
2. Verify and install the package. APT installs the required system dependencies:

   ```sh
   sha256sum -c ida-agent-VERSION-linux-x64.deb.sha256
   sudo apt install ./ida-agent-VERSION-linux-x64.deb
   ```

3. Open **IDA Agent** from the application menu. It includes a product icon and
   English/Chinese setup window. Select your IDA **user directory**, normally
   `~/.idapro` or your custom `IDAUSR`, then click **Install plugin**. Run this
   window as your normal user, without sudo. An existing manual plugin can be
   backed up before replacement.
4. Start IDA and open a database. Use **Edit → Plugins → IDA Agent** for AI Chat
   and provider settings. Click **Open manager** in the setup window to configure
   external MCP clients in your browser. The menu also offers an **Open client
   manager** action. Configure stdio clients to run `/usr/bin/ida-mcp`.

The package installs its payload in `/usr/lib/ida-agent`, desktop metadata in
`/usr/share/applications` and `metainfo`, and SVG plus multiple PNG sizes in the
hicolor icon theme. It does not modify user home directories during APT install.
The setup window creates a user plugin link; later package upgrades update the
plugin and Gateway together. Close IDA and run `ida-agent-setup --stop-manager` before upgrading. Settings and chat history
remain in the user's XDG configuration/state directories.

Without a desktop session, activate the plugin from a terminal:

```sh
ida-agent-setup --install-plugin
# For a custom IDA user directory:
ida-agent-setup --install-plugin --ida-user-dir "/path/to/IDA user directory"
# Back up a previous manual plugin when migrating:
ida-agent-setup --install-plugin --replace
```

To uninstall, close IDA and remove the managed plugin link first:

```sh
ida-agent-setup --stop-manager
ida-agent-setup --remove-plugin
sudo apt remove ida-agent
```

For a custom directory, use the same `--ida-user-dir` when removing the link.
Settings, chat history and plugin backups remain available. The Gateway must run
as the same Linux user as IDA.

## Portable tar.gz

Extract the archive and run `sha256sum -c SHA256SUMS.txt` from its directory.
Close IDA and copy `plugins/ida-agent-plugin.so` to `${IDAUSR:-$HOME/.idapro}/plugins/`,
creating the directory if necessary. Keep `ida-mcp` and `skills/` together in a
stable directory. Configure MCP clients with the absolute path to `ida-mcp`, or
run `./ida-mcp -web` and open the local URL printed in the terminal.

For headless IDAT, use the matching IDA runtime libraries through the wrapper:

```sh
# Installed .deb:
idat-with-agent /absolute/path/to/ida-9.4/idat [your usual IDA arguments]
# Portable package:
./idat-with-agent /absolute/path/to/ida-9.4/idat [your usual IDA arguments]
```

Unlike GUI IDA, bare `idat` does not preload Qt. The wrapper selects that IDA
installation's Qt libraries for this process without changing system library settings.

Linux has not been comprehensively tested. Please [report bugs](https://github.com/ackwrap/ida-pro-agent/issues)
with your distribution, architecture, IDA version, reproduction steps and logs with secrets removed.

## 中文

支持 **Ubuntu 24.04 及后续、Debian 13 及后续，amd64，IDA Professional 9.4 / Qt 6.8.2**。
当前源码新增 `.deb` 安装包，会随 v0.4.10 之后的下一次发布提供；旧版仍使用 tar.gz。
插件要求 glibc 2.38，当前二进制不支持 Ubuntu 22.04 和 Debian 12。

关闭 IDA / IDAT，下载同一版本的 `.deb` 和 `.sha256` 文件。将下面的 `VERSION` 替换为实际版本：

```sh
sha256sum -c ida-agent-VERSION-linux-x64.deb.sha256
sudo apt install ./ida-agent-VERSION-linux-x64.deb
```

安装后从应用菜单打开带图标的 **IDA Agent**。选择 IDA **用户目录**（默认 `~/.idapro`，
自定义时选择对应 `IDAUSR`），点击 **安装插件**；此步骤使用普通用户，不加 sudo。
已有手工安装的插件会在确认后先备份，再替换。点击 **打开管理页** 可在浏览器中配置外部
MCP 客户端；Gateway 的固定命令为 `/usr/bin/ida-mcp`。

命令行安装可用 `ida-agent-setup --install-plugin`，自定义目录增加
`--ida-user-dir "/你的 IDA 用户目录"`；迁移已有插件可增加 `--replace` 保留备份。
升级 `.deb` 会同步更新 Gateway 和插件；升级前先关闭 IDA，并运行
`ida-agent-setup --stop-manager` 停止从桌面入口启动的后台管理页。

卸载前先运行 `ida-agent-setup --stop-manager` 和 `ida-agent-setup --remove-plugin`，
再运行 `sudo apt remove ida-agent`。
自定义目录要带上与安装时相同的 `--ida-user-dir`。设置、聊天历史和旧插件备份会保留。
APT 安装本身不会扫描或修改其他用户的主目录。

tar.gz 便携包继续提供：解压并校验，将插件复制到 `${IDAUSR:-$HOME/.idapro}/plugins/`，
保留 Gateway 与 `skills/`。无界面 IDAT 使用 `idat-with-agent` 指定对应 IDA 的 Qt 库。
不附带 IDA、Qt 运行库或 IDA 许可证。Linux 尚未经过全面测试，遇到问题请提交 Issue。
