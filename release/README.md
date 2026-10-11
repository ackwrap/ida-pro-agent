# GitHub Actions builds and public releases

[English setup](#configure-public-publishing) | [中文配置说明](#中文配置说明)

> **One release contains Windows x64, Linux x64 and macOS Universal 2 packages.** All hosted source synchronization, testing, packaging and release publishing run in the public `ackwrap/ida-pro-agent` repository. The private `ackwrap/ida-agent` repository stores source and restricted build inputs only; local build scripts and tests remain available. MIT-licensed project source, public build checks, usage guides and binary releases are published to the public repository [`ackwrap/ida-pro-agent`](https://github.com/ackwrap/ida-pro-agent). Source snapshots preserve the public repository history; private Qt link inputs and local development files are excluded.

The [Release packages workflow](https://github.com/ackwrap/ida-pro-agent/blob/main/.github/workflows/windows-release.yml) builds all three platforms concurrently. Its publishing job requires all three package jobs to succeed, downloads their artifacts from the same run, verifies all nine named assets and their remote SHA-256 digests, then publishes one complete release. The historical workflow filename is retained for existing automation.

## Linux scripted packaging

`python3 release/build_linux.py --qt-runtime /path/to/ida-qt --qt-sdk /path/to/qt-6.8.2-linux`
builds the full AI Chat plugin and Gateway, runs Go validation and portable C++
tests, and creates `release/dist/ida-agent-<version>-linux-x64.tar.gz` and its
SHA-256 file. The baseline is Ubuntu 24.04 x86_64, with system OpenSSL 3. Licensed
IDA and GUI integration tests stay opt-in. See the [package installation guide](linux/INSTALL.md).

[Linux x64 package](https://github.com/ackwrap/ida-pro-agent/blob/main/.github/workflows/linux-package.yml) runs on GitHub-hosted
Ubuntu and is callable by the release workflow. Its private, pinned input is
`ida94-qt682-linux-x64-v1.tar.gz` from the source repository's
`linux-build-inputs-ida94-qt682-v1` release. `prepare_linux_qt.py` produces this
allowlisted bundle from an existing IDA 9.4 installation and official Qt 6.8.2
headers. It includes Core/Gui/Widgets/DBus link libraries, headers/mkspecs and a
version marker, with no IDA executable or license. Never include these inputs in
the public package. The packaged plugin has no build-machine RPATH and uses
IDA's already loaded Qt libraries in GUI mode; the included `idat-with-agent`
wrapper selects the same installation's Qt libraries for headless use. curl and
SQLite remain private static libraries.

## macOS scripted packaging

`build_macos.py` is the noninteractive entry point for local builds and the
macOS GitHub Actions job. It validates Go and C++, builds both architectures,
creates the portable ZIP and graphical installer DMG, verifies signatures and
checksums, and tests the installer in temporary directories.

The runner needs macOS 15+, Xcode command line tools, CMake >= 3.25, Ninja,
Go 1.25, Python >= 3.10, and the OpenSSL CLI for test-certificate generation.
Initialize the pinned SDK submodule. Provision the IDA 9.4 Universal 2 Qt link
bundle and Qt 6.8.2 headers described in the macOS README on the runner; pass
their absolute locations as job environment variables. They are build inputs
and must not be included in uploaded release artifacts. No live IDA or license
is needed for the default build and installer tests.

```sh
set -euo pipefail
python3 -m venv build/macos-venv
build/macos-venv/bin/python -m pip install websockets==15.0.1
build/macos-venv/bin/python release/build_macos.py \
  --qt-runtime "$IDA_AGENT_QT_RUNTIME_DIR" \
  --qt-sdk "$IDA_AGENT_QT_SDK_DIR" \
  --python build/macos-venv/bin/python
```

Upload only `release/dist/ida-agent-*-macos-universal2.zip`,
`release/dist/ida-agent-*-macos-universal2.dmg`, and their
`.sha256` files. The scripts do not create GitHub releases or require a GitHub
token. DMG packaging can run separately on an existing ZIP:

```sh
version=$(cat ida-mcp/VERSION)
python3 release/build_macos_dmg.py \
  --archive "release/dist/ida-agent-$version-macos-universal2.zip"
python3 release/tests/test_macos_installer.py \
  --dmg "release/dist/ida-agent-$version-macos-universal2.dmg"
```

The installer, gateway and plugin are Universal 2 and ad-hoc signed. Developer ID
signing and notarization are separate future CI steps; a notarization credential
is not needed to build or test this package. The DMG contains a user-level
installer, not a privileged PKG, and never installs Qt or IDA itself.

### macOS GitHub-hosted build

[macOS Universal 2 package](https://github.com/ackwrap/ida-pro-agent/blob/main/.github/workflows/macos-build.yml) runs on a
manual dispatch on public `main` or a release tag, or a call from the public release workflow, using
GitHub's `macos-15` Apple Silicon runner. It needs no local Mac or self-hosted
runner. There is no pull-request trigger.

The workflow downloads `ida94-qt682-macos-universal2-v1.tar.gz` from the source
repository's private `macos-build-inputs-ida94-qt682-v1` release and checks the
SHA-256 pinned in the workflow before extraction. The archive contains only the
QtCore/QtGui/QtWidgets Universal 2 link libraries, IDA version metadata, and Qt
6.8.2 headers/mkspecs. It contains no IDA executable, license, or user settings.
Keep these build inputs private; never copy them to the public release repository.
Updating the inputs requires a new asset version and a reviewed checksum change.

The job uses the source-only `IDA_AGENT_SOURCE_READ_TOKEN` to download private inputs, installs the
selected Go/Python versions, and runs the same release script. It uploads only
ZIP/DMG packages, checksums, release notes, and the CTest log to public Actions
artifacts. Private input bundles are never uploaded. The shared release workflow publishes those packages alongside Linux
and Windows. These tests require no IDA license. Both binary slices are built and checked; tests execute natively on
the runner's arm64 architecture and do not exercise the licensed IDA GUI.

## Workflows

Compilation automatically uses all logical CPUs available to the runner or local
process. Each build logs the detected CPU count and selected number of jobs.
Both release scripts accept `--jobs N` for an explicit override; otherwise they
respect `CMAKE_BUILD_PARALLEL_LEVEL` when set, then fall back to CPU detection.
The CI workflows set this value automatically. CTest concurrency is configured
separately and is not increased by the compiler setting.

| Workflow | Trigger | Result |
| --- | --- | --- |
| [Sync public source](https://github.com/ackwrap/ida-pro-agent/blob/main/.github/workflows/public-source-sync.yml) | Public schedule every 15 minutes; manual run on public main | Pull private master, export source, dispatch missing checks and matching version-tag releases |
| [Windows build and tests](https://github.com/ackwrap/ida-pro-agent/blob/main/.github/workflows/windows-build.yml) | Public branch push, pull request, manual or sync dispatch | Gateway and Python validation; full Qt plugin and C++ tests |
| [Linux source tests](https://github.com/ackwrap/ida-pro-agent/blob/main/.github/workflows/linux-build.yml) | Public branch push, pull request, manual or sync dispatch | Go/C++ MCP and independent AI backend tests without private Qt inputs |
| [Agent client regression](https://github.com/ackwrap/ida-pro-agent/blob/main/.github/workflows/agent-client-regression.yml) | Relevant public source push/PR; manual or sync dispatch | SDK compatibility on Windows, Linux and macOS |
| [Linux x64 package](https://github.com/ackwrap/ida-pro-agent/blob/main/.github/workflows/linux-package.yml) | Public release call or manual run | Full AI package and tested tar.gz; source-read secret required |
| [macOS Universal 2 package](https://github.com/ackwrap/ida-pro-agent/blob/main/.github/workflows/macos-build.yml) | Public release call or manual run | Full AI ZIP/DMG and installer tests; source-read secret required |
| [Release packages](https://github.com/ackwrap/ida-pro-agent/blob/main/.github/workflows/windows-release.yml) | Public `v*` tag push; sync dispatch for a matching private version tag | Validate all three platforms and publish one complete release |
| Release packages | Manual public run | Build all platforms; publish only when **publish** is selected |

All runners execute in the public repository. The release `publish` job runs after Windows, Linux and macOS packaging succeeds and receives its own repository's `GITHUB_TOKEN` with **Contents: write**. Source synchronization receives **Contents: write** and **Actions: write** to commit snapshots and explicitly dispatch tests, because a `GITHUB_TOKEN` push does not start push-triggered workflows. Build jobs have read-only public repository tokens; only the private-input download step receives the source-read secret. Windows packaging reuses its tested Release DLL through `build_release.py --plugin`.

## Configure public publishing

1. In **ida-pro-agent → Settings → Secrets and variables → Actions**, add **`IDA_AGENT_SOURCE_READ_TOKEN`**. Use a fine-grained PAT scoped only to **ackwrap/ida-agent → Contents: read**. Store it in Secrets, never source code, variables, or chat. A suitably scoped GitHub App token also works. This credential reads private source and the Linux/macOS Qt input assets; it cannot write either repository.
2. Keep the pinned `linux-build-inputs-ida94-qt682-v1` and `macos-build-inputs-ida94-qt682-v1` releases **published inside the private repository**. Their assets stay private. Draft releases are not available to read-only clients. Updating inputs requires new versioned assets and reviewed SHA-256 pins.
3. Leave all `.github/workflows/` files exclusively in the public repository. No Actions run in private ida-agent. Existing private `IDA_AGENT_RELEASE_TOKEN` and `IDA_AGENT_SOURCE_SYNC_KEY` are no longer used. Public release publishing uses its own `GITHUB_TOKEN`; it needs no cross-repository write token.
4. Push source changes to private `master`. Public **Sync public source** checks on a 15-minute schedule, which GitHub may delay, or can be run manually on public `main`. Without the read secret it reports the missing configuration and skips synchronization; ordinary public Windows/Linux/client checks remain usable.
5. To release, update `ida-mcp/VERSION`, commit and push a matching private `v<version>` tag at the current private master commit. When synchronization observes that matching commit and tag, it creates the public tag at the exported public commit and explicitly dispatches the release workflow with **publish=true**. Untagged development changes do not publish. Existing tags never move. If master advances beyond the tagged commit before polling, dispatch the release manually from the corresponding public tag after reviewing its source.
6. A public `v*` tag push also triggers release packaging. A manual release run publishes only with **publish** selected. Tags must match `ida-mcp/VERSION`. A newly created release tag is pinned to the tested public workflow commit, including on manual runs; private commit hashes are never used as release targets.

The published assets are exactly:

- `ida-agent-<version>-windows-x64.zip`
- `ida-agent-<version>-windows-x64-setup.exe`
- `ida-agent-<version>-windows-x64-setup.exe.sha256`
- `ida-agent-<version>-linux-x64.tar.gz`
- `ida-agent-<version>-linux-x64.tar.gz.sha256`
- `ida-agent-<version>-macos-universal2.zip`
- `ida-agent-<version>-macos-universal2.zip.sha256`
- `ida-agent-<version>-macos-universal2.dmg`
- `ida-agent-<version>-macos-universal2.dmg.sha256`

Each portable package contains the Gateway, full plugin, runtime instructions, and per-file `SHA256SUMS.txt`; Windows and Linux also include client skills. No package contains IDA executables, Qt runtime libraries, or project source files. The publisher requires every platform and rejects missing, extra or mismatched remote assets before making the draft public. Release notes include the Linux/macOS testing disclaimer and never derive text from private commit history.

## Maintain public usage documentation

Public users read the README and usage guides in [`ackwrap/ida-pro-agent`](https://github.com/ackwrap/ida-pro-agent). Their maintained copies are [public/README.md](public/README.md), [public/USAGE.md](public/USAGE.md), and [public/USAGE.zh-CN.md](public/USAGE.zh-CN.md).

Update these maintained copies and push the development repository master branch. The source-sync workflow publishes them automatically at the public repository root together with the committed source. Root development READMEs are published as `README.source.md` and `README.source.zh-CN.md`, preserving the user-facing README and usage guides. Keep relative links valid in both layouts.

公开用户从 `ackwrap/ida-pro-agent` 的 README 及中英文使用指南阅读说明。修改 `release/public/` 中的维护副本并推送开发仓库 master，自动同步会将其放到公开仓库根目录。开发 README 以 `README.source.md` 和 `README.source.zh-CN.md` 提供；检查两种布局下的相对链接。

## Automatic public source synchronization

[Sync public source](https://github.com/ackwrap/ida-pro-agent/blob/main/.github/workflows/public-source-sync.yml)
runs **in the public repository**, every 15 minutes or manually on public `main`.
It checks out the latest private master with the source-read secret and publishes
its committed snapshot using the public `GITHUB_TOKEN`. Concurrency serializes
runs. Windows/Linux/client checks are explicitly dispatched after bot pushes,
and missing dispatches can be retried by rerunning synchronization. Release
runs are not rebuilt automatically after a failure; use **Re-run failed jobs**.
Repository, visibility and branch guards keep secrets away from fork PRs.

`release/sync_public_source.py` reads tracked blobs from a commit, rejects
unapproved paths and credential-shaped content, preserves the pinned SDK Git
link and executable bits, and records managed paths in `.source-sync.json`.
Removed source files are deleted only when the preceding manifest owned them.
Public-owned `.github/workflows/` paths are neither copied, overwritten, deleted nor staged, including paths in older manifests. Unmanaged public files, previous commits and existing release tags are retained.
Updates use ordinary fast-forward pushes. A concurrent public edit causes a
rejection; review the edit and rerun synchronization rather than force-pushing.
Project code uses MIT; Qt headers and other dependencies retain the licenses in
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

To preview a **committed** snapshot in a fresh, separate checkout:

```sh
python release/sync_public_source.py --transport https --destination build/public-source-preview
```

The preview stages a diff without committing or pushing. Review it with
`git -C build/public-source-preview diff --cached`. Actual CI publication uses
HTTPS with an ephemeral public-token Git header and `--push`. Neither token is persisted in Git configuration. Rerunning an unchanged snapshot makes no new commit.
Local `build/`, release outputs, internal `docs/local/` plans, private Qt link
bundles and untracked user configuration are never read into the snapshot.
A newly tracked source root requires explicit addition to the export allowlist.

### 中文源码同步说明

公开仓库每 15 分钟拉取私有 `master`，也可在公开 `main` 手动运行 **Sync public source**；GitHub 定时任务可能延迟。只读凭据 `IDA_AGENT_SOURCE_READ_TOKEN` 仅授权私有 `ida-agent` 的 **Contents: read**。公开仓库用自己的 `GITHUB_TOKEN` 提交同步结果，并显式触发 Windows、Linux 和客户端回归。私有仓库不运行 Actions。

`.source-sync.json` 继续管理源码文件，公开 `.github/workflows/` 始终由公开仓库维护，同步不会覆盖或删除。既有历史和版本标签保留，使用普通快进推送。未提交文件、内部计划、构建产物和私有 Qt 链接包不会进入公开快照。本地构建与测试脚本继续保留。

## Retry and local validation

Assets are uploaded to a draft, and their remote SHA-256 digests are checked before the release is published. Failed uploads leave a draft that the publishing job can resume. A published release is never overwritten: identical assets are accepted as an already completed run, while different bytes fail explicitly. Unrelated drafts and unexpected assets are left for manual review.

If only publishing fails, fix the token/configuration and use **Re-run failed jobs** so the existing packaged artifact is reused. Rebuilding the same version can produce different installer bytes; bump the version for a replacement of an already published package. Packaged artifacts are retained for 30 days, and branch artifacts/test logs for 14 days.

Run the publisher tests or validate an existing local package without network access:

```powershell
python -m unittest discover -s release/tests -p 'test_publish_release.py'
python release/publish_release.py --dry-run
```

Python 3.11 and GitHub CLI are used for publishing. With `GH_TOKEN` configured, omitting `--dry-run` performs a real public release. The workflow uses GitHub-hosted `windows-2022` runners and pins Actions by commit SHA. MSVC, CMake, Ninja, GitHub CLI, and Inno Setup 6 come from the [runner image](https://github.com/actions/runner-images/blob/main/images/windows/Windows2022-Readme.md); Go and Python are selected by the workflow.

## Qt and runtime limits

The repository tracks Qt 6.8.2 headers and configuration. Checkout initializes the pinned public IDA SDK, including the official `QT`-namespaced import libraries in `src/lib/x64_win_qt`. Compilation and packaging require no IDA installation. An explicit local `IDA_AGENT_IDA_QT_RUNTIME_DIR` can still select regeneration from an installed IDA, but CI uses SDK imports.

Actual plugin use requires **IDA Professional 9.4 for the selected platform with its bundled Qt 6.8.2**. Hosted workflows validate compilation, linking, unit tests, and macOS installer behavior; they do not launch licensed IDA or run its integration/UI tests.

## 中文配置说明

> **统一发布 Windows x64、Linux x64 和 macOS Universal 2。** 私有 `ackwrap/ida-agent` 只存储源码和受限构建输入；所有自动同步、测试、打包和发布均在公开 [`ackwrap/ida-pro-agent`](https://github.com/ackwrap/ida-pro-agent/actions) 执行。本地编译、打包脚本与测试源码保留。

1. 在**公开仓库**的 **Settings → Secrets and variables → Actions** 添加 **`IDA_AGENT_SOURCE_READ_TOKEN`**。创建 fine-grained PAT 时，只选择私有 `ackwrap/ida-agent`，权限为 **Contents → Read-only**。它只用于读取源码和 Linux/macOS 构建输入；不要把令牌写入代码、Variable 或聊天。
2. Linux/macOS 固定版本 Qt 输入的 Release 需要在**私有仓库内部正式发布**，其附件仍是私有资源。只读凭据无法读取草稿。工作流下载后按固定 SHA-256 校验，输入包不进入公开附件。
3. 私有仓库不再需要 `IDA_AGENT_RELEASE_TOKEN`、`IDA_AGENT_SOURCE_SYNC_KEY`，也不再运行 Actions。公开仓库自身的 `GITHUB_TOKEN` 负责写入快照、触发测试和发布；只有相应任务获得写权限。
4. 推送私有 `master` 后，等待公开仓库的 15 分钟定时同步，或手动运行 **Sync public source**。Secret 暂未配置时会在摘要提示并跳过同步，公开源码的普通 CI 仍可运行。
5. 发布时更新 `ida-mcp/VERSION`，提交并推送私有版本标签，例如 `v0.4.9`。标签必须与同步时的私有 master 提交相同，才会自动在公开源码提交上创建同名标签并构建发布。若 master 在定时同步前已前进，先核对公开标签的源码，再手动运行发布工作流。开发提交不会自动发布；已有标签不会移动。
6. 直接推送公开 `v*` 标签也会触发发布。手动运行 **Release packages (Windows, Linux, macOS)** 时，勾选 **publish** 才会发布。新建 Release 标签指向实际测试的公开提交，不使用私有提交 SHA。

只有三个平台全部构建成功，且九个发布附件的远程 SHA-256 全部匹配，草稿才会正式发布。已发布附件不会被覆盖。仅发布失败时，用 **Re-run failed jobs** 复用已经验证的产物。构建附件保留 30 天，测试日志保留 14 天。

Windows 使用公开 SDK 的 Qt 导入库；Linux/macOS 从私有仓库读取构建输入。公开安装包不附带 IDA 或 Qt 运行库，实际运行需要对应平台的 **IDA Professional 9.4 / Qt 6.8.2**。CI 不执行需要许可的真实 IDA UI/集成测试。Linux/macOS 尚未全面测试的说明会保留在发布说明中。
