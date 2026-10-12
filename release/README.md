# GitHub Actions builds and public releases

[English setup](#configure-public-publishing) | [中文配置说明](#中文配置说明)

> **One release contains Windows x64, Linux x64 and macOS Universal 2 packages.** The public [`ackwrap/ida-pro-agent`](https://github.com/ackwrap/ida-pro-agent) repository and its `main` branch are the development mainline. Source, documentation, hosted tests, packaging and release publishing are maintained here directly. The private `ackwrap/ida-agent` repository is retained for archival storage and restricted Qt build inputs; it runs no Actions. Local build scripts and tests remain available. Project-owned source is MIT-licensed; private Qt link inputs and local development files are excluded from public release packages.

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

The workflow downloads `ida94-qt682-macos-universal2-v1.tar.gz` from the private
`ackwrap/ida-agent` repository's `macos-build-inputs-ida94-qt682-v1` release and checks the
SHA-256 pinned in the workflow before extraction. The archive contains only the
QtCore/QtGui/QtWidgets Universal 2 link libraries, IDA version metadata, and Qt
6.8.2 headers/mkspecs. It contains no IDA executable, license, or user settings.
Keep these build inputs private; never copy them to the public release repository.
Updating the inputs requires a new asset version and a reviewed checksum change.

The job uses the existing `IDA_AGENT_SOURCE_READ_TOKEN`, now only for build-input reads, to download private inputs, installs the
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
| [Windows build and tests](https://github.com/ackwrap/ida-pro-agent/blob/main/.github/workflows/windows-build.yml) | Public branch push, pull request or manual run | Gateway and Python validation; full Qt plugin and C++ tests |
| [Linux source tests](https://github.com/ackwrap/ida-pro-agent/blob/main/.github/workflows/linux-build.yml) | Public branch push, pull request or manual run | Go/C++ MCP and independent AI backend tests without private Qt inputs |
| [Agent client regression](https://github.com/ackwrap/ida-pro-agent/blob/main/.github/workflows/agent-client-regression.yml) | Relevant public source push/PR or manual run | SDK compatibility on Windows, Linux and macOS |
| [Linux x64 package](https://github.com/ackwrap/ida-pro-agent/blob/main/.github/workflows/linux-package.yml) | Public release call or manual run | Full AI package and tested tar.gz; private Qt read credential required |
| [macOS Universal 2 package](https://github.com/ackwrap/ida-pro-agent/blob/main/.github/workflows/macos-build.yml) | Public release call or manual run | Full AI ZIP/DMG and installer tests; private Qt read credential required |
| [Release packages](https://github.com/ackwrap/ida-pro-agent/blob/main/.github/workflows/windows-release.yml) | Public `v*` tag push | Validate all three platforms and publish one complete release |
| Release packages | Manual public run | Build all platforms; publish only when **publish** is selected |

All runners execute in the public repository. A direct developer push starts the matching checks through the ordinary `push` event; there is no source-sync schedule or dispatch bridge. The release `publish` job runs after Windows, Linux and macOS packaging succeeds and receives the public repository's `GITHUB_TOKEN` with **Contents: write**. Build jobs have read-only repository tokens; only the private Qt download step receives the input-read secret. Windows packaging reuses its tested Release DLL through `build_release.py --plugin`.

The publisher checks that the destination is public and active, then relies on GitHub's release API to enforce the token's **Contents: write** permission. Repository `permissions.push` metadata does not describe an installation token's scope and may be absent for `GITHUB_TOKEN`; it is not a publishing precondition. If GitHub denies draft creation, the publisher stops before uploading packages or publishing the release.

## Configure public publishing

1. Use **ackwrap/ida-pro-agent `main`** for source development. Clone the public repository or point the checkout's `origin` at `https://github.com/ackwrap/ida-pro-agent.git`, then track `origin/main`. Keep any private checkout/history separately; use the already published source as the base for public commits.
2. For full Linux/macOS packages, add **`IDA_AGENT_SOURCE_READ_TOKEN`** in **ida-pro-agent → Settings → Secrets and variables → Actions**. The retained secret name now refers only to private Qt build-input reads. Use a fine-grained PAT scoped only to **ackwrap/ida-agent → Contents: read**. A suitably scoped GitHub App token also works. Source checkout, ordinary Windows/Linux/client checks and Windows packaging need no cross-repository credential.
3. Keep the pinned `linux-build-inputs-ida94-qt682-v1` and `macos-build-inputs-ida94-qt682-v1` releases **published inside the private repository**. Their assets remain private; read-only clients cannot download drafts. New input versions require new assets and reviewed SHA-256 pins. Never include the input archives in public artifacts.
4. Commit and push source/documentation changes directly to public `main`. Scheduled private-to-public synchronization is retired. The private repository runs no Actions; its old `IDA_AGENT_RELEASE_TOKEN` and `IDA_AGENT_SOURCE_SYNC_KEY` are unused. Public publishing uses its own `GITHUB_TOKEN` and needs no cross-repository write token.
5. To release, update `ida-mcp/VERSION`, run the affected validation, commit and push `main`, then create and push a matching `v<version>` tag on that public commit. Tag pushes start the release workflow automatically. Development branch pushes run checks without publishing. Existing public release tags never move.
6. A manual release run on public `main` or a matching release tag publishes only with **publish** selected. Tags must match `ida-mcp/VERSION`; releases target the tested public commit. All three platform jobs and asset verification must pass before publication.

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

Edit [root README.md](../README.md), [USAGE.md](../USAGE.md) and [USAGE.zh-CN.md](../USAGE.zh-CN.md) directly. Source build references are [README.source.md](../README.source.md) and [README.source.zh-CN.md](../README.source.zh-CN.md). Commit documentation together with the feature on public `main`; no exporter or scheduled job is needed to publish it.

The old `release/public/` templates and `sync_public_source.py` / `sync_public_automation.py` utilities are retained for migration compatibility and regression tests. They are outside the current publication flow; do not use them to update public `main`. The source synchronization workflow and its active `.source-sync.json` manifest have been removed. Project code uses MIT; dependencies retain the licenses in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

公开使用文档直接维护仓库根目录的 `README.md`、`USAGE.md` 和 `USAGE.zh-CN.md`，源码编译说明维护 `README.source.md` 与 `README.source.zh-CN.md`。与功能改动一起提交、推送公开 `main`，GitHub 页面立即展示。`release/public/` 和旧快照工具仅保留作迁移兼容与回归测试，不再用于更新公开主线。

## Direct development and release

Start from the public development branch:

```sh
git clone --recurse-submodules https://github.com/ackwrap/ida-pro-agent.git
cd ida-pro-agent
git switch main
```

For an existing checkout already tracking the public repository, pull with `git pull --ff-only origin main`. Commit reviewed source and documentation changes, then use `git push origin main` to trigger build checks. Follow the scoped validation in [AGENTS.md](../AGENTS.md).

For example, after updating `ida-mcp/VERSION` to **0.4.10**, validating and committing the change:

```sh
git push origin main
git tag -a v0.4.10 -m "ida-agent 0.4.10"
git push origin refs/tags/v0.4.10
```

Use a new version for each release. Push the intended public tag explicitly so private archival tags are not included. Older public tags created before source publication retain their original documentation snapshots; current source is on `main`.

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

> **统一发布 Windows x64、Linux x64 和 macOS Universal 2。** 公开 [`ackwrap/ida-pro-agent`](https://github.com/ackwrap/ida-pro-agent) 的 `main` 是唯一开发主线，源码、文档、测试、打包和发布直接在这里维护。私有 `ackwrap/ida-agent` 保留历史存储与受限 Qt 构建输入，不运行 Actions。本地编译、打包脚本与测试源码保留。

1. 当前工作目录的 `origin` 应指向 `https://github.com/ackwrap/ida-pro-agent.git`，本地 `main` 跟踪 `origin/main`。已有公开源码作为开发基线，私有历史单独保留。
2. 完整 Linux/macOS 打包仍需在**公开仓库**的 **Settings → Secrets and variables → Actions** 添加 **`IDA_AGENT_SOURCE_READ_TOKEN`**。保留原 Secret 名称以兼容现有工作流，但现在只用于下载私有 Qt 构建输入。fine-grained PAT 仅选择私有 `ackwrap/ida-agent`，权限为 **Contents → Read-only**；源码检出、普通构建检查和 Windows 打包不需要它。
3. 固定 Qt 输入的 Release 在**私有仓库内部正式发布**，其附件仍为私有资源；只读凭据无法读取草稿。下载后按固定 SHA-256 校验，输入包不得上传至公开附件。
4. 源码、文档直接提交并推送 `origin main`，自动运行公开构建检查。定时源码同步已经移除，也不再需要同步凭据。旧私有发布令牌与同步密钥不再使用；公开仓库自己的 `GITHUB_TOKEN` 负责发布。
5. 发布时更新 `ida-mcp/VERSION`，按改动范围完成验证、提交并推送公开 `main`，再在同一公开提交上创建并推送匹配版本号的 `v*` 标签。标签推送自动触发三平台打包发布；普通开发提交只触发检查。已有发布标签不移动。
6. 手动运行 **Release packages (Windows, Linux, macOS)** 时，勾选 **publish** 才会发布。发布引用实际测试的公开提交，所有平台构建与附件校验成功后才正式发布。

只有三个平台全部构建成功，且九个发布附件的远程 SHA-256 全部匹配，草稿才会正式发布。已发布附件不会被覆盖。仅发布失败时，用 **Re-run failed jobs** 复用已经验证的产物。构建附件保留 30 天，测试日志保留 14 天。

Windows 使用公开 SDK 的 Qt 导入库；Linux/macOS 从私有仓库读取构建输入。公开安装包不附带 IDA 或 Qt 运行库，实际运行需要对应平台的 **IDA Professional 9.4 / Qt 6.8.2**。CI 不执行需要许可的真实 IDA UI/集成测试。Linux/macOS 尚未全面测试的说明会保留在发布说明中。
