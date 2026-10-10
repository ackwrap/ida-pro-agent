# GitHub Actions builds and public releases

[English setup](#configure-public-publishing) | [中文配置说明](#中文配置说明)

> **One release contains Windows x64, Linux x64 and macOS Universal 2 packages.** Development and full release builds run in `ackwrap/ida-agent`. MIT-licensed project source, public build checks, usage guides and binary releases are published to the public repository [`ackwrap/ida-pro-agent`](https://github.com/ackwrap/ida-pro-agent). Source snapshots preserve the public repository history; private Qt link inputs and local development files are excluded.

The [Release packages workflow](../.github/workflows/windows-release.yml) builds all three platforms concurrently. Its publishing job requires all three package jobs to succeed, downloads their artifacts from the same run, verifies all nine named assets and their remote SHA-256 digests, then publishes one complete release. The historical workflow filename is retained for existing automation.

## Linux scripted packaging

`python3 release/build_linux.py --qt-runtime /path/to/ida-qt --qt-sdk /path/to/qt-6.8.2-linux`
builds the full AI Chat plugin and Gateway, runs Go validation and portable C++
tests, and creates `release/dist/ida-agent-<version>-linux-x64.tar.gz` and its
SHA-256 file. The baseline is Ubuntu 24.04 x86_64, with system OpenSSL 3. Licensed
IDA and GUI integration tests stay opt-in. See the [package installation guide](linux/INSTALL.md).

[Linux x64 package](../.github/workflows/linux-package.yml) runs on GitHub-hosted
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

[macOS Universal 2 package](../.github/workflows/macos-build.yml) runs on a
`master` push, a manual dispatch, or a call from the release workflow in the private source repository, using
GitHub's `macos-15` Apple Silicon runner. It needs no local Mac or self-hosted
runner. There is no pull-request trigger.

The workflow downloads `ida94-qt682-macos-universal2-v1.tar.gz` from the source
repository's private `macos-build-inputs-ida94-qt682-v1` release and checks the
SHA-256 pinned in the workflow before extraction. The archive contains only the
QtCore/QtGui/QtWidgets Universal 2 link libraries, IDA version metadata, and Qt
6.8.2 headers/mkspecs. It contains no IDA executable, license, or user settings.
Keep these build inputs private; never copy them to the public release repository.
Updating the inputs requires a new asset version and a reviewed checksum change.

The job uses its read-only `GITHUB_TOKEN` to download the inputs, installs the
selected Go/Python versions, and runs the same release script. It uploads only
ZIP/DMG packages, checksums, release notes, and the CTest log to private Actions
artifacts. The shared release workflow publishes those packages alongside Linux
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
| [macOS Universal 2 package](../.github/workflows/macos-build.yml) | `master` push, manual run; private Qt build inputs required | GitHub-hosted Mac; full Universal 2 AI plugin and Gateway; unit and installer tests; private ZIP/DMG artifacts |
| [Sync public source](../.github/workflows/public-source-sync.yml) | Private master push, manual run on master | Publish committed source, MIT license and maintained usage guides to public main |
| [Windows build and tests](../.github/workflows/windows-build.yml) | Branch push, pull request, manual run | Gateway and publisher validation; complete Qt-enabled plugin; C++ tests; Actions artifacts in the repository running the workflow |
| [Linux x64 package](../.github/workflows/linux-package.yml) | Release workflow call, manual run | Full AI plugin and Gateway; portable tests; private tar.gz artifact |
| [Release packages](../.github/workflows/windows-release.yml) | `v*` tag push | Validate and package all three platforms, then publish their binary assets together |
| Release packages | Manual run | Build all three platforms; publish only when the **publish** checkbox is selected |

The release `publish` job runs after the Windows `package`, `linux`, and `macos` jobs succeed. Only its publishing step receives the cross-repository token. Build jobs use read-only repository tokens. Windows packaging reuses its tested Release DLL through `build_release.py --plugin`, avoiding a second compilation. The public repository also builds and tests synchronized source with the Windows/Linux branch workflows. Full package jobs and binary publishing run only in the private development repository.

## Configure public publishing

1. The public repository must have at least one commit, such as a README. The initial public documentation is maintained at [public/README.md](public/README.md). New release tags target a commit in the public repository's default branch, including its synchronized source snapshot. Existing tags are preserved: tags created before source publication still contain their original documentation snapshot. The snapshot workflow does not import private Git history.
2. Create a **fine-grained personal access token** with `ackwrap` as resource owner, **Only select repositories → ida-pro-agent**, and **Repository permissions → Contents → Read and write**. GitHub adds read access to metadata. An organization may require approval before the token works. A suitably scoped GitHub App installation token is also accepted.
3. In the **private** repository's **Settings → Secrets and variables → Actions**, add:

   | Type | Name | Value |
   | --- | --- | --- |
   | Secret | `IDA_AGENT_RELEASE_TOKEN` | The token that can write releases to the public repository |
   | Variable, optional | `IDA_AGENT_RELEASE_REPOSITORY` | `ackwrap/ida-pro-agent`; this is already the workflow default |

   Store the token directly in GitHub Secrets. Do not commit it or put it in a repository variable. The normal `GITHUB_TOKEN` is [limited to its own repository](https://docs.github.com/en/actions/concepts/security/github_token); cross-repository release creation requires separate credentials with [Contents write access](https://docs.github.com/en/rest/releases/releases#create-a-release).
4. Push the source and workflows to the private repository. For a release, update `ida-mcp/VERSION`, commit the change, and push a matching tag there. For version `0.3.0`, use `v0.3.0`. A mismatched tag fails before compilation. Tags publish automatically; a manual run publishes only when requested.
5. Open the public repository's **Releases** page or the publishing job's summary to download the finished release. Public Windows/Linux checks use the synchronized source and public SDK, with no access to private Qt link inputs. Complete package workflows remain restricted to the private development repository.

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

[Sync public source](../.github/workflows/public-source-sync.yml) runs after each
`ackwrap/ida-agent` master push and can be dispatched manually on master. It
checks out the latest master, runs exporter/publisher tests, then publishes a
committed snapshot to `ackwrap/ida-pro-agent` main. Concurrency serializes runs;
a queued run reads current master to avoid publishing an older snapshot last.
The workflow is guarded by repository, visibility and branch, so its public
copy never synchronizes back or needs credentials.

Configure a dedicated Ed25519 **deploy key** with write access on the public
repository. Store its private part only in the private development repository's
Actions secret **`IDA_AGENT_SOURCE_SYNC_KEY`**. This key is limited to Git access
to that one repository and can synchronize workflow files without broadening
the release token's permissions. The publishing step verifies GitHub's pinned
SSH host key. Keep `IDA_AGENT_RELEASE_TOKEN` for binary releases separately.
See [GitHub deploy keys](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys).

`release/sync_public_source.py` reads tracked blobs from a commit, rejects
unapproved paths and credential-shaped content, preserves the pinned SDK Git
link and executable bits, and records managed paths in `.source-sync.json`.
Removed source files are deleted only when the preceding manifest owned them.
Unmanaged public files, previous commits and existing release tags are retained.
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
SSH with `--push`. Rerunning an unchanged snapshot makes no new commit.
Local `build/`, release outputs, internal `docs/local/` plans, private Qt link
bundles and untracked user configuration are never read into the snapshot.
A newly tracked source root requires explicit addition to the export allowlist.

### 中文源码同步说明

开发仓库 `master` 每次推送自动将已提交源码同步到公开仓库 `main`，也可在 master
手动运行 **Sync public source**。同步配置使用公开仓库独享、允许写入的 Deploy Key，
私钥只存入开发仓库的 `IDA_AGENT_SOURCE_SYNC_KEY` Secret，二进制发布令牌保持独立。
同步保留公开仓库既有提交和发布标签，使用普通快进推送；新旧源码文件由
`.source-sync.json` 清单管理，其他公开文件保留。未提交的本地文件、内部计划、
构建产物和私有 Qt 链接包不进入公开仓库。公开仓库运行 Windows/Linux 源码检查，
完整三平台打包继续使用开发仓库的受限构建输入。

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

> **统一发布 Windows x64、Linux x64 和 macOS Universal 2。** 私有源码仓库为 `ackwrap/ida-agent`，公开下载仓库为 [`ackwrap/ida-pro-agent`](https://github.com/ackwrap/ida-pro-agent)。MIT 项目源码与使用说明自动同步到公开仓库，并运行 Windows/Linux 源码检查。完整三平台包在开发仓库构建，私有 Qt 链接输入保留在开发仓库。

配置步骤：

1. 公开仓库需要至少一次提交，例如 README。公开说明的维护副本位于 [public/README.md](public/README.md)。Release 的新标签指向公开仓库默认分支中的源码快照；既有标签保留原提交，公开源码之前的 **Source code** 压缩包仍是原文档快照。自动同步不导入私有历史。
2. 创建 fine-grained PAT：Resource owner 选择 `ackwrap`，Only select repositories 只选择 `ida-pro-agent`，Repository permissions 中设置 **Contents → Read and write**。组织策略可能要求审批后才能使用。
3. 在**私有仓库**的 **Settings → Secrets and variables → Actions** 添加 Secret **`IDA_AGENT_RELEASE_TOKEN`**，值为该令牌。目标仓库默认已经是 `ackwrap/ida-pro-agent`；如需覆盖，添加同名含义的 Variable **`IDA_AGENT_RELEASE_REPOSITORY`**，值使用 `owner/repo` 格式。令牌只放在 Secret 中，不要写进代码或 Variable。
4. 将源码和工作流推送到私有仓库。推送与 `ida-mcp/VERSION` 一致的 `v*` 标签会自动构建三平台并统一公开发布。手动运行 **Release packages (Windows, Linux, macOS)** 时，只有勾选 **publish** 才会发布；否则只保留私有构建产物。
5. 用户从同一个 **Release** 下载 Windows ZIP/安装器、Linux tar.gz、macOS ZIP/DMG 及校验文件。只有三个平台全部构建成功且九个发布附件均校验通过，Release 才会公开。Linux/macOS 的未全面测试声明会自动写入说明。

默认 `GITHUB_TOKEN` 只能操作工作流所在仓库，二进制跨仓库令牌只交给最终发布步骤，该步骤只上传固定名称的九个产物；源码同步另用公开仓库专用 Deploy Key。版本说明使用公开模板，不从私有提交记录生成。

发布时先创建草稿，上传并核对远程资产的 SHA-256，全部匹配后再正式发布。上传失败可以恢复脚本创建的草稿；不会覆盖已经发布的资产。若仅发布失败，修复配置后使用 **Re-run failed jobs**，复用已经验证的构建产物。重建同一版本的安装器可能产生不同字节；替换已发布包应升级版本号。

完整构建产物保留 30 天，分支产物与测试日志保留 14 天。Windows 使用公开 SDK 的 Qt 导入库；Linux/macOS 从私有仓库下载固定校验值的 Qt 构建输入。公开包均不附带 IDA 或 Qt。实际运行需对应平台的 **IDA Professional 9.4 及 Qt 6.8.2**。CI 不执行真实 IDA 的 UI 或需要许可的集成测试。
