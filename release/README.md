# GitHub Actions builds and public releases

[English setup](#configure-public-publishing) | [中文配置说明](#中文配置说明)

**Source, tests and releases are maintained entirely in public `ackwrap/ida-pro-agent`.** Windows x64, Linux x64 and macOS Universal 2 packaging requires no private repository, personal access token or separately uploaded Qt input release. Project-owned code is MIT-licensed; dependencies retain their own licenses.

The [Release packages workflow](https://github.com/ackwrap/ida-pro-agent/blob/main/.github/workflows/windows-release.yml) builds all three platforms concurrently. Publishing waits for all package and Debian installation jobs, verifies the eleven binary/checksum assets and their remote SHA-256 digests, then publishes one complete release. The historical workflow filename is retained for existing automation.

## Public Qt build inputs

Windows links the official `QT`-namespaced Qt import libraries in the pinned public [IDA SDK](https://github.com/HexRaysSA/ida-sdk) submodule. The matching Windows headers are tracked in `qt-sdk/qt-6.8.2-win`.

Linux and macOS use `release/build_qt.py` to download **Qt Base 6.8.2** from the [official source archive](https://download.qt.io/archive/qt/6.8/6.8.2/submodules/qtbase-everywhere-src-6.8.2.tar.xz). The script verifies SHA-256 `012043ce6d411e6e8a91fdc4e05e6bedcfa10fcb1347d3c33908f7fdd10dfe05` before extracting or compiling, builds shared Release libraries in namespace **`QT`**, and installs headers/mkspecs/libraries into a local prefix. macOS builds Universal 2 frameworks for `x86_64;arm64` with Qt's bundled third-party libraries. These link-only Qt inputs target macOS 14 because Qt 6.8.2 Cocoa cannot be built with a minimum target of 15; the plugin and installer still require macOS 15.

```sh
python3 release/build_qt.py --prefix build/qt-public
```

The first run needs a C++ toolchain, CMake, Ninja and internet access to official Qt sources. Qt compilation uses at most eight jobs by default to bound memory use; `--jobs N` overrides this. `--work-dir` relocates source and intermediate build files. Existing prefixes are reused only after checking their pinned recipe, headers, version, namespace and library architectures. Incomplete or mismatched caches fail with an explicit diagnostic.

Hosted Linux/macOS jobs cache only this installed public prefix, keyed by platform, architecture and build/validation scripts. A cache miss rebuilds it from public source. Neither the source archive nor these libraries come from an IDA installation. No cross-repository credential is used.

These are **build inputs only**. Product packages contain the gateway, plugin and explicitly selected documentation/assets; they never install or bundle Qt libraries, IDA executables, licenses, settings or build trees. Actual plugin use still requires the supported IDA Professional 9.4 runtime with its bundled Qt 6.8.2 in namespace `QT`.

An explicitly selected local IDA Qt installation remains available for developer integration checks through `--qt-runtime` plus `--qt-sdk`; it is optional and is not used by hosted builds. Stock distribution Qt libraries use a different namespace and are not a substitute.

## Linux scripted packaging

Install the dependencies in [README-LINUX.md](../ida-agent-plugin/README-LINUX.md), initialize the SDK, then run:

```sh
git submodule update --init ida-sdk
python3 release/build_qt.py --prefix build/qt-public
python3 release/build_linux.py --qt-prefix build/qt-public
```

The release script runs Python packaging tests, Go vet/test/build and portable C++ tests, then creates `release/dist/ida-agent-<version>-linux-x64.tar.gz`, a desktop `.deb` and their SHA-256 files. The baseline is Ubuntu 24.04+ / Debian 13+ amd64 with system OpenSSL 3. Packaging also requires `dpkg-deb`, `librsvg2-bin`, `desktop-file-utils` and `appstream`.

The `.deb` includes a graphical setup window, application entry and the shared icon in SVG and seven PNG sizes. Ubuntu/Debian container jobs verify APT installation, GUI startup, manager reuse and shutdown, reinstallation, upgrade and removal before publication. See the [Linux installation guide](linux/INSTALL.md).

The packaged plugin has no build-machine RPATH and uses IDA's Qt libraries. `idat-with-agent` selects the same IDA installation's libraries for headless use. curl and SQLite remain private static libraries within the plugin. Licensed IDA and GUI integration tests stay opt-in.

## macOS scripted packaging

The runner needs macOS 15+, Xcode command line tools, CMake >= 3.25, Ninja, Go 1.25, Python >= 3.10 and the OpenSSL CLI for temporary test certificates. No IDA installation or license is needed to build, link, package or test the installer.

```sh
git submodule update --init ida-sdk
python3 release/build_qt.py --prefix build/qt-public
python3 -m venv build/macos-venv
build/macos-venv/bin/python -m pip install websockets==15.0.1
build/macos-venv/bin/python release/build_macos.py \
  --qt-prefix build/qt-public --python build/macos-venv/bin/python
```

The script validates Go and C++, builds and checks both architectures, merges the gateway slices with `lipo`, ad-hoc signs both binaries, checks dynamic dependencies and portable runtime paths, creates ZIP/DMG packages and checksums, then tests the mounted installer in temporary directories. Use `--zip-only` to omit the DMG. No normal IDA user directory is modified.

DMG creation and installer validation can also run separately on an existing ZIP:

```sh
version=$(cat ida-mcp/VERSION)
python3 release/build_macos_dmg.py --archive "release/dist/ida-agent-$version-macos-universal2.zip"
python3 release/tests/test_macos_installer.py --dmg "release/dist/ida-agent-$version-macos-universal2.dmg"
```

[macOS Universal 2 package](https://github.com/ackwrap/ida-pro-agent/blob/main/.github/workflows/macos-build.yml) uses GitHub's `macos-15` runner, public Qt sources and the same release script. Both binary slices are checked; CTest and installer tests execute natively on the runner's arm64 architecture. Licensed IDA GUI behavior requires separate validation. Developer ID signing/notarization is not configured.

## Workflows

| Workflow | Trigger | Result |
| --- | --- | --- |
| [Windows build and tests](https://github.com/ackwrap/ida-pro-agent/blob/main/.github/workflows/windows-build.yml) | Branch push, pull request or manual run | Gateway/Python validation, full Qt plugin and C++ tests |
| [Linux source tests](https://github.com/ackwrap/ida-pro-agent/blob/main/.github/workflows/linux-build.yml) | Branch push, pull request or manual run | Go/C++ MCP and independent AI backend tests |
| [Agent client regression](https://github.com/ackwrap/ida-pro-agent/blob/main/.github/workflows/agent-client-regression.yml) | Relevant push/PR or manual run | SDK compatibility on Windows, Linux and macOS |
| [Linux x64 package](https://github.com/ackwrap/ida-pro-agent/blob/main/.github/workflows/linux-package.yml) | Release call or manual `main`/`devel`/tag run | Public Qt build, full AI `.deb`/tar.gz and installation tests |
| [macOS Universal 2 package](https://github.com/ackwrap/ida-pro-agent/blob/main/.github/workflows/macos-build.yml) | Release call or manual `main`/`devel`/tag run | Public Qt build, full AI ZIP/DMG and installer tests |
| [Release packages](https://github.com/ackwrap/ida-pro-agent/blob/main/.github/workflows/windows-release.yml) | Matching public `v*` tag or manual `main`/tag run | Build all platforms; publish on tag push or when **publish** is selected |

Package builders use all available CPUs by default, respect `CMAKE_BUILD_PARALLEL_LEVEL`, and accept `--jobs N`; the separate Qt source build defaults to at most eight jobs. CTest concurrency is configured separately.

Build jobs have read-only repository tokens. Only the release publishing job receives the same public repository's `GITHUB_TOKEN` with **Contents: write**. The publisher checks that the destination is public and active, then relies on GitHub's release API to enforce write permission. Repository `permissions.push` metadata is not a precondition for an installation token.

## Configure public publishing

1. Set `origin` to `https://github.com/ackwrap/ida-pro-agent.git` and develop on `devel`, tracking `origin/devel`. Preserve the public Git history.
2. Enable GitHub Actions in the public repository. No custom Actions secret or private repository access is required for any platform. Obsolete source-read, source-sync and cross-repository release credentials can be removed from repository settings after old workflow runs have finished.
3. Validate and commit on `devel`, then push `git push origin devel`. For platform package validation, manually dispatch its packaging workflow on `devel`; these jobs do not publish a release.
4. Promote validated changes by fast-forward with `git push origin devel:main`. Fetch and rebase onto `origin/main` first if it moved; revalidate after rebasing. Do not commit directly to `main`.
5. For a new release, update `ida-mcp/VERSION` on `devel`, validate and promote that commit, then create and push only the matching new `v*` tag. Existing published tags must not move. The tag must match the central version.
6. A manual **Release packages (Windows, Linux, macOS)** run publishes only when **publish** is selected. Publication references the tested public commit and requires every platform to succeed.

Public usage documentation is maintained directly in root `README.md`, `USAGE.md` and `USAGE.zh-CN.md`; source guides are `README.source.md` and `README.source.zh-CN.md`. Retired source snapshot/synchronization tools and their duplicate documentation templates have been removed. See [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) for dependency licenses.

## Retry and local validation

Assets upload to a draft and their remote SHA-256 digests are checked before publication. Failed uploads leave a resumable draft. A published release is never overwritten: identical assets are accepted as an already completed run; different bytes fail explicitly. Unrelated drafts and unexpected assets are left for manual review.

If only publishing fails, fix the configuration and select **Re-run failed jobs** to reuse the tested packages. Rebuilding the same version can produce different installer bytes; use a new version to replace a published package. Package artifacts are retained for 30 days and test logs for 14 days.

```sh
python -m unittest discover -s release/tests -p 'test_*.py'
python release/publish_release.py --dry-run
```

Publishing uses Python 3.11 and GitHub CLI. The release workflow supplies `GH_TOKEN` automatically. Actions are pinned by commit SHA. Hosted workflows test compilation, linking, unit tests and installation; they do not launch licensed IDA.

## 中文配置说明

**源码、测试、构建和发布全部在公开仓库 `ackwrap/ida-pro-agent` 完成，不再依赖私有仓库、PAT 或私有 Qt 附件。**

- Windows 使用公开 IDA SDK 的 Qt 导入库。Linux/macOS 从 Qt 官方下载固定校验值的 6.8.2 源码，以 `QT` 命名空间构建共享 Release 链接库；macOS 同时包含 Intel 和 Apple Silicon 架构。
- 首次构建运行 `python3 release/build_qt.py --prefix build/qt-public`；Linux 打包运行 `python3 release/build_linux.py --qt-prefix build/qt-public`。macOS 使用同一前缀调用 `build_macos.py`，具体 Python 环境命令见上文。
- Actions 缓存公开 Qt 构建结果；缓存缺失时重新从官方源码构建，不需要额外 Secret。缓存命中后仍校验构建配方、头文件、版本、命名空间和架构。
- 安装包只含产品文件，不打包 Qt、IDA 程序或许可证。实际使用仍需要对应平台的 **IDA Professional 9.4 / Qt 6.8.2**；需要许可的真实 IDA UI/集成测试仍为可选验证。
- 开发使用 `devel`，完成验证后推送 `git push origin devel`。可在 `devel` 手动运行 Linux/macOS 打包检查；这些独立打包任务不会发布。
- 验证通过后用 `git push origin devel:main` 快进到稳定分支。新版本须更新 `ida-mcp/VERSION`，提交并提升后推送对应的新 `v*` 标签，自动触发三平台统一发布；已有标签不移动。
- 发布仅使用公开仓库自己的 `GITHUB_TOKEN`，发布任务具有 **Contents: write**。旧工作流运行结束后，可在仓库设置中删除已停用的源码读取、同步与跨仓库发布凭据。
- 三个平台和 Ubuntu/Debian 安装测试全部通过，且十一个二进制/校验附件验证成功后才正式发布。仅发布失败时用 **Re-run failed jobs** 复用已验证产物；已发布附件不会被覆盖。

Linux/macOS 尚未全面测试的说明仍保留。许可证与第三方依赖见 [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)。
