#!/usr/bin/env python3
"""Publish the complete three-platform release to a separate public repository."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPOSITORY = "ackwrap/ida-pro-agent"
MARKER = "<!-- ida-agent managed binary release -->"


def sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


class GitHub:
    def run(self, *args: str) -> str:
        environment = os.environ.copy()
        environment.update({"GH_HOST": "github.com", "GH_PROMPT_DISABLED": "1"})
        # Never log the token or raw CLI error bodies.
        result = subprocess.run(
            ["gh", *args], env=environment, capture_output=True,
            text=True, encoding="utf-8", errors="replace", check=False,
        )
        if result.returncode:
            raise RuntimeError(
                f"GitHub CLI {' '.join(args[:2])} failed. Check repository access, "
                "Contents: write permission, token expiry, and tag rules in the public repository."
            )
        return result.stdout

    def api(self, path: str, *, paginate: bool = False, payload: Path | None = None):
        arguments = ["api", "--hostname", "github.com", "-H", "X-GitHub-Api-Version: 2026-03-10", path]
        if payload is not None:
            arguments.extend(["--method", "POST", "--input", str(payload)])
        if paginate:
            arguments.extend(["--paginate", "--slurp"])
        value = json.loads(self.run(*arguments))
        return [item for page in value for item in page] if paginate else value


def validate_repository(repository: str, source: str = "") -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9._-]*", repository):
        raise ValueError("Release repository must be owner/repo, without a URL or .git suffix.")
    if repository.endswith(".git") or repository.lower() == source.lower():
        raise ValueError("Select a separate public release repository, not the source repository.")
    return repository


def collect_assets(directory: Path, version: str) -> list[Path]:
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("The release version must contain three numeric components.")
    # No globs: source archives, PDBs, build logs, and unrelated files cannot be selected.
    filenames = [f"ida-agent-{version}-{platform}{suffix}"
                 for platform, suffixes in (
                     ("windows-x64", (".zip", "-setup.exe", "-setup.exe.sha256")),
                     ("linux-x64", (".tar.gz", ".tar.gz.sha256")),
                     ("macos-universal2", (".zip", ".zip.sha256", ".dmg", ".dmg.sha256")))
                 for suffix in suffixes]
    assets = [directory / name for name in filenames]
    for path in assets:
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"Missing or invalid release asset: {path.name}")
        if path.resolve().parent != directory.resolve():
            raise ValueError("Release assets must be direct children of the artifact directory.")
    for checksum in (path for path in assets if path.suffix == ".sha256"):
        binary = checksum.with_suffix("")
        expected = f"{sha256(binary)}  {binary.name}"
        if checksum.read_text(encoding="ascii").strip() != expected:
            raise ValueError(f"The checksum does not match the package: {binary.name}")
    return assets


def release_notes(version: str) -> str:
    notes = f"""{MARKER}
# ida-agent {version}

Requires **IDA Professional 9.4** and its bundled **Qt 6.8.2** for the selected platform.
需要对应平台的 **IDA Professional 9.4** 及其自带的 **Qt 6.8.2**。

| Platform / 平台 | Downloads / 下载 |
| --- | --- |
| Windows x64 | `*-windows-x64-setup.exe` installer / 安装器；`*-windows-x64.zip` portable / 便携包 |
| Linux x64 (Ubuntu 24.04 baseline) | `*-linux-x64.tar.gz`: Gateway, full AI Chat plugin and client skills / Gateway、完整 AI Chat 插件及客户端技能 |
| macOS 15+, Intel + Apple Silicon | `*-macos-universal2.dmg` installer / 安装器；`*-macos-universal2.zip` portable / 便携包 |

Close IDA before installing or upgrading. Extracted packages contain per-file `SHA256SUMS.txt`;
installers and Linux/macOS archives also have separate `.sha256` files.
安装或升级前请关闭 IDA。解压包内含逐文件 `SHA256SUMS.txt`，安装器及 Linux/macOS 压缩包另附 `.sha256` 校验文件。

No IDA or Qt runtime libraries are bundled. Linux requires system OpenSSL 3 and CA certificates.
macOS uses native networking and does not require OpenSSL; its binaries are ad-hoc signed, without Developer ID notarization.
不附带 IDA 或 Qt 运行库。Linux 需要系统 OpenSSL 3 和 CA 证书；macOS 使用原生网络接口，无需 OpenSSL，使用临时签名，未做 Developer ID 公证。

**Linux and macOS have not been comprehensively tested. Please [report bugs](https://github.com/ackwrap/ida-pro-agent/issues)
with OS, CPU architecture, IDA version, reproduction steps and logs with secrets removed.**

**Linux 和 macOS 版本尚未经过全面测试。如遇问题，请[提交 Bug / Issue](https://github.com/ackwrap/ida-pro-agent/issues)，
附上操作系统、CPU 架构、IDA 版本、复现步骤及已去除密钥的相关日志。**
"""
    changelog = ROOT / "release" / "notes" / f"{version}.md"
    if changelog.is_file():
        notes += "\n" + changelog.read_text(encoding="utf-8").strip() + "\n"
    return notes


def verify_assets(remote: list[dict], assets: list[Path]) -> None:
    expected = {path.name: path for path in assets}
    if len(remote) != len(expected) or {item["name"] for item in remote} != set(expected):
        raise RuntimeError("The release must contain exactly the expected three-platform binary-package assets.")
    for item in remote:
        path = expected[item["name"]]
        if (item.get("state") != "uploaded" or item.get("size") != path.stat().st_size
                or item.get("digest") != "sha256:" + sha256(path)):
            raise RuntimeError(f"Remote release asset does not match the local package: {path.name}")


def publish(github: GitHub, repository: str, version: str, assets: list[Path]) -> str:
    metadata = github.api(f"repos/{repository}")
    if metadata.get("private") is not False or metadata.get("visibility") != "public":
        raise ValueError("The release destination must be a public repository.")
    if metadata.get("archived") or not metadata.get("permissions", {}).get("push"):
        raise ValueError("The release token needs Contents: write on an active public repository.")
    tag = f"v{version}"
    releases = github.api(f"repos/{repository}/releases?per_page=100", paginate=True)
    matches = [item for item in releases if item["tag_name"] == tag]
    if len(matches) > 1:
        raise RuntimeError("Multiple releases use this tag; resolve the duplicate drafts first.")
    release = matches[0] if matches else None
    if release:
        remote = github.api(f"repos/{repository}/releases/{release['id']}/assets?per_page=100", paginate=True)
        if not release["draft"]:
            # Rerunning only the failed publishing job reuses the same artifact.
            # Published assets are never overwritten, including immutable releases.
            verify_assets(remote, assets)
            return f"https://github.com/{repository}/releases/tag/{tag}"
        if MARKER not in (release.get("body") or ""):
            raise RuntimeError("An unrelated draft exists for this tag; it will not be modified.")
        allowed = {path.name for path in assets}
        if any(item["name"] not in allowed for item in remote):
            raise RuntimeError("The draft contains unexpected assets; review it before retrying.")

    with tempfile.TemporaryDirectory(prefix="ida-agent-release-") as temporary:
        notes = Path(temporary) / "release-notes.md"
        notes.write_text(release_notes(version), encoding="utf-8", newline="\n")
        if release is None:
            # Resolve a commit belonging to the PUBLIC repository, never GITHUB_SHA.
            branch = quote(metadata["default_branch"], safe="")
            head = github.api(f"repos/{repository}/commits/{branch}")
            if not re.fullmatch(r"[0-9a-f]{40}", head.get("sha", "")):
                raise RuntimeError("Initialize the public repository with a README commit first.")
            payload = Path(temporary) / "create-release.json"
            payload.write_text(json.dumps({
                "tag_name": tag, "target_commitish": head["sha"],
                "name": f"ida-agent {version}", "body": release_notes(version), "draft": True,
            }), encoding="utf-8")
            # The release list can lag behind creation. Use the POST response's ID.
            release = github.api(f"repos/{repository}/releases", payload=payload)
            if (not isinstance(release.get("id"), int) or release.get("id", 0) <= 0
                    or release.get("tag_name") != tag or release.get("draft") is not True
                    or MARKER not in (release.get("body") or "")):
                raise RuntimeError("GitHub did not confirm the newly created draft release.")
        github.run("release", "upload", tag, *(str(path) for path in assets),
                   "--repo", repository, "--clobber")
        remote = github.api(f"repos/{repository}/releases/{release['id']}/assets?per_page=100", paginate=True)
        verify_assets(remote, assets)
        github.run("release", "edit", tag, "--repo", repository, "--draft=false",
                   "--latest", "--title", f"ida-agent {version}", "--notes-file", str(notes))
    completed = github.api(f"repos/{repository}/releases/{release['id']}")
    if completed.get("draft") is not False or completed.get("tag_name") != tag:
        raise RuntimeError("GitHub did not confirm that the release was published.")
    return f"https://github.com/{repository}/releases/tag/{tag}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, default=ROOT / "release/dist")
    parser.add_argument("--dry-run", action="store_true", help="validate local assets without GitHub access")
    args = parser.parse_args()
    try:
        repository = validate_repository(
            os.environ.get("IDA_AGENT_RELEASE_REPOSITORY", DEFAULT_REPOSITORY),
            os.environ.get("GITHUB_REPOSITORY", ""),
        )
        version = (ROOT / "ida-mcp/VERSION").read_text(encoding="ascii").strip()
        assets = collect_assets(args.assets, version)
        if args.dry_run:
            print(json.dumps({"repository": repository, "tag": f"v{version}",
                              "assets": {path.name: sha256(path) for path in assets}}, indent=2))
            return 0
        if not os.environ.get("GH_TOKEN"):
            raise ValueError("Set the source repository secret IDA_AGENT_RELEASE_TOKEN before publishing.")
        url = publish(GitHub(), repository, version, assets)
        print(f"Published: {url}")
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
                summary.write(f"Public release: [{version}]({url})\n")
        return 0
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Release publishing failed: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
