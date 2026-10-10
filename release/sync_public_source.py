#!/usr/bin/env python3
"""Publish a committed source snapshot without copying private Git history."""

from __future__ import annotations

import argparse
import configparser
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import urllib.request

MANIFEST = ".source-sync.json"
SOURCE_REPOSITORY = "ackwrap/ida-agent"
PUBLIC_REPOSITORY = "ackwrap/ida-pro-agent"
ROOT_FILES = {
    ".gitattributes", ".gitignore", ".gitmodules", "AGENTS.md", "LICENSE",
    "THIRD_PARTY_NOTICES.md", "README.md", "README.zh-CN.md",
}
SOURCE_DIRS = {"ida-agent-plugin", "ida-mcp", "mcp-test-project", "protocol", "release", "skills"}
PUBLIC_DOCS = {"README.md", "USAGE.md", "USAGE.zh-CN.md"}
DOC_RENAMES = {"README.md": "README.source.md", "README.zh-CN.md": "README.source.zh-CN.md"}
SECRET_PATTERNS = [
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"gh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(rb"github_pat_[A-Za-z0-9_]{30,}"),
    re.compile(rb"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{25,}"),
]
BINARY_SUFFIXES = {".dll", ".so", ".dylib", ".exe", ".lib", ".a", ".zip", ".gz", ".idb", ".i64", ".pem", ".key", ".p12"}


def git(root: Path, *args: str, data: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-c", "core.autocrlf=false", "-C", str(root), *args], input=data,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)


def safe_name(name: str) -> bool:
    parts = PurePosixPath(name).parts
    return bool(parts) and not name.startswith("/") and "\\" not in name and all(
        part.lower() not in {".", "..", ".git"} for part in parts
    ) and str(PurePosixPath(name)) == name and ":" not in name


def allowed_source(name: str) -> bool:
    if not safe_name(name):
        return False
    path = PurePosixPath(name)
    qt_plist_template = (name.startswith("qt-sdk/qt-6.8.2-win/mkspecs/") and
                         path.name == "Info.plist.lib")
    if path.name.startswith(".env") or (path.suffix.lower() in BINARY_SUFFIXES and not qt_plist_template):
        return False
    if name in ROOT_FILES or name == "ida-sdk" or name == "docs/UPGRADING.md":
        return True
    return (path.parts[0] in SOURCE_DIRS or
            name.startswith(".github/workflows/") or
            name.startswith("qt-sdk/qt-6.8.2-win/"))


def allowed_public(name: str) -> bool:
    return allowed_source(name) or name in DOC_RENAMES.values() or name in PUBLIC_DOCS


def snapshot(source: Path, revision: str = "HEAD") -> tuple[str, dict[str, tuple[str, bytes]]]:
    commit = git(source, "rev-parse", "--verify", f"{revision}^{{commit}}").stdout.decode().strip()
    tree = git(source, "ls-tree", "-r", "-z", "--full-tree", commit).stdout
    entries = {}
    for row in tree.split(b"\0"):
        if not row:
            continue
        metadata, raw_name = row.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split()
        name = raw_name.decode("utf-8")
        if not allowed_source(name):
            raise ValueError(f"Tracked path is not approved for public source: {name}")
        if mode not in {"100644", "100755"} and not (name == "ida-sdk" and mode == "160000"):
            raise ValueError(f"Unsupported tracked file mode: {name} ({mode})")
        entries[name] = (mode, kind, oid)
    archive = git(source, "archive", "--format=tar", commit).stdout
    files = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        for member in tar:
            if member.isdir():
                continue
            name = member.name
            if name not in entries or not member.isfile():
                raise ValueError(f"Unexpected archive member: {name}")
            mode = entries[name][0]
            stream = tar.extractfile(member)
            if stream is None:
                raise ValueError(f"Unreadable archive member: {name}")
            data = stream.read()
            if any(pattern.search(data) for pattern in SECRET_PATTERNS):
                raise ValueError(f"Credential-shaped content requires review: {name}")
            public_name = DOC_RENAMES.get(name, name)
            if name in DOC_RENAMES:
                for old, new in DOC_RENAMES.items():
                    data = data.replace(f"]({old})".encode(), f"]({new})".encode())
            files[public_name] = (mode, data)
    for name, (mode, kind, oid) in entries.items():
        public_name = DOC_RENAMES.get(name, name)
        if mode == "160000":
            files[name] = (mode, oid.encode())
        elif public_name not in files:
            raise ValueError(f"Archive omitted tracked source: {name}")
    for name in PUBLIC_DOCS:
        source_name = f"release/public/{name}"
        if source_name not in files:
            raise ValueError(f"Missing maintained public document: {source_name}")
        files[name] = files[source_name]
    required = {"LICENSE", "THIRD_PARTY_NOTICES.md", ".gitmodules", "ida-sdk", "ida-mcp/VERSION"}
    if not required.issubset(files):
        raise ValueError("The public snapshot lacks required license, SDK or version files")
    modules = configparser.RawConfigParser()
    modules.read_string(files[".gitmodules"][1].decode())
    section = 'submodule "ida-sdk"'
    if (modules.sections() != [section] or dict(modules[section]) != {
            "path": "ida-sdk", "url": "https://github.com/HexRaysSA/ida-sdk.git"}):
        raise ValueError("Only the pinned public IDA SDK submodule may be synchronized")
    return commit, files


def destination_path(root: Path, name: str) -> Path:
    if not safe_name(name):
        raise ValueError(f"Unsafe public path: {name}")
    path = root / name
    parent = path.parent
    while parent != root:
        if parent.is_symlink():
            raise ValueError(f"Public path traverses a symlink: {name}")
        parent = parent.parent
    if not path.parent.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"Public path escapes the checkout: {name}")
    return path


def apply_snapshot(destination: Path, commit: str, files: dict[str, tuple[str, bytes]]) -> bool:
    destination = destination.resolve()
    top = git(destination, "rev-parse", "--show-toplevel").stdout.decode().strip()
    if Path(top).resolve() != destination:
        raise ValueError("Destination must be the root of its own checkout")
    if git(destination, "status", "--porcelain", "--untracked-files=all").stdout:
        raise ValueError("Public checkout must be clean before synchronization")
    previous = git(destination, "show", f"HEAD:{MANIFEST}", check=False)
    old_files = set()
    if previous.returncode == 0:
        manifest = json.loads(previous.stdout)
        if (manifest.get("format_version") != 1 or
                manifest.get("source_repository") != SOURCE_REPOSITORY or
                not isinstance(manifest.get("files"), list)):
            raise ValueError("Unrecognized source synchronization manifest")
        old_files = set(manifest["files"])
        if not all(isinstance(name, str) and allowed_public(name) for name in old_files):
            raise ValueError("The source manifest contains an unapproved path")
    if not all(allowed_public(name) for name in files):
        raise ValueError("The source snapshot contains an unapproved path")
    # Check every path before writing or removing any managed file.
    for name in old_files | files.keys() | {MANIFEST}:
        destination_path(destination, name)
    for name in old_files - files.keys():
        path = destination_path(destination, name)
        if path.is_dir() and not path.is_symlink():
            path.rmdir()  # An initialized submodule/nonempty directory is never removed.
        elif path.exists() or path.is_symlink():
            path.unlink()
    for name, (mode, data) in files.items():
        if mode == "160000":
            path = destination_path(destination, name)
            if path.is_symlink() or (path.exists() and not path.is_dir()):
                raise ValueError(f"Public submodule path is not a directory: {name}")
            path.mkdir(exist_ok=True)
            continue
        path = destination_path(destination, name)
        if path.is_symlink():
            path.unlink()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o755 if mode == "100755" else 0o644)
    manifest = {"format_version": 1, "source_repository": SOURCE_REPOSITORY,
                "source_commit": commit, "version": files["ida-mcp/VERSION"][1].decode().strip(),
                "files": sorted(files)}
    (destination / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    regular = {name for name, (mode, _) in files.items() if mode != "160000"}
    staged = sorted(regular | (old_files - files.keys()) | {MANIFEST})
    paths = b"".join(f":(literal){name}".encode() + b"\0" for name in staged)
    git(destination, "add", "--all", "--force", "--pathspec-from-file=-", "--pathspec-file-nul", data=paths)
    for name, (mode, data) in files.items():
        if mode == "160000":
            git(destination, "update-index", "--add", "--cacheinfo", f"160000,{data.decode()},{name}")
    # Preserve executable bits on Windows as well as Unix.
    for mode, option in [("100755", "+x"), ("100644", "-x")]:
        names = [name for name, (file_mode, _) in files.items() if file_mode == mode]
        if names:
            git(destination, "update-index", f"--chmod={option}", "-z", "--stdin",
                data=b"".join(name.encode() + b"\0" for name in names))
    return git(destination, "diff", "--cached", "--quiet", check=False).returncode != 0


def validate_public_repository(repository: str, branch: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Repository must have owner/name format")
    request = urllib.request.Request(f"https://api.github.com/repos/{repository}",
                                     headers={"Accept": "application/vnd.github+json", "User-Agent": "ida-agent-source-sync"})
    token = os.environ.get("GH_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=30) as response:
        metadata = json.load(response)
    if metadata.get("private") is not False or metadata.get("archived") is not False:
        raise ValueError("Source synchronization requires an active public repository")
    if metadata.get("default_branch") != branch:
        raise ValueError("Synchronization must target the public default branch")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--repository", default=PUBLIC_REPOSITORY)
    parser.add_argument("--branch", default="main")
    parser.add_argument("--transport", choices=["ssh", "https"], default="ssh")
    parser.add_argument("--push", action="store_true", help="Commit and push; otherwise stage a reviewable preview")
    args = parser.parse_args()
    source, destination = args.source.resolve(), args.destination.resolve()
    if source == destination or destination.is_relative_to(source / ".git"):
        raise ValueError("Source and public checkouts must be separate")
    validate_public_repository(args.repository, args.branch)
    commit, files = snapshot(source)
    url = (f"git@github.com:{args.repository}.git" if args.transport == "ssh"
           else f"https://github.com/{args.repository}.git")
    if not destination.exists():
        destination.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "-c", "core.autocrlf=false", "clone", "--depth", "1", "--single-branch", "--branch", args.branch,
                        url, str(destination)], check=True)
    if git(destination, "remote", "get-url", "origin").stdout.decode().strip() != url:
        raise ValueError("Public checkout origin does not match the requested repository/transport")
    if git(destination, "symbolic-ref", "--short", "HEAD").stdout.decode().strip() != args.branch:
        raise ValueError("Public checkout is on the wrong branch")
    if git(destination, "status", "--porcelain", "--untracked-files=all").stdout:
        raise ValueError("Public checkout must be clean before updating it")
    git(destination, "fetch", "origin", args.branch)
    git(destination, "merge", "--ff-only", f"origin/{args.branch}")
    changed = apply_snapshot(destination, commit, files)
    version = files["ida-mcp/VERSION"][1].decode().strip()
    print(f"Source {commit}, version {version}: {len(files)} managed paths")
    if not changed:
        print("Public source is already synchronized; no commit or push needed.")
        return 0
    print(git(destination, "diff", "--cached", "--shortstat").stdout.decode())
    if args.push:
        git(destination, "-c", "user.name=ida-agent source sync", "-c",
            "user.email=41898282+github-actions[bot]@users.noreply.github.com", "commit", "-m",
            f"chore: sync ida-agent source {version}", "-m", f"Source-commit: {commit}")
        # A concurrent public edit causes a normal non-fast-forward rejection, never a force push.
        git(destination, "push", "origin", f"HEAD:refs/heads/{args.branch}")
        public_commit = git(destination, "rev-parse", "HEAD").stdout.decode().strip()
        print(f"Published https://github.com/{args.repository}/commit/{public_commit}")
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as stream:
                stream.write(f"Synchronized **{len(files)}** source paths from `{commit}` to "
                             f"[public commit](https://github.com/{args.repository}/commit/{public_commit}).\n")
    else:
        print("Preview staged. Review the destination diff; rerun on a clean checkout with --push to publish.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, subprocess.CalledProcessError) as error:
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stderr.decode(errors="replace") if error.stderr else str(error))
        else:
            print(str(error))
        raise SystemExit(1)
