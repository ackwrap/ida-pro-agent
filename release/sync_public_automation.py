#!/usr/bin/env python3
"""Synchronize from public Actions, then dispatch checks and matching releases."""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.error
import urllib.request

from sync_public_source import PUBLIC_REPOSITORY, SOURCE_REPOSITORY, git

CHECK_WORKFLOWS = ("windows-build.yml", "linux-build.yml", "agent-client-regression.yml")
RELEASE_WORKFLOW = "windows-release.yml"


class GitHub:
    def __init__(self, token: str):
        self.token = token

    def api(self, path: str, *, payload: dict | None = None, missing: bool = False):
        data = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(
            f"https://api.github.com/{path}", data=data,
            headers={"Accept": "application/vnd.github+json", "Content-Type": "application/json",
                     "Authorization": f"Bearer {self.token}", "User-Agent": "ida-agent-public-sync",
                     "X-GitHub-Api-Version": "2026-03-10"},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = response.read()
                return json.loads(body) if body else None
        except urllib.error.HTTPError as error:
            if missing and error.code == 404:
                return None
            # Do not print authenticated requests or raw error bodies.
            raise RuntimeError(f"GitHub request failed with HTTP {error.code}; check token permissions.") from None
        except urllib.error.URLError:
            raise RuntimeError("GitHub could not be reached; retry source synchronization.") from None


def commit_sha(github: GitHub, repository: str, ref: dict) -> str:
    obj = ref["object"]
    for _ in range(5):
        if not re.fullmatch(r"[0-9a-f]{40}", obj.get("sha", "")):
            raise ValueError("GitHub returned an invalid tag object")
        if obj["type"] == "commit":
            return obj["sha"]
        if obj["type"] != "tag":
            break
        obj = github.api(f"repos/{repository}/git/tags/{obj['sha']}")["object"]
    raise ValueError("Release tag does not resolve to a commit")


def dispatch_checks(github: GitHub, public_commit: str) -> list[str]:
    dispatched = []
    for workflow in CHECK_WORKFLOWS:
        prefix = f"repos/{PUBLIC_REPOSITORY}/actions/workflows/{workflow}"
        runs = github.api(f"{prefix}/runs?head_sha={public_commit}&per_page=1")
        if not runs["workflow_runs"]:
            github.api(f"{prefix}/dispatches", payload={"ref": "main"})
            dispatched.append(workflow)
    return dispatched


def dispatch_release(public: GitHub, source: GitHub, source_commit: str,
                     public_commit: str, version: str) -> bool:
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Release version must contain three numeric components")
    tag = f"v{version}"
    source_ref = source.api(f"repos/{SOURCE_REPOSITORY}/git/ref/tags/{tag}", missing=True)
    # Never release untagged development changes, even if VERSION has not changed.
    if source_ref is None or commit_sha(source, SOURCE_REPOSITORY, source_ref) != source_commit:
        return False
    public_ref = public.api(f"repos/{PUBLIC_REPOSITORY}/git/ref/tags/{tag}", missing=True)
    if public_ref is None:
        public.api(f"repos/{PUBLIC_REPOSITORY}/git/refs",
                   payload={"ref": f"refs/tags/{tag}", "sha": public_commit})
        release_commit = public_commit
    else:
        # Existing public tags, including old documentation snapshots, never move.
        release_commit = commit_sha(public, PUBLIC_REPOSITORY, public_ref)
    release = public.api(f"repos/{PUBLIC_REPOSITORY}/releases/tags/{tag}", missing=True)
    if release is not None and not release["draft"]:
        return False
    prefix = f"repos/{PUBLIC_REPOSITORY}/actions/workflows/{RELEASE_WORKFLOW}"
    runs = public.api(f"{prefix}/runs?head_sha={release_commit}&per_page=1")
    if runs["workflow_runs"]:
        # Includes failed runs: retry them explicitly instead of rebuilding every poll.
        return False
    public.api(f"{prefix}/dispatches", payload={"ref": tag, "inputs": {"publish": "true"}})
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    if os.environ.get("GITHUB_REPOSITORY") != PUBLIC_REPOSITORY:
        raise ValueError("Automation must run in the public ida-pro-agent repository")
    public_token, source_token = os.environ.get("GH_TOKEN"), os.environ.get("SOURCE_READ_TOKEN")
    if not public_token or not source_token:
        raise ValueError("Configure IDA_AGENT_SOURCE_READ_TOKEN in the public repository first")
    environment = os.environ.copy()
    environment.pop("SOURCE_READ_TOKEN", None)
    # An ephemeral Git header permits public pushes without persisting either token.
    header = base64.b64encode(f"x-access-token:{public_token}".encode()).decode()
    count = int(environment.get("GIT_CONFIG_COUNT", "0"))
    environment.update({"GIT_CONFIG_COUNT": str(count + 1),
                        f"GIT_CONFIG_KEY_{count}": "http.https://github.com/.extraheader",
                        f"GIT_CONFIG_VALUE_{count}": f"AUTHORIZATION: basic {header}"})
    subprocess.run([os.sys.executable, str(Path(__file__).with_name("sync_public_source.py")),
                    "--source", str(args.source.resolve()), "--destination", str(args.destination.resolve()),
                    "--transport", "https", "--push"], env=environment, check=True)
    source_commit = git(args.source, "rev-parse", "HEAD").stdout.decode().strip()
    public_commit = git(args.destination, "rev-parse", "HEAD").stdout.decode().strip()
    version = git(args.source, "show", "HEAD:ida-mcp/VERSION").stdout.decode().strip()
    public, source = GitHub(public_token), GitHub(source_token)
    checks = dispatch_checks(public, public_commit)
    released = dispatch_release(public, source, source_commit, public_commit, version)
    message = f"Public checks dispatched: {', '.join(checks) or 'already present'}. Release dispatched: {released}."
    print(message)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
            summary.write(message + "\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Public source synchronization failed: {error}")
        raise SystemExit(1)
