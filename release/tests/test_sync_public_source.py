from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import sys
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("sync_public_source", Path(__file__).resolve().parents[1] / "sync_public_source.py")
sync = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sync)


def git(root, *args, check=True):
    return subprocess.run(["git", "-c", "core.autocrlf=false", "-C", str(root), *args],
                          check=check, capture_output=True)


def commit(root, message="fixture"):
    git(root, "add", "--all")
    git(root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", message)
    return git(root, "rev-parse", "HEAD").stdout.decode().strip()


class SourceSyncTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ida source sync ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source, self.public = self.root / "source", self.root / "public"
        for root in [self.source, self.public]:
            root.mkdir()
            git(root, "init", "-b", "main")
        self.write(self.public, "README.md", "existing public usage\n")
        self.write(self.public, "PUBLIC_ONLY.md", "keep public additions\n")
        self.public_parent = commit(self.public, "existing documentation")
        git(self.public, "tag", "v0.4.5")
        initial = {
            "README.md": "[中文](README.zh-CN.md)\nsource build guide\n",
            "README.zh-CN.md": "[English](README.md)\n源码编译\n",
            "LICENSE": "project MIT license\n",
            "THIRD_PARTY_NOTICES.md": "dependencies retain their licenses\n",
            ".gitmodules": '[submodule "ida-sdk"]\n\tpath = ida-sdk\n\turl = https://github.com/HexRaysSA/ida-sdk.git\n',
            "ida-mcp/VERSION": "0.4.5\n",
            "ida-mcp/main.go": "committed source\n",
            "release/public/README.md": "public usage guide\n",
            "release/public/USAGE.md": "English usage\n",
            "release/public/USAGE.zh-CN.md": "中文使用说明\n",
            "release/linux/idat-with-agent": "#!/bin/sh\nexit 0\n",
        }
        for name, text in initial.items():
            self.write(self.source, name, text)
        commit(self.source)
        git(self.source, "update-index", "--add", "--cacheinfo", f"160000,{self.public_parent},ida-sdk")
        (self.source / "ida-sdk").mkdir()
        git(self.source, "update-index", "--chmod=+x", "release/linux/idat-with-agent")
        git(self.source, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "public SDK link")

    def write(self, root, name, text):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline='\n')

    def publish_fixture(self):
        revision, files = sync.snapshot(self.source)
        self.assertTrue(sync.apply_snapshot(self.public, revision, files))
        git(self.public, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "source snapshot")
        return revision, files

    def test_committed_snapshot_ignores_worktree_and_untracked_files(self):
        self.write(self.source, "ida-mcp/main.go", "uncommitted content\n")
        self.write(self.source, "ida-mcp/.env", "untracked local values\n")
        _, files = sync.snapshot(self.source)
        self.assertEqual(files["ida-mcp/main.go"][1], b"committed source\n")
        self.assertNotIn("ida-mcp/.env", files)

    def test_public_docs_and_source_guides_are_both_preserved(self):
        _, files = sync.snapshot(self.source)
        self.assertEqual(files["README.md"][1], b"public usage guide\n")
        self.assertIn(b"](README.source.zh-CN.md)", files["README.source.md"][1])
        self.assertIn(b"](README.source.md)", files["README.source.zh-CN.md"][1])
        self.assertEqual(files["USAGE.md"], files["release/public/USAGE.md"])

    def test_snapshot_keeps_sdk_pin_executable_mode_and_public_history(self):
        source_revision, _ = self.publish_fixture()
        sdk = git(self.public, "ls-tree", "HEAD", "ida-sdk").stdout.decode()
        self.assertIn(f"160000 commit {self.public_parent}", sdk)
        self.assertIn("100755", git(self.public, "ls-tree", "HEAD", "release/linux/idat-with-agent").stdout.decode())
        self.assertEqual(git(self.public, "rev-parse", "HEAD^").stdout.decode().strip(), self.public_parent)
        self.assertEqual(git(self.public, "rev-parse", "v0.4.5").stdout.decode().strip(), self.public_parent)
        self.assertNotEqual(git(self.public, "cat-file", "-e", source_revision, check=False).returncode, 0)
        self.assertEqual((self.public / "PUBLIC_ONLY.md").read_text(), "keep public additions\n")

    def test_repeat_snapshot_is_noop(self):
        revision, files = self.publish_fixture()
        self.assertFalse(sync.apply_snapshot(self.public, revision, files))
        self.assertEqual(git(self.public, "status", "--porcelain").stdout, b"")

    def test_deletion_removes_only_previous_managed_paths(self):
        self.publish_fixture()
        (self.source / "ida-mcp/main.go").unlink()
        commit(self.source, "remove obsolete source")
        revision, files = sync.snapshot(self.source)
        self.assertTrue(sync.apply_snapshot(self.public, revision, files))
        self.assertFalse((self.public / "ida-mcp/main.go").exists())
        self.assertTrue((self.public / "PUBLIC_ONLY.md").exists())
        self.assertIn(b"D\tida-mcp/main.go", git(self.public, "diff", "--cached", "--name-status").stdout)

    def test_dirty_public_checkout_is_refused(self):
        self.write(self.public, "README.md", "unsaved public edit")
        revision, files = sync.snapshot(self.source)
        with self.assertRaisesRegex(ValueError, "clean"):
            sync.apply_snapshot(self.public, revision, files)
        self.assertEqual((self.public / "README.md").read_text(), "unsaved public edit")

    def test_internal_plans_private_inputs_and_credentials_are_refused(self):
        for name in ["docs/local/plan.md", "build/private.txt", "qt-sdk/qt-6.8.2-linux/header.h",
                     "ida-mcp/.env", "release/private.key", "ida-agent-plugin/plugin.dll"]:
            with self.subTest(name=name):
                self.assertFalse(sync.allowed_source(name))
        self.write(self.source, "docs/local/plan.md", "internal plan")
        commit(self.source)
        with self.assertRaisesRegex(ValueError, "not approved"):
            sync.snapshot(self.source)

    def test_qt_plist_templates_are_source_configuration_not_link_libraries(self):
        name = "qt-sdk/qt-6.8.2-win/mkspecs/macx-clang/Info.plist.lib"
        self.write(self.source, name, "<plist><dict/></plist>")
        git(self.source, "add", "--force", "--", name)
        commit(self.source)
        _, files = sync.snapshot(self.source)
        self.assertEqual(files[name][1], b"<plist><dict/></plist>")
        self.assertFalse(sync.allowed_source("qt-sdk/qt-6.8.2-win/mkspecs/Qt6Core.lib"))
        self.assertFalse(sync.allowed_source("ida-mcp/Info.plist.lib"))

    def test_credential_shaped_content_is_refused_without_echoing_value(self):
        fake = "ghp_" + "A" * 40
        self.write(self.source, "ida-mcp/main.go", fake)
        commit(self.source)
        with self.assertRaises(ValueError) as context:
            sync.snapshot(self.source)
        self.assertNotIn(fake, str(context.exception))
        self.assertIn("ida-mcp/main.go", str(context.exception))

    def test_private_sdk_url_is_refused(self):
        self.write(self.source, ".gitmodules", '[submodule "ida-sdk"]\npath = ida-sdk\nurl = https://private.example/sdk.git\n')
        commit(self.source)
        with self.assertRaisesRegex(ValueError, "pinned public IDA SDK"):
            sync.snapshot(self.source)

    def test_manifest_cannot_remove_unrelated_or_parent_paths(self):
        self.publish_fixture()
        path = self.public / sync.MANIFEST
        manifest = json.loads(path.read_text())
        manifest["files"].append("../outside.txt")
        path.write_text(json.dumps(manifest))
        commit(self.public, "invalid public manifest")
        revision, files = sync.snapshot(self.source)
        with self.assertRaisesRegex(ValueError, "unapproved path"):
            sync.apply_snapshot(self.public, revision, files)
        self.assertTrue((self.public / "PUBLIC_ONLY.md").exists())

    def test_unsafe_names_and_git_metadata_are_refused(self):
        for name in ["/etc/passwd", "../file", "release/../file", "release/.git/config",
                     "release/.GiT/config", "C:/file", "release\\file"]:
            with self.subTest(name=name):
                self.assertFalse(sync.safe_name(name))

    @unittest.skipIf(os.name == "nt", "Symlink parent protection also runs on Linux CI")
    def test_public_symlink_parent_is_refused_before_any_write(self):
        outside = self.root / "outside"
        outside.mkdir()
        (self.public / "ida-mcp").symlink_to(outside, target_is_directory=True)
        commit(self.public)
        revision, files = sync.snapshot(self.source)
        before = (self.public / "README.md").read_bytes()
        with self.assertRaisesRegex(ValueError, "symlink"):
            sync.apply_snapshot(self.public, revision, files)
        self.assertEqual((self.public / "README.md").read_bytes(), before)
        self.assertEqual(list(outside.iterdir()), [])

    def test_cli_preview_is_clean_after_clone_with_windows_line_ending_defaults(self):
        destination = self.root / "cli preview"
        actual_run = subprocess.run
        metadata = {"private": False, "archived": False, "default_branch": "main"}

        def local_remote(command, **kwargs):
            if command[0] == "git" and "clone" in command:
                rewritten = list(command)
                rewritten[-2] = str(self.public)
                result = actual_run(rewritten, **kwargs, capture_output=True)
                actual_run(["git", "-C", str(destination), "remote", "set-url", "origin",
                            "https://github.com/ackwrap/ida-pro-agent.git"], check=True, capture_output=True)
                return result
            if command[0] == "git" and "fetch" in command:
                return subprocess.CompletedProcess(command, 0, b"", b"")
            return actual_run(command, **kwargs)

        argv = ["sync_public_source.py", "--source", str(self.source), "--destination", str(destination), "--transport", "https"]
        env = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.autocrlf", "GIT_CONFIG_VALUE_0": "true"}
        with patch.dict(os.environ, env), patch.object(sys, "argv", argv), redirect_stdout(io.StringIO()):
            with patch.object(sync.urllib.request, "urlopen", return_value=io.BytesIO(json.dumps(metadata).encode())):
                with patch.object(sync.subprocess, "run", side_effect=local_remote):
                    self.assertEqual(sync.main(), 0)
        self.assertEqual((destination / "ida-mcp/main.go").read_bytes(), b"committed source" + bytes([10]))
        self.assertEqual(git(destination, "rev-parse", "HEAD").stdout.decode().strip(), self.public_parent)
        self.assertTrue((destination / sync.MANIFEST).is_file())

    def test_private_archived_and_wrong_default_branch_targets_are_refused(self):
        for metadata in [{"private": True, "archived": False, "default_branch": "main"},
                         {"private": False, "archived": True, "default_branch": "main"},
                         {"private": False, "archived": False, "default_branch": "other"}]:
            with self.subTest(metadata=metadata):
                with patch.object(sync.urllib.request, "urlopen", return_value=io.BytesIO(json.dumps(metadata).encode())):
                    with self.assertRaises(ValueError):
                        sync.validate_public_repository("ackwrap/ida-pro-agent", "main")

    def test_public_default_branch_target_is_accepted(self):
        metadata = {"private": False, "archived": False, "default_branch": "main"}
        with patch.object(sync.urllib.request, "urlopen", return_value=io.BytesIO(json.dumps(metadata).encode())):
            sync.validate_public_repository("ackwrap/ida-pro-agent", "main")


if __name__ == "__main__":
    unittest.main()