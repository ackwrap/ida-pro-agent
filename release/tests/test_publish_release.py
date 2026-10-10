import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import publish_release as publisher


REPOSITORY = "example/public-downloads"
PUBLIC_HEAD = "a" * 40


class FakeGitHub:
    def __init__(self, assets, release=None):
        self.metadata = {"private": False, "visibility": "public", "archived": False,
                         "permissions": {"push": True}, "default_branch": "main"}
        self.assets = assets
        self.release = copy.deepcopy(release)
        self.remote = []
        self.calls = []
        self.corrupt_upload = False
        self.empty_repository = False
        self.fail_upload = False
        self.hide_created_from_list = False
        self.invalid_created_draft = False
        self.list_reads = 0

    def uploaded_assets(self):
        return [{"name": path.name, "state": "uploaded", "size": path.stat().st_size,
                 "digest": "sha256:" + publisher.sha256(path)} for path in self.assets]

    def api(self, path, *, paginate=False, payload=None):
        if payload is not None:
            assert path == f"repos/{REPOSITORY}/releases"
            request = json.loads(payload.read_text(encoding="utf-8"))
            self.calls.append(("api", "create", request))
            assert request["target_commitish"] == PUBLIC_HEAD
            assert request["draft"] is True
            assert publisher.MARKER in request["body"] and "PRIVATE_SOURCE" not in request["body"]
            self.release = {"id": 7, "tag_name": request["tag_name"], "draft": True,
                            "body": request["body"]}
            return {**self.release, "draft": False} if self.invalid_created_draft else copy.deepcopy(self.release)
        if path == f"repos/{REPOSITORY}":
            return copy.deepcopy(self.metadata)
        if path.endswith("/releases?per_page=100"):
            self.list_reads += 1
            if self.hide_created_from_list:
                return []
            return [copy.deepcopy(self.release)] if self.release else []
        if path.endswith("/commits/main"):
            if self.empty_repository:
                raise RuntimeError("Repository is empty")
            return {"sha": PUBLIC_HEAD}
        if path.endswith("/assets?per_page=100"):
            return copy.deepcopy(self.remote)
        if path.endswith("/releases/7"):
            return copy.deepcopy(self.release)
        raise AssertionError(path)

    def run(self, *arguments):
        self.calls.append(arguments)
        if arguments[:2] == ("release", "upload"):
            assert self.release["draft"]
            if self.fail_upload:
                raise RuntimeError("Interrupted upload")
            self.remote = self.uploaded_assets()
            if self.corrupt_upload:
                self.remote[0]["digest"] = "sha256:" + "0" * 64
        elif arguments[:2] == ("release", "edit"):
            assert self.release["draft"]
            self.release["draft"] = False
        else:
            raise AssertionError(arguments)
        return ""


class PublishReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        base = "ida-agent-0.3.0-windows-x64"
        self.zip = self.directory / f"{base}.zip"
        self.installer = self.directory / f"{base}-setup.exe"
        self.checksum = self.directory / f"{base}-setup.exe.sha256"
        self.zip.write_bytes(b"portable package")
        self.installer.write_bytes(b"installer")
        self.checksum.write_text(f"{publisher.sha256(self.installer)}  {self.installer.name}\n", encoding="ascii")
        for platform, suffixes in (("linux-x64", (".tar.gz",)), ("macos-universal2", (".zip", ".dmg"))):
            for suffix in suffixes:
                package = self.directory / f"ida-agent-0.3.0-{platform}{suffix}"
                package.write_bytes(b"platform package")
                Path(str(package) + ".sha256").write_text(
                    f"{publisher.sha256(package)}  {package.name}\n", encoding="ascii")
        self.assets = publisher.collect_assets(self.directory, "0.3.0")

    def draft(self, body=publisher.MARKER):
        return {"id": 7, "tag_name": "v0.3.0", "draft": True, "body": body}

    def test_repository_selection_rejects_urls_options_and_source(self):
        for value in ("https://github.com/example/downloads", "--repo", "../source", "a/b.git", "a/b/c"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                publisher.validate_repository(value)
        with self.assertRaises(ValueError):
            publisher.validate_repository("Owner/Source", "owner/source")
        self.assertEqual(publisher.validate_repository(REPOSITORY), REPOSITORY)

    def test_allowlist_excludes_unrelated_assets(self):
        for name in ("source.zip", "secrets.txt", "debug.pdb", "Qt6Core.dll", "ida.exe"):
            (self.directory / name).write_bytes(b"must not publish")
        self.assertEqual(publisher.collect_assets(self.directory, "0.3.0"), self.assets)

    def test_missing_empty_and_changed_installer_are_rejected(self):
        self.zip.unlink()
        with self.assertRaises(ValueError):
            publisher.collect_assets(self.directory, "0.3.0")
        self.zip.write_bytes(b"")
        with self.assertRaises(ValueError):
            publisher.collect_assets(self.directory, "0.3.0")
        self.zip.write_bytes(b"zip")
        self.installer.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "checksum"):
            publisher.collect_assets(self.directory, "0.3.0")

    def test_invalid_version_is_rejected(self):
        for version in ("../0.3.0", "v0.3.0", "0.3.0\n", "0.3.0-preview"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                publisher.collect_assets(self.directory, version)

    def test_every_platform_is_required_before_publication(self):
        self.assertEqual(len(self.assets), 9)
        for package in self.assets:
            contents = package.read_bytes()
            package.unlink()
            with self.subTest(asset=package.name), self.assertRaises(ValueError):
                publisher.collect_assets(self.directory, "0.3.0")
            package.write_bytes(contents)

    def test_linux_and_macos_checksums_are_verified(self):
        for package in self.assets:
            if package.name.endswith((".tar.gz", "universal2.zip", ".dmg")):
                contents = package.read_bytes()
                package.write_bytes(b"changed")
                with self.subTest(asset=package.name), self.assertRaisesRegex(ValueError, "checksum"):
                    publisher.collect_assets(self.directory, "0.3.0")
                package.write_bytes(contents)

    def test_versioned_release_notes_keep_package_requirements(self):
        notes = publisher.release_notes("0.3.1")
        self.assertIn(publisher.MARKER, notes)
        self.assertIn("IDA Professional 9.4", notes)
        self.assertIn("## Changes", notes)
        self.assertIn("## 更新内容", notes)
        self.assertIn("IDA_AGENT_CODEX_PATH", notes)
        self.assertIn("ZCode", notes)
        self.assertNotIn("## Changes", publisher.release_notes("0.3.0"))
        current = publisher.release_notes("0.4.0")
        self.assertIn("ida-mcp", current)
        self.assertIn("fresh installation", current)
        self.assertIn("Pipe", current)
        current = publisher.release_notes("0.4.3")
        self.assertIn("linux-x64.tar.gz", current)
        self.assertIn("macos-universal2.dmg", current)
        self.assertIn("尚未经过全面测试", current)
        self.assertNotIn("Windows x64 only", current)

    def test_publication_uses_public_commit_and_only_packaged_assets(self):
        github = FakeGitHub(self.assets)
        with patch.dict(os.environ, {"GITHUB_SHA": "PRIVATE_SOURCE", "GITHUB_REPOSITORY": "example/private-source"}):
            url = publisher.publish(github, REPOSITORY, "0.3.0", self.assets)
        self.assertEqual(url, f"https://github.com/{REPOSITORY}/releases/tag/v0.3.0")
        self.assertEqual([call[1] for call in github.calls], ["create", "upload", "edit"])
        upload = github.calls[1]
        self.assertEqual(list(upload[3:3 + len(self.assets)]), [str(path) for path in self.assets])
        self.assertFalse(github.release["draft"])

    def test_creation_does_not_require_immediate_list_visibility(self):
        github = FakeGitHub(self.assets)
        github.hide_created_from_list = True
        publisher.publish(github, REPOSITORY, "0.3.0", self.assets)
        self.assertEqual(github.list_reads, 1)
        self.assertEqual([call[1] for call in github.calls], ["create", "upload", "edit"])
        self.assertFalse(github.release["draft"])

    def test_unconfirmed_creation_does_not_upload_or_publish(self):
        github = FakeGitHub(self.assets)
        github.invalid_created_draft = True
        with self.assertRaisesRegex(RuntimeError, "did not confirm"):
            publisher.publish(github, REPOSITORY, "0.3.0", self.assets)
        self.assertEqual([call[1] for call in github.calls], ["create"])

    def test_create_api_posts_json_payload_and_reads_response(self):
        payload = self.directory / "create.json"
        payload.write_text('{"draft": true}', encoding="utf-8")
        github = publisher.GitHub()
        with patch.object(github, "run", return_value='{"id": 7}') as run:
            self.assertEqual(github.api(f"repos/{REPOSITORY}/releases", payload=payload), {"id": 7})
        arguments = run.call_args.args
        self.assertEqual(arguments[arguments.index("--method") + 1], "POST")
        self.assertEqual(arguments[arguments.index("--input") + 1], str(payload))

    def test_private_archived_and_readonly_destinations_are_rejected_before_writes(self):
        for change in ({"private": True}, {"visibility": "internal"}, {"archived": True}, {"permissions": {"push": False}}):
            github = FakeGitHub(self.assets)
            github.metadata.update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                publisher.publish(github, REPOSITORY, "0.3.0", self.assets)
            self.assertEqual(github.calls, [])

    def test_empty_destination_is_rejected_before_writes(self):
        github = FakeGitHub(self.assets)
        github.empty_repository = True
        with self.assertRaises(RuntimeError):
            publisher.publish(github, REPOSITORY, "0.3.0", self.assets)
        self.assertEqual(github.calls, [])

    def test_corrupt_upload_remains_a_draft(self):
        github = FakeGitHub(self.assets)
        github.corrupt_upload = True
        with self.assertRaisesRegex(RuntimeError, "does not match"):
            publisher.publish(github, REPOSITORY, "0.3.0", self.assets)
        self.assertTrue(github.release["draft"])
        self.assertNotIn("edit", [call[1] for call in github.calls])

    def test_interrupted_upload_can_resume_its_managed_draft(self):
        github = FakeGitHub(self.assets)
        github.fail_upload = True
        with self.assertRaisesRegex(RuntimeError, "Interrupted"):
            publisher.publish(github, REPOSITORY, "0.3.0", self.assets)
        self.assertTrue(github.release["draft"])
        github.fail_upload = False
        publisher.publish(github, REPOSITORY, "0.3.0", self.assets)
        self.assertEqual([call[1] for call in github.calls].count("create"), 1)
        self.assertFalse(github.release["draft"])

    def test_unrelated_or_extra_asset_drafts_are_not_changed(self):
        for draft, extra in ((self.draft("User-created draft"), []), (self.draft(), [{"name": "source.zip"}])):
            github = FakeGitHub(self.assets, draft)
            github.remote = extra
            with self.assertRaises(RuntimeError):
                publisher.publish(github, REPOSITORY, "0.3.0", self.assets)
            self.assertEqual(github.calls, [])

    def test_same_published_assets_are_idempotent_and_never_overwritten(self):
        github = FakeGitHub(self.assets, {**self.draft(), "draft": False, "immutable": True})
        github.remote = github.uploaded_assets()
        publisher.publish(github, REPOSITORY, "0.3.0", self.assets)
        self.assertEqual(github.calls, [])
        github.remote[0]["digest"] = "sha256:" + "0" * 64
        with self.assertRaises(RuntimeError):
            publisher.publish(github, REPOSITORY, "0.3.0", self.assets)
        self.assertEqual(github.calls, [])

    def test_cli_errors_do_not_print_credentials(self):
        result = subprocess.CompletedProcess([], 1, "sensitive stdout", "token-secret")
        with patch.object(subprocess, "run", return_value=result), self.assertRaises(RuntimeError) as raised:
            publisher.GitHub().run("release", "upload", "v0.3.0")
        self.assertNotIn("token-secret", str(raised.exception))
        self.assertNotIn("sensitive", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
