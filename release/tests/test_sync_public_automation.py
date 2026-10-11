import io
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import sync_public_automation as automation

SOURCE = "a" * 40
PUBLIC = "b" * 40
TAG_OBJECT = "c" * 40


class FakeGitHub:
    def __init__(self, source=False):
        self.source = source
        self.ref = {"object": {"type": "commit", "sha": SOURCE}} if source else None
        self.release = None
        self.runs = {}
        self.writes = []
        self.fail_dispatch = False

    def api(self, path, *, payload=None, missing=False):
        if payload is not None:
            if self.fail_dispatch and path.endswith("/dispatches"):
                raise RuntimeError("temporary dispatch failure")
            self.writes.append((path, payload))
            if path.endswith("/git/refs"):
                self.ref = {"object": {"type": "commit", "sha": payload["sha"]}}
            return None
        if "/git/ref/tags/" in path:
            return self.ref
        if "/git/tags/" in path:
            return {"object": {"type": "commit", "sha": SOURCE}}
        if "/releases/tags/" in path:
            return self.release
        for name in (*automation.CHECK_WORKFLOWS, automation.RELEASE_WORKFLOW):
            if f"/{name}/runs?" in path:
                return {"workflow_runs": self.runs.get(name, [])}
        raise AssertionError(path)


class PublicAutomationTests(unittest.TestCase):
    def test_bot_push_explicitly_dispatches_missing_checks(self):
        public = FakeGitHub()
        public.runs[automation.CHECK_WORKFLOWS[0]] = [{"id": 1}]
        names = automation.dispatch_checks(public, PUBLIC)
        self.assertEqual(names, list(automation.CHECK_WORKFLOWS[1:]))
        self.assertTrue(all(payload == {"ref": "main"} for _, payload in public.writes))

    def test_existing_checks_are_not_duplicated(self):
        public = FakeGitHub()
        public.runs = {name: [{"id": 1}] for name in automation.CHECK_WORKFLOWS}
        self.assertEqual(automation.dispatch_checks(public, PUBLIC), [])
        self.assertEqual(public.writes, [])

    def test_untagged_or_new_development_commit_never_releases(self):
        for ref in (None, {"object": {"type": "commit", "sha": "d" * 40}}):
            with self.subTest(ref=ref):
                public, source = FakeGitHub(), FakeGitHub(source=True)
                source.ref = ref
                self.assertFalse(automation.dispatch_release(public, source, SOURCE, PUBLIC, "0.4.9"))
                self.assertEqual(public.writes, [])

    def test_annotated_source_tag_creates_public_tag_and_dispatches_release(self):
        public, source = FakeGitHub(), FakeGitHub(source=True)
        source.ref = {"object": {"type": "tag", "sha": TAG_OBJECT}}
        self.assertTrue(automation.dispatch_release(public, source, SOURCE, PUBLIC, "0.4.9"))
        self.assertEqual(public.writes[0][1], {"ref": "refs/tags/v0.4.9", "sha": PUBLIC})
        self.assertEqual(public.writes[1][1], {"ref": "v0.4.9", "inputs": {"publish": "true"}})

    def test_dispatch_failure_retries_without_rewriting_existing_tag(self):
        public, source = FakeGitHub(), FakeGitHub(source=True)
        public.fail_dispatch = True
        with self.assertRaises(RuntimeError):
            automation.dispatch_release(public, source, SOURCE, PUBLIC, "0.4.9")
        public.fail_dispatch = False
        self.assertTrue(automation.dispatch_release(public, source, SOURCE, PUBLIC, "0.4.9"))
        self.assertEqual(sum(path.endswith("/git/refs") for path, _ in public.writes), 1)

    def test_existing_published_release_keeps_its_tag_and_assets(self):
        public, source = FakeGitHub(), FakeGitHub(source=True)
        public.ref = {"object": {"type": "commit", "sha": "e" * 40}}
        public.release = {"draft": False}
        self.assertFalse(automation.dispatch_release(public, source, SOURCE, PUBLIC, "0.4.9"))
        self.assertEqual(public.writes, [])

    def test_existing_running_or_failed_release_is_not_automatically_rebuilt(self):
        for status in ("in_progress", "completed"):
            with self.subTest(status=status):
                public, source = FakeGitHub(), FakeGitHub(source=True)
                public.ref = {"object": {"type": "commit", "sha": PUBLIC}}
                public.runs[automation.RELEASE_WORKFLOW] = [{"status": status}]
                self.assertFalse(automation.dispatch_release(public, source, SOURCE, PUBLIC, "0.4.9"))
                self.assertEqual(public.writes, [])

    def test_invalid_version_and_tag_object_are_rejected_before_writes(self):
        public, source = FakeGitHub(), FakeGitHub(source=True)
        with self.assertRaises(ValueError):
            automation.dispatch_release(public, source, SOURCE, PUBLIC, "../bad")
        source.ref = {"object": {"type": "commit", "sha": "invalid"}}
        with self.assertRaises(ValueError):
            automation.dispatch_release(public, source, SOURCE, PUBLIC, "0.4.9")
        self.assertEqual(public.writes, [])

    def test_http_error_never_prints_authentication_or_response_body(self):
        error = urllib.error.HTTPError("https://api.github.com/private", 403, "FORBIDDEN", {},
                                       io.BytesIO(b"SENSITIVE_RESPONSE"))
        with patch.object(automation.urllib.request, "urlopen", side_effect=error):
            with self.assertRaises(RuntimeError) as context:
                automation.GitHub("SENSITIVE_TOKEN").api("repos/example/private")
        self.assertNotIn("SENSITIVE", str(context.exception))
        self.assertIn("403", str(context.exception))


if __name__ == "__main__":
    unittest.main()
