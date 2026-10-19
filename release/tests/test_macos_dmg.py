"""Disk-image transient errors must be retried without hiding permanent failures."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import build_macos_dmg as builder


class DiskImageRetryTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.image = self.root / "release.dmg"

    def test_busy_retry_removes_only_partial_owned_image_then_succeeds(self):
        other = self.root / "published.dmg"
        other.write_bytes(b"preserve")
        def create(*args, **kwargs):
            if self.image.exists():
                return subprocess.CompletedProcess(args[0], 0, "created\n", "")
            self.image.write_bytes(b"partial")
            return subprocess.CompletedProcess(args[0], 1, "", "hdiutil: create failed - Resource busy\n")
        with mock.patch.object(builder.subprocess, "run", side_effect=create) as command, \
                mock.patch.object(builder.time, "sleep") as sleep:
            def wait_for_retry(_):
                self.assertFalse(self.image.exists(), "partial image was not removed before retry")
                self.image.write_bytes(b"complete")
            sleep.side_effect = wait_for_retry
            builder.create_image(self.root, self.image, "0.5.3")
        self.assertEqual(command.call_count, 2)
        self.assertEqual(sleep.call_args.args, (2,))
        self.assertEqual(self.image.read_bytes(), b"complete")
        self.assertEqual(other.read_bytes(), b"preserve")

    def test_permanent_error_stops_without_retry(self):
        failure = subprocess.CompletedProcess([], 1, "", "hdiutil: invalid argument\n")
        with mock.patch.object(builder.subprocess, "run", return_value=failure) as command, \
                mock.patch.object(builder.time, "sleep") as sleep:
            with self.assertRaises(subprocess.CalledProcessError):
                builder.create_image(self.root, self.image, "0.5.3")
        command.assert_called_once()
        sleep.assert_not_called()

    def test_busy_retries_are_bounded_and_exhaustion_fails(self):
        failure = subprocess.CompletedProcess([], 1, "", "Resource busy\n")
        with mock.patch.object(builder.subprocess, "run", return_value=failure) as command, \
                mock.patch.object(builder.time, "sleep") as sleep:
            with self.assertRaises(subprocess.CalledProcessError):
                builder.create_image(self.root, self.image, "0.5.3")
        self.assertEqual(command.call_count, 4)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [2, 4, 8])


if __name__ == "__main__":
    unittest.main()
