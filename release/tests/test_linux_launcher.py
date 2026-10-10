import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

LAUNCHER = Path(__file__).resolve().parents[1] / "linux/idat-with-agent"


@unittest.skipUnless(sys.platform == "linux", "Linux launcher")
class LinuxLauncherTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ida launcher ")
        self.addCleanup(self.temporary.cleanup)
        self.runtime = Path(self.temporary.name) / "IDA's installation"
        self.runtime.mkdir()
        self.idat = self.runtime / "idat"
        self.idat.write_text(
            "#!/usr/bin/env python3\nimport json, os, sys\n"
            "print(json.dumps({'args': sys.argv[1:], 'libraries': os.environ['LD_LIBRARY_PATH']}))\n",
            encoding="utf-8")
        self.idat.chmod(0o700)
        for module in ("Core", "Gui", "Widgets"):
            (self.runtime / f"libQt6{module}.so.6").write_bytes(b"test fixture")

    def test_forwards_arguments_and_selects_matching_libraries(self):
        arguments = ["-A", "-Sscript with spaces.py", "user's sample.i64"]
        result = subprocess.run(["sh", str(LAUNCHER), str(self.idat), *arguments],
                                env=dict(os.environ, LD_LIBRARY_PATH="/existing/libs"),
                                capture_output=True, text=True, check=True)
        report = json.loads(result.stdout)
        self.assertEqual(report["args"], arguments)
        self.assertEqual(report["libraries"], f"{self.runtime}:/existing/libs")

    def test_missing_qt_fails_before_starting_idat(self):
        (self.runtime / "libQt6Widgets.so.6").unlink()
        result = subprocess.run(["sh", str(LAUNCHER), str(self.idat)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("Missing IDA Qt library", result.stderr)

    def test_help_does_not_require_ida(self):
        result = subprocess.run(["sh", str(LAUNCHER), "--help"], capture_output=True, text=True, check=True)
        self.assertIn("Usage:", result.stdout)


if __name__ == "__main__":
    unittest.main()
