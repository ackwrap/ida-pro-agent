import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("build_deb", ROOT / "release/build_deb.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class DebValidationTests(unittest.TestCase):
    def test_version_rejects_paths_and_control_field_injection(self):
        for version in ("../1.0.0", "v1.0.0", "1.0.0\nDepends: anything", "1.0.0\n", "1.0"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                builder.validate_version(version)
        builder.validate_version("0.4.11")

    def test_abi_rejects_newer_glibc_and_cpp_requirements(self):
        for value in ("Name: GLIBC_2.39", "Name: GLIBCXX_3.4.31"):
            with patch.object(builder.subprocess, "check_output", return_value=value), self.assertRaises(RuntimeError):
                builder.validate_abi(Path("plugin.so"))
        with patch.object(builder.subprocess, "check_output", return_value="GLIBC_2.38 GLIBCXX_3.4.30 Qt_6 OPENSSL_3.0.0"):
            builder.validate_abi(Path("plugin.so"))


@unittest.skipUnless(sys.platform == "linux" and all(shutil.which(tool) for tool in (
    "rsvg-convert", "desktop-file-validate", "dpkg-deb", "appstreamcli")), "Linux Debian packaging tools")
class DebPackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ida deb test ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.package = self.root / "portable"
        for relative in ("ida-mcp", "plugins/ida-agent-plugin.so", "idat-with-agent",
                         "licenses/curl-COPYING.txt", "skills/ida-reverse-analysis/SKILL.md"):
            path = self.package / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"package test fixture")
        (self.package / "private-qt-input.so").write_bytes(b"must not ship")
        self.stage = self.root / "stage"
        self.stage.mkdir()

    def test_real_deb_metadata_icons_ownership_and_allowlist(self):
        payload = builder.assemble_tree(self.package, "0.4.11", self.stage)
        self.assertEqual((payload / "VERSION").read_text().strip(), "0.4.11")
        self.assertEqual((self.stage / "usr/bin/ida-mcp").readlink(), Path("../lib/ida-agent/ida-mcp"))
        self.assertTrue((payload / "skills/ida-reverse-analysis/SKILL.md").is_file())
        self.assertFalse((payload / "private-qt-input.so").exists())
        self.assertFalse((self.stage / "DEBIAN/postinst").exists())
        self.assertFalse((self.stage / "DEBIAN/postrm").exists())
        deb = self.root / "test.deb"
        builder.run("dpkg-deb", "--root-owner-group", "-Zxz", "--build", self.stage, deb)
        self.assertEqual(subprocess.check_output(["dpkg-deb", "--field", str(deb), "Architecture"], text=True).strip(), "amd64")
        dependencies = subprocess.check_output(["dpkg-deb", "--field", str(deb), "Depends"], text=True)
        self.assertIn("libc6 (>= 2.38)", dependencies)
        self.assertIn("libssl3t64 | libssl3", dependencies)
        self.assertIn("python3-tk", dependencies)
        data = subprocess.Popen(["dpkg-deb", "--fsys-tarfile", str(deb)], stdout=subprocess.PIPE)
        with tarfile.open(fileobj=data.stdout, mode="r|") as archive:
            members = list(archive)
        data.stdout.close()
        self.assertEqual(data.wait(), 0)
        self.assertTrue(all(item.uid == 0 and item.gid == 0 for item in members))
        for size in builder.ICONS:
            self.assertTrue((self.stage / f"usr/share/icons/hicolor/{size}x{size}/apps/ida-agent.png").is_file())

    def test_symlinked_input_is_rejected_before_packaging(self):
        gateway = self.package / "ida-mcp"
        gateway.unlink()
        gateway.symlink_to(self.package / "private-qt-input.so")
        with self.assertRaises(ValueError):
            builder.assemble_tree(self.package, "0.4.11", self.stage)


if __name__ == "__main__":
    unittest.main()
