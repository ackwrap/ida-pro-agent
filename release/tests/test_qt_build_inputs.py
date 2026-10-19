"""Integrity, cache and architecture checks for public Qt build inputs."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import build_qt
from qt_link_inputs import MANIFEST, SOURCE_NAME, VERSION, build_manifest, validate_prefix


class PublicQtInputsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def prefix(self, system="linux"):
        (self.root / MANIFEST).write_text(json.dumps(build_manifest(system)), encoding="utf-8")
        headers = self.root / "include/QtCore"
        headers.mkdir(parents=True)
        (headers / "qconfig.h").write_text('#define QT_VERSION_STR "6.8.2"\n', encoding="utf-8")
        exports = self.root / "lib/cmake/Qt6Core"
        exports.mkdir(parents=True)
        (exports / "Qt6CoreTargets.cmake").write_text("QT_NAMESPACE=QT", encoding="utf-8")
        spec = self.root / "mkspecs" / ("linux-g++" if system == "linux" else "macx-clang")
        spec.mkdir(parents=True)
        (spec / "qplatformdefs.h").touch()
        return self.root

    def test_cache_rejects_changed_source_namespace_version_and_recipe(self):
        prefix = self.prefix()
        original = build_manifest("linux")
        for field, value in (("namespace", ""), ("version", "6.8.3"),
                             ("source_sha256", "0" * 64), ("recipe", 0), ("system", "darwin")):
            with self.subTest(field=field):
                (prefix / MANIFEST).write_text(json.dumps(dict(original, **{field: value})), encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "metadata"):
                    validate_prefix(prefix, "linux")

    def test_cache_rejects_stock_qt_build_exports(self):
        prefix = self.prefix()
        (prefix / "lib/cmake/Qt6Core/Qt6CoreTargets.cmake").write_text("QT_CORE_LIB", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "namespace"):
            validate_prefix(prefix, "linux")

    def test_universal_cache_accepts_each_slice_and_rejects_unknown_architecture(self):
        prefix = self.prefix("darwin")
        for arches in (["x86_64"], ["arm64"], ["x86_64", "arm64"]):
            self.assertEqual(validate_prefix(prefix, "darwin", arches), prefix / "lib")
        with self.assertRaisesRegex(RuntimeError, "architecture"):
            validate_prefix(prefix, "darwin", ["i386"])

    def test_cached_source_is_verified_without_network_access(self):
        archive = self.root / SOURCE_NAME
        archive.write_bytes(b"verified source")
        with mock.patch.object(build_qt, "SOURCE_SHA256", hashlib.sha256(archive.read_bytes()).hexdigest()), \
                mock.patch.object(build_qt.urllib.request, "urlopen") as request:
            build_qt.download_source(archive)
            request.assert_not_called()
        archive.write_bytes(b"tampered")
        with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
            build_qt.download_source(archive)

    def test_failed_download_is_never_promoted_or_left_as_cache(self):
        archive = self.root / SOURCE_NAME
        response = io.BytesIO(b"corrupt download")
        response.url = "https://download.qt.io/source.tar.xz"
        with mock.patch.object(build_qt.urllib.request, "urlopen", return_value=response):
            with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
                build_qt.download_source(archive)
        self.assertFalse(archive.exists())
        self.assertFalse(archive.with_suffix(".xz.download").exists())

    def source_archive(self, name, link=False):
        archive = self.root / "source.tar.xz"
        with tarfile.open(archive, "w:xz") as target:
            entry = tarfile.TarInfo(name)
            if link:
                entry.type = tarfile.SYMTYPE
                entry.linkname = "../outside"
                target.addfile(entry)
            else:
                data = b"source"
                entry.size = len(data)
                target.addfile(entry, io.BytesIO(data))
        return archive

    def test_source_archive_rejects_traversal_absolute_paths_and_links(self):
        for name, link in (("../outside", False), ("/outside", False),
                           (f"qtbase-everywhere-src-{VERSION}/../outside", False),
                           (f"qtbase-everywhere-src-{VERSION}/link", True)):
            with self.subTest(name=name):
                with self.assertRaises(RuntimeError):
                    build_qt.extract_source(self.source_archive(name, link), self.root)
        self.assertFalse((self.root / "outside").exists())

    def test_framework_headers_are_available_to_existing_plugin_includes(self):
        for module in ("Core", "Gui", "Widgets"):
            headers = self.root / f"lib/Qt{module}.framework/Headers"
            headers.mkdir(parents=True)
            (headers / "header.h").write_text(module, encoding="utf-8")
        build_qt.install_framework_headers(self.root)
        for module in ("Core", "Gui", "Widgets"):
            self.assertEqual((self.root / f"include/Qt{module}/header.h").read_text(encoding="utf-8"), module)



if __name__ == "__main__":
    unittest.main()
