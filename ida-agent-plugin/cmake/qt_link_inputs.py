"""Pinned public Qt link inputs shared by the builder and CMake preflight."""
import json
from pathlib import Path
import re

VERSION = "6.8.2"
SOURCE_NAME = f"qtbase-everywhere-src-{VERSION}.tar.xz"
SOURCE_URL = f"https://download.qt.io/archive/qt/6.8/{VERSION}/submodules/{SOURCE_NAME}"
SOURCE_SHA256 = "012043ce6d411e6e8a91fdc4e05e6bedcfa10fcb1347d3c33908f7fdd10dfe05"
RECIPE = 1
MANIFEST = "ida-agent-qt-build.json"


def build_manifest(system):
    if system not in ("linux", "darwin"):
        raise ValueError("Public Qt link inputs support Linux and macOS only")
    return {"recipe": RECIPE, "version": VERSION, "namespace": "QT", "system": system,
            "architectures": ["x86_64"] if system == "linux" else ["x86_64", "arm64"],
            "source_url": SOURCE_URL, "source_sha256": SOURCE_SHA256}


def validate_prefix(prefix: Path, system: str, architectures=None) -> Path:
    """Reject incomplete, stale or differently configured cached build inputs."""
    manifest = json.loads((prefix / MANIFEST).read_text(encoding="utf-8"))
    if manifest != build_manifest(system):
        raise RuntimeError("Public Qt input metadata differs from the pinned build recipe; use a fresh prefix")
    if architectures and not set(architectures).issubset(manifest["architectures"]):
        raise RuntimeError("Public Qt inputs are missing a requested architecture")
    config = (prefix / "include/QtCore/qconfig.h").read_text(encoding="utf-8")
    if not re.search(r'^#define QT_VERSION_STR "6\.8\.2"$', config, re.MULTILINE):
        raise RuntimeError("Public Qt headers must be exactly 6.8.2")
    exports = (prefix / "lib/cmake/Qt6Core/Qt6CoreTargets.cmake").read_text(encoding="utf-8")
    if "QT_NAMESPACE=QT" not in exports:
        raise RuntimeError("Public Qt build exports must use namespace QT")
    spec = "linux-g++" if system == "linux" else "macx-clang"
    if not (prefix / f"mkspecs/{spec}/qplatformdefs.h").is_file():
        raise RuntimeError("Public Qt platform headers are missing")
    return prefix / "lib"
