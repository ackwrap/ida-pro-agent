"""Reject stock Qt and mismatched headers/runtime before linking the IDA panel."""
import ctypes
from pathlib import Path
import sys


def main():
    root = Path(sys.argv[1]).resolve(strict=True)
    manifest = root / "ida-version.txt"
    if manifest.is_file():
        if manifest.read_text(encoding="ascii").strip() != "9.4":
            raise RuntimeError("The Qt link bundle must come from IDA 9.4")
    elif not (root / "ida").is_file():
        raise RuntimeError("Expected Linux IDA 9.4 or its versioned Qt link bundle")
    core = ctypes.CDLL(str(root / "libQt6Core.so.6"), mode=ctypes.RTLD_GLOBAL)
    version = getattr(core, "_ZN2QT8qVersionEv")
    version.restype = ctypes.c_char_p
    if version() != b"6.8.2":
        raise RuntimeError(f"Expected Qt 6.8.2 in namespace QT, got {version()!r}")
    for module, symbol in (("Gui", "_ZN2QT5QFont16staticMetaObjectE"),
                           ("Widgets", "_ZN2QT7QWidget16staticMetaObjectE")):
        library = ctypes.CDLL(str(root / f"libQt6{module}.so.6"), mode=ctypes.RTLD_GLOBAL)
        getattr(library, symbol)
    print(f"Using IDA Linux Qt 6.8.2 (namespace QT): {root}")


if __name__ == "__main__":
    main()
