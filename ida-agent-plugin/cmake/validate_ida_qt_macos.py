"""Check IDA's macOS Qt ABI without running any target architecture code."""
import pathlib
import plistlib
import subprocess
import sys


def validate(bundle: pathlib.Path, architectures: list[str]) -> None:
    with (bundle / "Contents/Info.plist").open("rb") as source:
        version = plistlib.load(source).get("CFBundleShortVersionString", "")
    if not version.startswith("9.4.") and version != "9.4":
        raise RuntimeError("The application bundle must contain IDA 9.4")
    if not architectures or any(arch not in ("x86_64", "arm64") for arch in architectures):
        raise RuntimeError("Qt target architectures must be x86_64 and/or arm64")
    for module in ("Core", "Gui", "Widgets"):
        library = bundle / f"Contents/Frameworks/Qt{module}.framework/Qt{module}"
        subprocess.run(["lipo", str(library), "-verify_arch", *architectures], check=True)
        for arch in architectures:
            dependencies = subprocess.check_output(
                ["otool", "-arch", arch, "-L", str(library)], text=True
            )
            identity = next((line for line in dependencies.splitlines()
                             if f"@rpath/Qt{module}.framework/" in line), "")
            if "current version 6.8.2)" not in identity:
                raise RuntimeError(f"Qt{module} ({arch}) must be Qt 6.8.2")
            symbols = subprocess.check_output(
                ["nm", "-arch", arch, "-gU", str(library)], text=True
            )
            if "__ZN2QT" not in symbols:
                raise RuntimeError(f"Qt{module} ({arch}) does not use IDA's QT namespace")
    print(f"Using IDA macOS Qt 6.8.2 (namespace QT, {', '.join(architectures)}): {bundle}")


if __name__ == "__main__":
    validate(pathlib.Path(sys.argv[1]).resolve(), sys.argv[2:])
