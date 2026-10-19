"""Check macOS Qt link inputs without running any target architecture code."""
import argparse
import pathlib
import plistlib
import subprocess

from qt_link_inputs import validate_prefix


def validate(bundle: pathlib.Path, architectures: list[str], public=False) -> None:
    if not architectures or any(arch not in ("x86_64", "arm64") for arch in architectures):
        raise RuntimeError("Qt target architectures must be x86_64 and/or arm64")
    if public:
        frameworks = validate_prefix(bundle, "darwin", architectures)
    else:
        with (bundle / "Contents/Info.plist").open("rb") as source:
            version = plistlib.load(source).get("CFBundleShortVersionString", "")
        if not version.startswith("9.4.") and version != "9.4":
            raise RuntimeError("The application bundle must contain IDA 9.4")
        frameworks = bundle / "Contents/Frameworks"
    for module in ("Core", "Gui", "Widgets"):
        library = frameworks / f"Qt{module}.framework/Qt{module}"
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
    origin = "Public source-built" if public else "IDA macOS"
    print(f"Using {origin} Qt 6.8.2 (namespace QT, {', '.join(architectures)}): {bundle}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", action="store_true", help="Validate a public source-built Qt prefix")
    parser.add_argument("root", type=pathlib.Path)
    parser.add_argument("architectures", nargs="+")
    args = parser.parse_args()
    validate(args.root.resolve(), args.architectures, public=args.prefix)
