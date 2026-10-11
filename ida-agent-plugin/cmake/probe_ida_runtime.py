"""Read-only Windows IDA/Qt ABI preflight; it never loads or installs the plugin."""
import argparse
import hashlib
import json
import re
import shutil
import struct
import subprocess
from pathlib import Path

from generate_ida_qt_import_lib import EXPORT_PATTERN, file_version

QT_MODULES = ("Qt6Core.dll", "Qt6Gui.dll", "Qt6Widgets.dll")
HOST_LIBRARIES = {name.lower() for name in QT_MODULES} | {"ida.dll", "ida64.dll"}


def parse_exports(output: str) -> set[str]:
    result = set()
    for line in output.splitlines():
        match = EXPORT_PATTERN.match(line)
        if match and match.group(4) != "[NONAME]":
            result.add(match.group(4))
    return result


def parse_imports(output: str) -> dict[str, set[str]]:
    imports = {}
    current = None
    for line in output.splitlines():
        stripped = line.strip()
        if re.fullmatch(r"[A-Za-z0-9_.-]+\.dll", stripped, re.IGNORECASE):
            current = stripped.lower()
            imports.setdefault(current, set())
            continue
        if current is None:
            continue
        # dumpbin prints a hex hint followed by the decorated import name.
        match = re.fullmatch(r"[0-9A-Fa-f]+\s+(\S+)", stripped)
        if match:
            imports[current].add(match.group(1))
        elif re.search(r"Ordinal\s+\d+", stripped, re.IGNORECASE):
            imports[current].add("<ordinal-import>")
    return imports


def evaluate(host_version: str, qt_versions: dict[str, str],
             exports: dict[str, set[str]], imports: dict[str, set[str]] | None = None) -> dict:
    issues = []
    experimental = host_version.startswith("9.5.")
    if not (host_version.startswith("9.4.") or experimental):
        issues.append(f"Unsupported IDA host version: {host_version}")
    for module in QT_MODULES:
        key = module.lower()
        version = qt_versions.get(key, "")
        if version != "6.8.2" and not version.startswith("6.8.2."):
            issues.append(f"{module} requires Qt 6.8.2, found {version or 'missing'}")
        if not any("@QT@@" in symbol for symbol in exports.get(key, set())):
            issues.append(f"{module} does not expose the required QT namespace")
    checked = 0
    if imports is not None:
        host_imports = {name: symbols for name, symbols in imports.items() if name in HOST_LIBRARIES}
        if not host_imports:
            issues.append("Plugin imports did not contain any recognized IDA/Qt host libraries")
        for name, symbols in sorted(host_imports.items()):
            if not symbols:
                issues.append(f"No named imports could be checked for {name}")
            for symbol in sorted(symbols):
                checked += 1
                if symbol not in exports.get(name, set()):
                    issues.append(f"Missing plugin import in {name}: {symbol}")
    return {
        "schemaVersion": 1,
        "idaVersion": host_version,
        "experimentalHost": experimental,
        "qtVersions": qt_versions,
        "abiPreflightPassed": not issues,
        "pluginImportsChecked": imports is not None,
        "checkedImportCount": checked,
        "liveAcceptance": "pending",
        "issues": issues,
        "note": "ABI preflight does not certify plugin loading, Hex-Rays behavior, UI lifecycle or license compatibility.",
    }


def dump(dumpbin: Path, operation: str, binary: Path) -> str:
    return subprocess.run([str(dumpbin), "/nologo", operation, str(binary)],
                          check=True, capture_output=True, text=True, errors="strict", timeout=30).stdout


def pe_machine(path: Path) -> str:
    with path.open("rb") as stream:
        header = stream.read(64)
        if len(header) != 64 or header[:2] != b"MZ":
            raise RuntimeError(f"Invalid PE header: {path}")
        offset = struct.unpack_from("<I", header, 0x3C)[0]
        if offset < 64 or offset > 16 * 1024 * 1024:
            raise RuntimeError(f"Invalid PE header offset: {path}")
        stream.seek(offset)
        signature = stream.read(6)
        if len(signature) != 6 or signature[:4] != b"PE\0\0":
            raise RuntimeError(f"Invalid PE signature: {path}")
        machine = struct.unpack_from("<H", signature, 4)[0]
    return {0x8664: "x64", 0xAA64: "arm64", 0x14C: "x86"}.get(machine, f"unknown-0x{machine:04x}")


def probe(ida_dir: Path, dumpbin: Path, plugin: Path | None = None) -> dict:
    host = ida_dir / "ida.exe"
    if not host.is_file():
        raise RuntimeError(f"IDA executable is missing: {host}")
    exports = {}
    qt_versions = {}
    for module in QT_MODULES:
        dll = ida_dir / module
        if not dll.is_file():
            raise RuntimeError(f"IDA Qt runtime is missing: {dll}")
        qt_versions[module.lower()] = file_version(dll)
        exports[module.lower()] = parse_exports(dump(dumpbin, "/exports", dll))
    imports = None
    if plugin:
        if not plugin.is_file():
            raise RuntimeError(f"Plugin build artifact is missing: {plugin}")
        imports = parse_imports(dump(dumpbin, "/imports", plugin))
        for module in sorted(set(imports) & HOST_LIBRARIES - set(exports)):
            dll = ida_dir / module
            if dll.is_file():
                exports[module] = parse_exports(dump(dumpbin, "/exports", dll))
    report = evaluate(file_version(host), qt_versions, exports, imports)
    report["idaDirectory"] = str(ida_dir)
    binaries = [host] + [ida_dir / name for name in QT_MODULES]
    binaries += [ida_dir / name for name in (set(imports or {}) & HOST_LIBRARIES - set(qt_versions)) if (ida_dir / name).is_file()]
    if plugin:
        binaries.append(plugin)
    report["architectures"] = {binary.name: pe_machine(binary) for binary in binaries}
    for name, machine in report["architectures"].items():
        if machine != "x64":
            report["issues"].append(f"{name} requires Windows x64, found {machine}")
            report["abiPreflightPassed"] = False
    if plugin:
        report["pluginPath"] = str(plugin.resolve())
        report["pluginSha256"] = hashlib.sha256(plugin.read_bytes()).hexdigest()
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ida-dir", required=True, type=Path)
    parser.add_argument("--dumpbin", type=Path, default=shutil.which("dumpbin"))
    parser.add_argument("--plugin", type=Path, help="Check the exact built plugin's IDA/Qt imports")
    parser.add_argument("--expected-host-version", choices=("9.4", "9.5"), help="Require this exact IDA major/minor version")
    parser.add_argument("--output", type=Path, help="Write the JSON acceptance report")
    args = parser.parse_args()
    if not args.dumpbin:
        parser.error("pass --dumpbin or run in an MSVC developer environment")
    try:
        report = probe(args.ida_dir.resolve(), args.dumpbin, args.plugin)
        if args.expected_host_version and not report["idaVersion"].startswith(args.expected_host_version + "."):
            report["issues"].append("IDA host does not match expected version " + args.expected_host_version)
            report["abiPreflightPassed"] = False
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        report = {"schemaVersion": 1, "abiPreflightPassed": False,
                  "liveAcceptance": "pending", "issues": [str(error)]}
    encoded = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)
    return 0 if report["abiPreflightPassed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
