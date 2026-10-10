import argparse
import ctypes
import re
import subprocess
from pathlib import Path


EXPORT_PATTERN = re.compile(r"^\s*(\d+)\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s+(\S+)")


class VsFixedFileInfo(ctypes.Structure):
    _fields_ = [
        ("signature", ctypes.c_uint32),
        ("struct_version", ctypes.c_uint32),
        ("file_version_ms", ctypes.c_uint32),
        ("file_version_ls", ctypes.c_uint32),
        ("product_version_ms", ctypes.c_uint32),
        ("product_version_ls", ctypes.c_uint32),
        ("file_flags_mask", ctypes.c_uint32),
        ("file_flags", ctypes.c_uint32),
        ("file_os", ctypes.c_uint32),
        ("file_type", ctypes.c_uint32),
        ("file_subtype", ctypes.c_uint32),
        ("file_date_ms", ctypes.c_uint32),
        ("file_date_ls", ctypes.c_uint32),
    ]


def file_version(path: Path) -> str:
    version = ctypes.windll.version
    size = version.GetFileVersionInfoSizeW(str(path), None)
    if size == 0:
        raise RuntimeError(f"version metadata is unavailable: {path}")
    buffer = ctypes.create_string_buffer(size)
    if not version.GetFileVersionInfoW(str(path), 0, size, buffer):
        raise RuntimeError(f"version metadata could not be read: {path}")
    pointer = ctypes.c_void_p()
    length = ctypes.c_uint()
    if not version.VerQueryValueW(buffer, "\\", ctypes.byref(pointer), ctypes.byref(length)):
        raise RuntimeError(f"fixed version metadata is unavailable: {path}")
    info = ctypes.cast(pointer, ctypes.POINTER(VsFixedFileInfo)).contents
    parts = (
        info.file_version_ms >> 16,
        info.file_version_ms & 0xFFFF,
        info.file_version_ls >> 16,
        info.file_version_ls & 0xFFFF,
    )
    return ".".join(str(part) for part in parts)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dumpbin", required=True, type=Path)
    parser.add_argument("--lib", required=True, type=Path)
    parser.add_argument("--dll", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-namespace", required=True)
    parser.add_argument("--host-executable", required=True, type=Path)
    parser.add_argument("--expected-host-version", required=True)
    args = parser.parse_args()

    actual_host_version = file_version(args.host_executable)
    if not actual_host_version.startswith(args.expected_host_version + "."):
        raise RuntimeError(
            f"IDA host version mismatch: expected {args.expected_host_version}, "
            f"got {actual_host_version} from {args.host_executable}"
        )
    actual_version = file_version(args.dll)
    expected_prefix = args.expected_version + "."
    if actual_version != args.expected_version and not actual_version.startswith(expected_prefix):
        raise RuntimeError(
            f"{args.dll.name} version mismatch: expected {args.expected_version}, got {actual_version}"
        )

    result = subprocess.run(
        [str(args.dumpbin), "/nologo", "/exports", str(args.dll)],
        check=True,
        capture_output=True,
        text=True,
        errors="strict",
    )
    exports = []
    for line in result.stdout.splitlines():
        match = EXPORT_PATTERN.match(line)
        if match is None:
            continue
        name = match.group(4)
        if name != "[NONAME]":
            exports.append(name)
    if not exports:
        raise RuntimeError(f"no named exports found in {args.dll}")
    namespace_marker = f"@{args.expected_namespace}@@"
    if not any(namespace_marker in name for name in exports):
        raise RuntimeError(
            f"{args.dll.name} does not export the expected {args.expected_namespace} namespace"
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    definition = args.output.with_suffix(".def")
    definition.write_text(
        f'LIBRARY "{args.dll.name}"\nEXPORTS\n'
        + "".join(f"  {name}\n" for name in exports),
        encoding="ascii",
        newline="\n",
    )
    subprocess.run(
        [
            str(args.lib),
            "/nologo",
            "/machine:x64",
            f"/def:{definition}",
            f"/out:{args.output}",
        ],
        check=True,
    )


if __name__ == "__main__":
    main()
