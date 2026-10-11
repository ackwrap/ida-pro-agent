import struct
import tempfile
import sys
import unittest
from pathlib import Path

CMAKE = Path(__file__).resolve().parents[3] / "cmake"
sys.path.insert(0, str(CMAKE))
import probe_ida_runtime as probe


class RuntimeProbeTests(unittest.TestCase):
    def fixture(self):
        versions = {name.lower(): "6.8.2.0" for name in probe.QT_MODULES}
        exports = {name.lower(): {"?test@QT@@", "?other@QT@@"} for name in probe.QT_MODULES}
        return versions, exports

    def test_pe_architecture_is_read_without_loading_binary(self):
        with tempfile.TemporaryDirectory(prefix="ida-runtime-probe-") as directory:
            binary = Path(directory) / "fixture.dll"
            for machine, expected in ((0x8664, "x64"), (0xAA64, "arm64"), (0x14C, "x86")):
                data = bytearray(128)
                data[:2] = b"MZ"
                struct.pack_into("<I", data, 0x3C, 64)
                data[64:68] = b"PE\0\0"
                struct.pack_into("<H", data, 68, machine)
                binary.write_bytes(data)
                self.assertEqual(probe.pe_machine(binary), expected)
            binary.write_bytes(b"not-a-PE")
            with self.assertRaises(RuntimeError):
                probe.pe_machine(binary)

    def test_stable_preflight_does_not_claim_live_acceptance(self):
        versions, exports = self.fixture()
        result = probe.evaluate("9.4.0.250918", versions, exports)
        self.assertTrue(result["abiPreflightPassed"])
        self.assertFalse(result["experimentalHost"])
        self.assertEqual(result["liveAcceptance"], "pending")
        self.assertFalse(result["pluginImportsChecked"])

    def test_beta_same_qt_requires_unchanged_imports(self):
        versions, exports = self.fixture()
        exports["ida.dll"] = {"getinf"}
        imports = {"qt6core.dll": {"?test@QT@@"}, "ida.dll": {"getinf"}}
        result = probe.evaluate("9.5.0.261001", versions, exports, imports)
        self.assertTrue(result["abiPreflightPassed"])
        self.assertTrue(result["experimentalHost"])
        self.assertEqual(result["checkedImportCount"], 2)
        imports["ida.dll"].add("removed_symbol")
        self.assertFalse(probe.evaluate("9.5.0.261001", versions, exports, imports)["abiPreflightPassed"])

    def test_wrong_qt_namespace_host_and_unknown_imports_fail(self):
        versions, exports = self.fixture()
        versions["qt6core.dll"] = "6.9.1.0"
        exports["qt6widgets.dll"] = {"?stockQtSymbol@@"}
        result = probe.evaluate("9.6.0.0", versions, exports, {})
        self.assertFalse(result["abiPreflightPassed"])
        self.assertGreaterEqual(len(result["issues"]), 4)

    def test_dumpbin_parsers_preserve_decorated_symbols(self):
        exports = "  1 0 00001000 ?foo@QT@@QEAAHXZ\n  2 1 00002000 [NONAME]\n"
        self.assertEqual(probe.parse_exports(exports), {"?foo@QT@@QEAAHXZ"})
        imports = "    Qt6Core.dll\n  000123 Import Address Table\n  8AA ?foo@QT@@QEAAHXZ\n  007 ?bar@QT@@\n    KERNEL32.dll\n  100 Sleep\n"
        self.assertEqual(probe.parse_imports(imports)["qt6core.dll"], {"?foo@QT@@QEAAHXZ", "?bar@QT@@"})
        self.assertEqual(probe.parse_imports(imports)["kernel32.dll"], {"Sleep"})

    def test_ordinal_and_unreadable_plugin_imports_fail_closed(self):
        versions, exports = self.fixture()
        ordinal = probe.parse_imports("    ida.dll\n  Ordinal 125\n")
        self.assertFalse(probe.evaluate("9.5.0.0", versions, exports, ordinal)["abiPreflightPassed"])
        self.assertFalse(probe.evaluate("9.5.0.0", versions, exports, {"ida.dll": set()})["abiPreflightPassed"])


if __name__ == "__main__":
    unittest.main()
