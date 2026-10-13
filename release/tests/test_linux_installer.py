import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("ida_agent_installer", ROOT / "release/linux/ida_agent_installer.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


@unittest.skipUnless(sys.platform == "linux", "Linux user plugin links")
class LinuxInstallerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ida installer ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.payload = self.root / "system package"
        self.source = self.payload / "plugins/ida-agent-plugin.so"
        self.source.parent.mkdir(parents=True)
        self.source.write_bytes(b"version one")
        self.user = self.root / "user's IDA directory"
        self.target = installer.plugin_path(self.user)

    def test_install_upgrade_and_remove_preserve_user_data(self):
        self.user.mkdir()
        settings = self.user / "user.cfg"
        settings.write_bytes(b"keep settings")
        self.assertEqual(installer.plugin_status(self.payload, self.user), "missing")
        target, backup = installer.install_plugin(self.payload, self.user)
        self.assertEqual(target, self.target)
        self.assertIsNone(backup)
        self.assertTrue(target.is_symlink())
        self.assertEqual(installer.plugin_status(self.payload, self.user), "installed")
        self.source.write_bytes(b"version two")
        self.assertEqual(target.read_bytes(), b"version two")
        self.assertEqual(installer.install_plugin(self.payload, self.user), (target, None))
        installer.remove_plugin(self.payload, self.user)
        self.assertFalse(os.path.lexists(target))
        self.assertEqual(settings.read_bytes(), b"keep settings")

    def test_existing_manual_plugin_is_preserved_and_can_be_backed_up(self):
        self.target.parent.mkdir(parents=True)
        self.target.write_bytes(b"manual plugin")
        with self.assertRaises(FileExistsError):
            installer.install_plugin(self.payload, self.user)
        self.assertEqual(self.target.read_bytes(), b"manual plugin")
        target, backup = installer.install_plugin(self.payload, self.user, replace=True)
        self.assertEqual(backup.read_bytes(), b"manual plugin")
        self.assertEqual(target.read_bytes(), b"version one")
        installer.remove_plugin(self.payload, self.user)
        self.assertEqual(backup.read_bytes(), b"manual plugin")

    def test_foreign_and_dangling_links_are_not_removed(self):
        self.target.parent.mkdir(parents=True)
        foreign = self.root / "another plugin.so"
        self.target.symlink_to(foreign)
        self.assertEqual(installer.plugin_status(self.payload, self.user), "conflict")
        with self.assertRaises(RuntimeError):
            installer.remove_plugin(self.payload, self.user)
        self.assertEqual(os.readlink(self.target), str(foreign))
        _, backup = installer.install_plugin(self.payload, self.user, replace=True)
        self.assertEqual(os.readlink(backup), str(foreign))

    def test_our_dangling_link_can_be_removed_after_package_uninstall(self):
        installer.install_plugin(self.payload, self.user)
        self.source.unlink()
        installer.remove_plugin(self.payload, self.user)
        self.assertFalse(os.path.lexists(self.target))

    def test_failed_replacement_restores_previous_plugin(self):
        self.target.parent.mkdir(parents=True)
        self.target.write_bytes(b"manual plugin")
        actual_replace = os.replace
        def fail_install(source, target):
            if str(source).endswith(".tmp"):
                raise OSError("simulated installation failure")
            return actual_replace(source, target)
        with patch.object(installer.os, "replace", side_effect=fail_install), self.assertRaises(OSError):
            installer.install_plugin(self.payload, self.user, replace=True)
        self.assertEqual(self.target.read_bytes(), b"manual plugin")
        self.assertEqual(list(self.target.parent.iterdir()), [self.target])

    def test_directory_collision_and_missing_payload_fail_without_modification(self):
        self.target.mkdir(parents=True)
        with self.assertRaises(RuntimeError):
            installer.install_plugin(self.payload, self.user, replace=True)
        self.assertTrue(self.target.is_dir())
        self.source.unlink()
        with self.assertRaises(RuntimeError):
            installer.install_plugin(self.payload, self.user)
        self.assertTrue(self.target.is_dir())

    def test_idausr_selects_user_directory_and_root_is_rejected(self):
        with patch.dict(os.environ, {"IDAUSR": str(self.user)}):
            self.assertEqual(installer.default_user_directory(), self.user)
        with patch.object(installer.os, "geteuid", return_value=0), self.assertRaises(RuntimeError):
            installer.require_normal_user()

    def test_invalid_manager_cache_does_not_reuse_a_process(self):
        for value in ({}, [], None, {"pid": True}, {"pid": -1}, {"pid": "1"}):
            with self.subTest(value=value):
                self.assertFalse(installer._running_manager(value, self.payload / "ida-mcp"))


    def test_stop_manager_ignores_missing_state_and_preserves_foreign_process(self):
        state = self.root / "manager state"
        self.assertFalse(installer.stop_manager(self.payload, state_directory=state))
        self.assertFalse(state.exists())
        state.mkdir()
        (state / "manager.json").write_text(json.dumps({"pid": os.getpid(), "url": "http://127.0.0.1:12345"}))
        with patch("signal.pidfd_send_signal") as send_signal:
            self.assertFalse(installer.stop_manager(self.payload, state_directory=state))
            send_signal.assert_not_called()
        self.assertTrue((state / "manager.json").exists())

if __name__ == "__main__":
    unittest.main()
