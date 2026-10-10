"""Runs in a disposable real IDA GUI; all Qt operations stay on its main thread."""
import json
import os
from pathlib import Path
import sqlite3
import time
import traceback

import ida_auto
import ida_kernwin
import ida_loader
import ida_pro
from PySide6 import QtCore, QtWidgets

ROOT = Path(os.environ["IDA_AGENT_PANEL_TEST_ROOT"])
PHASE = os.environ["IDA_AGENT_PANEL_TEST_PHASE"]
START = time.monotonic()
stage = 0
report = {"ok": False, "phase": PHASE, "qt": QtCore.qVersion(), "dialogs": []}
widget_refs = []


def panel():
    global widget_refs
    widget_refs = QtWidgets.QApplication.allWidgets()
    inputs = [w for w in widget_refs if isinstance(w, QtWidgets.QLineEdit)
              and w.placeholderText() == "Ask IDA Agent AI..." and w.isVisible()]
    assert len(inputs) == 1, f"expected one chat input, found {len(inputs)}"
    entry = inputs[0]
    container = entry.parentWidget()
    widget_refs.append(container)
    output = container.findChild(QtWidgets.QPlainTextEdit)
    assert output and output.isReadOnly()
    return entry, output


def send(text):
    entry, _ = panel()
    entry.setFocus()
    entry.setText(text)
    entry.returnPressed.emit()


def action(name):
    assert name in ida_kernwin.get_registered_actions(), f"missing action: {name}"
    # Our handlers return 0 even when the action successfully opens a panel.
    ida_kernwin.process_ui_action(name)


def replies_saved(count):
    # Visible streaming text can precede the terminal event. Wait for the
    # committed transcript before starting the next conversation turn.
    database = ROOT / "state/ida-agent/ai/chat.db"
    if not database.is_file():
        return False
    connection = sqlite3.connect(database)
    try:
        rows = connection.execute("SELECT history_json FROM chat_sessions").fetchall()
        return any(row[0].count("streamed reply OK") >= count for row in rows)
    finally:
        connection.close()


def save_dialog(title):
    def accept():
        try:
            dialog = QtWidgets.QApplication.activeModalWidget()
            assert isinstance(dialog, QtWidgets.QDialog) and dialog.windowTitle() == title, str(dialog)
            buttons = dialog.findChild(QtWidgets.QDialogButtonBox)
            assert buttons
            report["dialogs"].append(title)
            dialog.grab().save(str(ROOT / ("providers.png" if "Provider" in title else "settings.png")))
            buttons.button(QtWidgets.QDialogButtonBox.Ok).click()
        except Exception:
            fail()
    QtCore.QTimer.singleShot(250, accept)


def finish():
    entry, output = panel()
    container = entry.parentWidget()
    geometry = lambda w: [w.x(), w.y(), w.width(), w.height()]
    report["geometry"] = {"panel": geometry(container), "output": geometry(output), "input": geometry(entry),
        "dpr": container.devicePixelRatioF()}
    assert entry.width() > 0 and entry.height() > 0 and output.height() > 0
    assert output.y() + output.height() <= entry.y(), report["geometry"]
    report["nativeCli"] = [{"class": w.metaObject().className(), "geometry": geometry(w)}
        for w in QtWidgets.QApplication.allWidgets() if w.metaObject().className() == "CLILineEdit" and w.isVisible()]
    entry.window().grab().save(str(ROOT / (PHASE + ".png")))
    report["ok"] = True
    (ROOT / (PHASE + ".json")).write_text(json.dumps(report, indent=2))
    ida_loader.save_database(str(ROOT / "sample.i64"), 0)
    # Exercise the ordinary Qt application shutdown path and global action cleanup.
    QtCore.QTimer.singleShot(100, lambda: ida_kernwin.process_ui_action("QuitIDA"))
    return -1


def fail():
    report["error"] = traceback.format_exc()
    report["stage"] = stage
    try:
        report["output"] = panel()[1].toPlainText()
    except Exception:
        pass
    for widget in QtWidgets.QApplication.topLevelWidgets():
        if widget.isVisible() and isinstance(widget, QtWidgets.QMainWindow):
            widget.grab().save(str(ROOT / "failure.png"))
    (ROOT / (PHASE + ".json")).write_text(json.dumps(report, indent=2))
    ida_pro.qexit(1)


def tick():
    global stage
    try:
        assert time.monotonic() - START < 70, f"stage {stage} timed out"
        if stage == 0:
            if not ida_auto.auto_is_ok():
                return 100
            assert QtCore.qVersion() == "6.8.2"
            if "ida-agent:ai:open" not in ida_kernwin.get_registered_actions():
                return 100
            action("ida-agent:ai:open")
            stage = 1
            return 300
        if stage == 10:
            action("ida-agent:ai:open")
            stage = 11
            return 300
        entry, output = panel()
        text = output.toPlainText()
        status = "\n".join(w.text() for w in entry.parentWidget().findChildren(QtWidgets.QLabel))
        (ROOT / "progress.json").write_text(json.dumps({"stage": stage, "output": text, "status": status}, ensure_ascii=False))
        if PHASE == "restore":
            assert "streamed reply OK" in text, "chat history was not restored"
            return finish()
        if stage == 1:
            stage = 2
            save_dialog("IDA Agent AI Provider Manager")
            action("ida-agent:ai:providers")
        elif stage == 2:
            stage = 3
            save_dialog("IDA Agent Settings")
            action("ida-agent:settings")
        elif stage == 3:
            send("panel-check")
            stage = 4
        elif stage == 4 and "side effect(s) are prepared" in status:
            assert not (ROOT / "panel-note.txt").exists(), "file changed before approval"
            send("/y")
            stage = 5
        elif stage == 5 and "streamed reply OK" in text and replies_saved(1):
            assert (ROOT / "panel-note.txt").read_text() == "Linux panel tool OK\n"
            send("cancel-check")
            stage = 6
        elif stage == 6 and "Waiting for cancellation" in text:
            valid, state = ida_kernwin.get_action_state("ida-agent:ai:cancel")
            assert valid and state <= ida_kernwin.AST_ENABLE, f"cancel action disabled: {state}"
            action("ida-agent:ai:cancel")
            stage = 7
            return 700
        elif stage == 7 and "AI request was cancelled." in text:
            send("after-cancel")
            stage = 8
        elif stage == 8 and text.count("streamed reply OK") >= 2 and replies_saved(2):
            send("/history")
            stage = 9
            return 250
        elif stage == 9:
            # Close and reopen the dock without closing the database.
            widget = ida_kernwin.find_widget(entry.parentWidget().windowTitle())
            assert widget is not None, "chat dock identity missing"
            ida_kernwin.close_widget(widget, ida_kernwin.WCLS_DONT_SAVE_SIZE)
            stage = 10
            return 250
        elif stage == 11:
            assert "streamed reply OK" in text
            return finish()
        return 100
    except Exception:
        fail()
        return -1


ida_kernwin.register_timer(100, tick)
