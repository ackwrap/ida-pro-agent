"""Runs in a disposable real IDA GUI; all Qt operations stay on its main thread."""
import json
import os
from pathlib import Path
import time
import traceback

import ida_auto
import ida_kernwin
import ida_loader
import ida_pro
from PySide6 import QtCore, QtGui, QtWidgets

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
    output = container.findChild(QtWidgets.QTextEdit, "idaAgentChatOutput")
    assert output and output.isReadOnly()
    return entry, output


def effort_control():
    entry, _ = panel()
    combo = entry.parentWidget().findChild(QtWidgets.QComboBox, "idaAgentReasoningEffort")
    assert combo is not None, "reasoning effort selector missing"
    return combo


def select_effort(level):
    combo = effort_control()
    assert combo.isEnabled(), "effort selector stayed disabled after request completion"
    index = combo.findData(level)
    assert index >= 0, f"missing effort level: {level}"
    settings = ROOT / "config/ida-agent/ai/providers.json"
    before = settings.read_bytes()
    combo.setCurrentIndex(index)
    assert settings.read_bytes() == before, "programmatic selection wrote model settings"
    combo.activated.emit(index)
    assert combo.currentData() == level, "effort selection was not accepted"
    manager = json.loads(settings.read_text())
    profile = next(p for p in manager["profiles"] if p["id"] == manager["activeProfileId"])
    model = next(m for m in profile["models"] if m["id"] == profile["settings"]["model"])
    assert model["reasoningEffort"] == level, "effort selection was not persisted"


def measure_layout(label):
    entry, output = panel()
    twidget = ida_kernwin.find_widget(entry.parentWidget().windowTitle())
    container = ida_kernwin.PluginForm.TWidgetToPyQtWidget(twidget)
    assert container == entry.parentWidget(), "chat input parent changed"
    combo = effort_control()
    geometry = lambda w: [w.x(), w.y(), w.width(), w.height()]
    value = {"panel": geometry(container), "output": geometry(output), "input": geometry(entry),
        "effort": geometry(combo), "dpr": container.devicePixelRatioF(),
        "palette": combo.palette().color(QtGui.QPalette.Window).name()}
    assert output.y() == 0 and output.height() > 0, value
    assert entry.y() == combo.y() and entry.height() == combo.height() == entry.sizeHint().height(), value
    assert container.height() - entry.y() - entry.height() == 2, value
    assert entry.x() + entry.width() + 2 == combo.x(), value
    assert combo.x() + combo.width() == container.width(), value
    native = ida_kernwin.find_widget("Output window") or ida_kernwin.find_widget("Output")
    assert native is not None, "native Output widget missing"
    native_container = ida_kernwin.PluginForm.TWidgetToPyQtWidget(native)
    native_inputs = [w for w in native_container.findChildren(QtWidgets.QWidget)
                     if w.metaObject().className() == "CLILineEdit" and w.isVisible()]
    assert len(native_inputs) == 1, "native CLI input could not be measured"
    native_input = native_inputs[0]
    relative = native_input.mapTo(native_container, QtCore.QPoint(0, 0))
    value["nativeCli"] = {"panelHeight": native_container.height(), "x": relative.x(), "y": relative.y(),
        "width": native_input.width(), "height": native_input.height(), "hintHeight": native_input.sizeHint().height(),
        "bottomGap": native_container.height() - relative.y() - native_input.height()}
    report.setdefault("layouts", {})[label] = value
    # Compare the native CLI's bottom-relative top edge. Its own font/style
    # gives it a 23-pixel height and one-pixel bottom gap in the default Linux
    # style; ChatPanel retains its 22-pixel input and two-pixel bottom margin.
    if label == "native":
        assert container.height() - entry.y() == native_container.height() - relative.y(), value
    # The added selector must not increase the original input-row height.
    combo.hide()
    try:
        container.layout().activate()
        value["withoutEffort"] = {"inputY": entry.y(), "inputHeight": entry.height(), "outputHeight": output.height()}
        assert entry.y() == value["input"][1] and entry.height() == value["input"][3], value
        assert output.height() == value["output"][3], value
    finally:
        combo.show()
        container.layout().activate()
    container.grab().save(str(ROOT / (PHASE + "-" + label + ".png")))
    return value


def check_palette_layouts():
    application = QtWidgets.QApplication.instance()
    entry, output = panel()
    container = entry.parentWidget()
    combo = effort_control()
    original = container.styleSheet()
    report["geometry"] = measure_layout("native")
    try:
        for label, background, foreground in (("dark", "#252525", "#eeeeee"), ("light", "#eeeeee", "#202020")):
            # IDA styles override the application palette. Apply only colors
            # to this disposable panel, as a scoped Qt stylesheet would.
            container.setStyleSheet(original + "\nQLineEdit, QTextEdit, QComboBox { "
                + f"background-color: {background}; color: {foreground}; " + "}")
            application.processEvents()
            value = measure_layout(label)
            assert combo.palette().color(QtGui.QPalette.Base).name() == background, value
            assert combo.palette().color(QtGui.QPalette.Text).name() == foreground, value
            rendered = output.document().find("render-markdown-complete")
            if not rendered.isNull():
                assert rendered.charFormat().foreground().color().name() == foreground, "message body did not follow the palette"

    finally:
        container.setStyleSheet(original)
        application.processEvents()


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
    # Read the outer runner's snapshot: opening Python's SQLite in this process
    # would mix its VFS/lock bookkeeping with the plugin's private SQLite.
    snapshot = ROOT / "history-progress.json"
    if not snapshot.is_file():
        return False
    return json.loads(snapshot.read_text())["replies"] >= count


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
    assert effort_control().currentData() == "xhigh", "effort did not survive close/reopen or restart"
    check_palette_layouts()
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
        (ROOT / "progress.json").write_text(json.dumps({"stage": stage, "output": text, "status": status, "effortEnabled": effort_control().isEnabled(), "effort": effort_control().currentData(), "effortTooltip": effort_control().toolTip()}, ensure_ascii=False))
        if PHASE == "restore":
            if os.environ.get("IDA_AGENT_PANEL_TEST_RENDER_CHECK"):
                assert "render-markdown-complete" in text and "Display limit reached" in text, "bounded rich history was not restored"
            else:
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
            return 700
        elif stage == 3:
            select_effort("high")
            send("panel-check")
            stage = 4
        elif stage == 4 and "side effect(s) are prepared" in status:
            assert not effort_control().isEnabled(), "effort remained editable during a tool/approval round"
            assert not (ROOT / "panel-note.txt").exists(), "file changed before approval"
            send("/y")
            stage = 5
        elif stage == 5 and "streamed reply OK" in text and replies_saved(1):
            assert (ROOT / "panel-note.txt").read_text() == "Linux panel tool OK\n"
            if not effort_control().isEnabled():
                return 100
            select_effort("low")
            send("cancel-check")
            stage = 6
        elif stage == 6 and "Waiting for cancellation" in text:
            valid, state = ida_kernwin.get_action_state("ida-agent:ai:cancel")
            assert valid and state <= ida_kernwin.AST_ENABLE, f"cancel action disabled: {state}"
            action("ida-agent:ai:cancel")
            stage = 7
            return 700
        elif stage == 7 and "AI request was cancelled." in text:
            if not effort_control().isEnabled():
                return 100
            select_effort("default")
            send("after-cancel")
            stage = 8
        elif stage == 8 and text.count("streamed reply OK") >= 2 and replies_saved(2):
            if not effort_control().isEnabled():
                return 100
            select_effort("xhigh")
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


if __name__ == "__main__":
    ida_kernwin.register_timer(100, tick)
