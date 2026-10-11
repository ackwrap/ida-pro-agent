"""Main-thread Markdown, copy, long-history and stream checks in real IDA."""
import json
import time
import traceback
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ida_auto
import ida_kernwin
import ida_loader
import ida_pro
from PySide6 import QtCore, QtGui, QtWidgets
import linux_panel_driver as base
from linux_chat_render_fixture import MARKDOWN, BURST

ROOT = base.ROOT
START = time.monotonic()
report = {"ok": False, "phase": "render", "qt": QtCore.qVersion()}
stage = 0
running = False
initial = None
selection_text = ""
anchor = ""
heartbeats = []
heartbeat_phases = {}
last_heartbeat = time.monotonic()


def heartbeat():
    global last_heartbeat
    now = time.monotonic()
    gap = (now - last_heartbeat) * 1000
    heartbeats.append(gap)
    heartbeat_phases.setdefault(str(stage), []).append(gap)
    last_heartbeat = now


heartbeat_timer = QtCore.QTimer()
heartbeat_timer.setInterval(10)
heartbeat_timer.timeout.connect(heartbeat)
heartbeat_timer.start()


def stats(output):
    value = output.property("idaAgentRenderStats")
    assert value is not None, "renderer diagnostics missing"
    assert value["messages"] <= 256 and value["bytes"] <= 512 * 1024, value
    assert value["maxStreamBatch"] <= 16 * 1024, value
    assert output.document().blockCount() < 2000, "pruning leaked document blocks"
    return dict(value)


def copy_action(output, cursor, name, expected):
    old_selection, old_scroll = output.textCursor(), output.verticalScrollBar().value()
    old_bottom = old_scroll >= output.verticalScrollBar().maximum()
    output.setTextCursor(cursor)
    output.ensureCursorVisible()
    error = []
    def select():
        menu = QtWidgets.QApplication.activePopupWidget()
        try:
            assert isinstance(menu, QtWidgets.QMenu), str(menu)
            action = next((a for a in menu.actions() if a.objectName() == name), None)
            assert action is not None, [a.text() for a in menu.actions()]
            action.trigger()
        except Exception:
            error.append(traceback.format_exc())
        finally:
            if menu:
                menu.close()
    QtCore.QTimer.singleShot(25, select)
    output.customContextMenuRequested.emit(output.cursorRect(cursor).center())
    output.setTextCursor(old_selection)
    output.verticalScrollBar().setValue(output.verticalScrollBar().maximum() if old_bottom else old_scroll)
    assert not error, error
    assert QtWidgets.QApplication.clipboard().text() == expected, name


def finish():
    heartbeat_timer.stop()
    report["heartbeatMs"] = {"samples": len(heartbeats), "max": max(heartbeats),
        "median": sorted(heartbeats)[len(heartbeats) // 2]}
    report["heartbeatByStageMs"] = {key: max(values) for key, values in heartbeat_phases.items()}
    assert max(heartbeats) < 1500, "GUI heartbeat stalled for more than 1.5 seconds"
    base.check_palette_layouts()
    report["layouts"] = base.report.get("layouts")
    _, output = base.panel()
    report["final"] = stats(output)
    base.panel()[0].parentWidget().grab().save(str(ROOT / "render-final.png"))
    report["elapsedSeconds"] = time.monotonic() - START
    report["ok"] = True
    (ROOT / "render.json").write_text(json.dumps(report, indent=2))
    ida_loader.save_database(str(ROOT / "sample.i64"), 0)
    QtCore.QTimer.singleShot(100, lambda: ida_kernwin.process_ui_action("QuitIDA"))
    return -1


def tick():
    global stage, initial, selection_text, anchor, running
    if running:
        return 40
    running = True
    try:
        assert time.monotonic() - START < 70, f"render stage {stage} timed out"
        if stage == 0:
            if not ida_auto.auto_is_ok():
                return 100
            base.action("ida-agent:ai:open")
            stage = 1
            return 250
        _, output = base.panel()
        text = output.toPlainText()
        (ROOT / "render-progress.json").write_text(json.dumps({"stage": stage, "stats": output.property("idaAgentRenderStats"), "textTail": text[-500:], "effortEnabled": base.effort_control().isEnabled(), "effortTooltip": base.effort_control().toolTip()}))
        value = stats(output)
        if stage == 1:
            assert "seed-0399" in text and "seed-0000" not in text, "long history tail was not clipped"
            assert value["messages"] == 256, value
            assert 1 <= value["resets"] <= 3, value
            report["initialScroll"] = [output.verticalScrollBar().value(), output.verticalScrollBar().maximum()]
            initial = value
            base.send("render-markdown")
            stage = 2
        elif stage == 2 and "render-markdown-complete" in text and base.effort_control().isEnabled():
            assert "thinking-check" in text, "thinking preview was lost"
            document = output.document()
            heading = document.find("Render check")
            report["codeBlockText"] = document.find("return 42;").block().text()
            report["headingProperties"] = {str(k): str(v) for k, v in heading.blockFormat().properties().items()}
            assert heading.blockFormat().headingLevel() == 2, "Markdown heading not rendered"
            bold = document.find("evidence", document.find("Render check"))
            assert bold.charFormat().fontWeight() >= QtGui.QFont.Bold, "Markdown bold not rendered"
            code = document.find("return 42;")
            assert code.charFormat().fontFixedPitch(), "code block does not use a fixed font"
            assert any(isinstance(f, QtGui.QTextTable) for m in document.rootFrame().childFrames()
                for f in m.childFrames()), "Markdown table missing"
            report["bottom"] = [output.verticalScrollBar().value(), output.verticalScrollBar().maximum()]
            assert output.verticalScrollBar().value() == output.verticalScrollBar().maximum(), "new replies did not follow bottom"
            copy_action(output, code, "idaAgentCopyCode", "int answer() {\n    return 42;\n}")
            copy_action(output, code, "idaAgentCopyMessage", MARKDOWN)
            thinking = document.find("thinking-check: comparing evidence")
            role = document.find("[Thinking]")
            assert not thinking.isNull() and role.block() == thinking.block(), "thinking label did not stay inline"
            assert role.charFormat().fontWeight() >= QtGui.QFont.DemiBold
            assert thinking.charFormat().fontWeight() == output.font().weight(), "role weight leaked into thinking body"
            copy_action(output, thinking, "idaAgentCopyMessage", "thinking-check: comparing evidence")
            assert value["resets"] == initial["resets"], "stream reset the whole document"
            assert value["markdownPasses"] == initial["markdownPasses"] + 2, "Markdown parsed during every delta"
            report["markdown"] = value
            # Expand only this disposable dock for readable visual QA.
            # Production preserves the user's persisted IDA dock geometry.
            output.parentWidget().setMinimumHeight(400)
            QtWidgets.QApplication.processEvents()
            report["readableCaptureMinHeight"] = 400
            base.check_palette_layouts()
            for label in ("native", "dark", "light"):
                (ROOT / ("markdown-" + label + ".png")).write_bytes(
                    (ROOT / ("render-" + label + ".png")).read_bytes())
            cursor = document.find("seed-0399")
            output.setTextCursor(cursor)
            selection_text = cursor.selectedText()
            output.verticalScrollBar().setValue(output.verticalScrollBar().maximum() // 3)
            anchor = output.cursorForPosition(QtCore.QPoint(10, 10)).block().text()
            base.send("render-burst")
            stage = 3
        elif stage == 3:
            assert output.textCursor().selectedText() == selection_text, "stream changed an older selection"
            report["viewport"] = {"expected": anchor[:90],
                "actual": output.cursorForPosition(QtCore.QPoint(10, 10)).block().text()[:90],
                "scroll": output.verticalScrollBar().value()}
            assert output.cursorForPosition(QtCore.QPoint(10, 10)).block().text() == anchor, "stream moved an older viewport"
            if "Display limit reached" in text and base.effort_control().isEnabled():
                assert value["resets"] == initial["resets"], "large stream reset the whole document"
                assert value["blockedResources"] > 0, "Markdown resource blocking was not exercised"
                assert "burst-complete" not in text, "large display was not bounded"
                clipped = output.document().find("Display limit reached")
                copy_action(output, clipped, "idaAgentCopyMessage", BURST)
                assert value["messages"] < 256, "byte-budget pruning was not exercised"
                report["burst"] = value
                return finish()
        return 40
    except Exception:
        report["error"] = traceback.format_exc()
        report["stage"] = stage
        try:
            report["outputTail"] = base.panel()[1].toPlainText()[-3000:]
            report["stats"] = stats(base.panel()[1])
            base.panel()[0].parentWidget().grab().save(str(ROOT / "render-failure.png"))
        except Exception:
            pass
        (ROOT / "render.json").write_text(json.dumps(report, indent=2))
        ida_pro.qexit(1)
        return -1
    finally:
        running = False


ida_kernwin.register_timer(100, tick)
