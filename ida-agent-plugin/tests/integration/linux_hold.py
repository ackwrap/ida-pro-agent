"""Keep a disposable IDA database serving main-thread RPCs for the Linux smoke test."""
import json
import os
import threading
import time
from pathlib import Path

import ida_auto
import ida_funcs
import ida_kernwin
import ida_loader
import ida_name
import ida_pro


def main():
    ida_auto.auto_wait()
    if not ida_loader.load_and_run_plugin("ida-agent-plugin", 0):
        raise RuntimeError("basic MCP plugin failed to start")
    address = ida_name.get_name_ea(0xffffffffffffffff, "main")
    if ida_funcs.get_func(address) is None:
        address = ida_name.get_name_ea(0xffffffffffffffff, "_main")
    if ida_funcs.get_func(address) is None:
        raise RuntimeError("sample main function was not found")
    ready = Path(os.environ["IDA_AGENT_TEST_READY_FILE"])
    release = Path(os.environ["IDA_AGENT_TEST_RELEASE_FILE"])
    timed_out = []

    def stop_when_released():
        deadline = time.monotonic() + 180
        while not release.exists():
            if time.monotonic() >= deadline:
                timed_out.append(True)
                break
            time.sleep(0.05)
        ida_kernwin.stop_serving()

    threading.Thread(target=stop_when_released, daemon=True).start()
    ready.write_text(json.dumps({"functionAddress": hex(address)}), encoding="utf-8")
    ida_kernwin.serve()
    ida_pro.qexit(1 if timed_out else 0)


try:
    main()
except Exception as error:
    ida_kernwin.msg("[ida-agent-test] %s\n" % error)
    ida_pro.qexit(1)
