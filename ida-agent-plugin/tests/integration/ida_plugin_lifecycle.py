import ida_auto
import ida_kernwin
import ida_loader
import ida_pro


def main():
    ida_auto.auto_wait()
    if not ida_loader.load_and_run_plugin("ida-agent-plugin", 0):
        ida_kernwin.msg("[ida-agent-test] load_and_run_plugin failed\n")
        ida_pro.qexit(1)
        return

    ida_kernwin.msg("[ida-agent-test] lifecycle passed\n")
    ida_pro.qexit(0)


main()
