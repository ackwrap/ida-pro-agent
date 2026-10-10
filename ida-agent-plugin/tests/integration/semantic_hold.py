"""Create fixed semantic fixtures only in the isolated integration-test IDB."""
import json
import os
import threading
import time
from pathlib import Path

import ida_auto
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_loader
import ida_pro
import idautils
import idc


def main():
    ida_auto.auto_wait()
    if not ida_loader.load_and_run_plugin('ida-agent-plugin', 0):
        raise RuntimeError('test plugin could not start')
    cases = {}
    sink = idc.get_name_ea_simple('semantic_sink')
    # These declarations come from semantic_sample.cpp and are applied only to
    # the disposable fixture IDB. Production analysis never writes types.
    declarations = {
        'sink': 'void semantic_sink(unsigned __int64 n);',
        'checked': 'void semantic_checked(unsigned __int64 n, unsigned __int64 cap);',
        'diamond': 'void semantic_diamond(unsigned __int64 n, unsigned __int64 cap);',
        'overwritten': 'void semantic_overwritten(unsigned __int64 n, unsigned __int64 cap, unsigned __int64 other);',
        'converted': 'void semantic_converted(__int64 n, __int64 cap);',
        'merge': 'void semantic_merge(unsigned __int64 n, unsigned __int64 flag);',
        'constant': 'void semantic_constant(void);',
        'leaf': 'void semantic_leaf(unsigned __int64 n);',
        'mid': 'void semantic_mid(unsigned __int64 n);',
        'top_a': 'void semantic_top_a(void);',
        'top_b': 'void semantic_top_b(void);',
        'recursive': 'void semantic_recursive(unsigned __int64 n);',
        'with_handler': 'void semantic_with_handler(unsigned __int64 n);',
    }
    for name, declaration in declarations.items():
        if not idc.SetType(idc.get_name_ea_simple('semantic_' + name), declaration):
            raise RuntimeError('could not apply fixture declaration ' + name)
    ida_auto.auto_wait()
    for name in ['checked', 'diamond', 'overwritten', 'converted', 'merge', 'constant', 'leaf', 'recursive', 'with_handler']:
        entry = idc.get_name_ea_simple('semantic_' + name)
        function = ida_funcs.get_func(entry)
        if function is None:
            raise RuntimeError('missing sample function ' + name)
        target = entry if name == 'recursive' else sink
        calls = [ea for ea in idautils.FuncItems(entry)
                 if idc.print_insn_mnem(ea).lower() == 'call'
                 and target in list(idautils.CodeRefsFrom(ea, False))]
        if len(calls) != 1:
            raise RuntimeError('expected one real sink call in ' + name)
        cases[name] = {'callAddress': hex(calls[0]), 'argumentIndex': 0}
    ready = Path(os.environ['IDA_AGENT_TEST_READY_FILE'])
    ready.write_text(json.dumps(cases), encoding='utf-8')
    release = Path(os.environ['IDA_AGENT_TEST_RELEASE_FILE'])
    def stop():
        deadline = time.monotonic() + 180
        while not release.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        ida_kernwin.stop_serving()
    threading.Thread(target=stop, daemon=True).start()
    ida_kernwin.serve()
    # Capture diagnostic evidence after the RPCs, without warming the analysis.
    for name in cases:
        entry = idc.get_name_ea_simple('semantic_' + name)
        mba = ida_hexrays.gen_microcode(ida_hexrays.decomp_ranges_t(entry), None, None,
                                       ida_hexrays.DECOMP_NO_WAIT, ida_hexrays.MMAT_CALLS)
        if mba is None:
            continue
        lines = ['argument indexes: ' + str(list(mba.argidx))]
        for b in range(mba.qty):
            block = mba.get_mblock(b)
            lines.append('block ' + str(b))
            ins = block.head
            while ins:
                lines.append(hex(ins.ea) + ': ' + ins.dstr())
                ins = ins.next
        ready.with_name(name + '.microcode.txt').write_text('\n'.join(lines), encoding='utf-8')
    ida_pro.qexit(0)


try:
    main()
except Exception:
    import traceback
    traceback.print_exc()
    ida_pro.qexit(1)
