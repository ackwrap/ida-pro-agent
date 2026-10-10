"""Run production debugger handlers against an owned target in isolated idat."""
import ctypes
import json
import os
from pathlib import Path
import time
import traceback

import ida_auto
import ida_dbg
import ida_idaapi
import ida_kernwin
import ida_name
import idc

root = Path(os.environ['IDA_AGENT_DEBUGGER_TEST_ROOT'])
report = {'checks': [], 'calls': []}

def save():
    (root / 'debugger-results.json').write_text(json.dumps(report, indent=2), encoding='utf-8')

def require(condition, message):
    if not condition:
        raise AssertionError(message)
    report['checks'].append(message)
    save()

def run():
    ida_auto.auto_wait()
    driver = ctypes.CDLL(os.environ['IDA_AGENT_DEBUGGER_TEST_DRIVER'])
    invoke = driver.ida_debugger_integration_call
    invoke.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t]
    invoke.restype = ctypes.c_int
    def call(method, params=None, error=None):
        output = ctypes.create_string_buffer(524288)
        rc = invoke(method.encode(), json.dumps(params or {}).encode(), output, len(output))
        if rc != 0:
            raise AssertionError(method + ': native driver returned ' + str(rc))
        value = json.loads(output.value)
        report['calls'].append({'method': method, 'response': value})
        save()
        if error:
            require(value.get('error', {}).get('code') == error, method + ': expected ' + error)
            return value
        if 'error' in value:
            raise AssertionError(method + ': ' + str(value))
        return value['result']
    def wait(state, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            # Pump IDA debugger events after async requests; never infer completion
            # from the immediate accepted receipt alone.
            ida_dbg.wait_for_next_event(ida_dbg.WFNE_ANY | ida_dbg.WFNE_SILENT, 1)
            current = call('debugger.info')
            if current['state'] == state:
                return current
        raise AssertionError('debugger did not reach ' + state)

    available = call('debugger.backends')
    backend_name = os.environ.get('IDA_AGENT_DEBUGGER_TEST_BACKEND', 'win32')
    local = next((x for x in available['items'] if x['name'] == backend_name and not x['remote']), None)
    require(local is not None, 'local ' + backend_name + ' debugger is enumerated')
    initial_options = call('debugger.configuration')
    require('hasPassword' in initial_options and 'password' not in initial_options,
            'configuration can be read before debugger selection')
    call('debugger.select', local)
    options = call('debugger.configuration')
    require('password' not in options, 'configuration never returns password')
    sample = os.environ['IDA_AGENT_DEBUGGER_TEST_SAMPLE']
    call('debugger.configure', {'path': sample, 'arguments': '', 'directory': str(root),
                               'host': '', 'port': -1, 'password': 'integration-fixture'})
    configured = call('debugger.configuration')
    require(configured['path'] == sample and configured['hasPassword'], 'launch options and password presence round-trip')
    call('debugger.configure', {'password': ''})
    cleared = call('debugger.configuration')
    require(cleared['path'] == sample and not cleared['hasPassword'], 'clear preserves omitted configuration fields')
    if 'IDA_AGENT_DEBUGGER_TEST_PID_FILE' in os.environ:
        pid_file = Path(os.environ['IDA_AGENT_DEBUGGER_TEST_PID_FILE'])
        deadline = time.monotonic() + 10
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        pid = int(pid_file.read_text(encoding='ascii'))
    else:
        pid = int(os.environ['IDA_AGENT_DEBUGGER_TEST_ATTACH_PID'])
    processes = call('debugger.processes', {'limit': 1000})
    require(any(x['pid'] == pid for x in processes['items']), 'owned attach target is enumerated')
    call('debugger.suspend', error='CONFLICT')
    call('debugger.attach', {'pid': 0}, error='INVALID_ARGUMENT')
    address = ida_name.get_name_ea(ida_idaapi.BADADDR, 'ida_debugger_test_tick')
    require(address != ida_idaapi.BADADDR, 'exported target function is found')
    call('debugger.breakpoints', {'action': 'add', 'address': hex(address)})
    ida_dbg.set_debugger_options(ida_dbg.DOPT_START_BPT)
    require(call('debugger.start')['accepted'], 'start is accepted')
    wait('suspended')
    # Resolve again because the debugger may have rebased the IDB for ASLR.
    address = ida_name.get_name_ea(ida_idaapi.BADADDR, 'ida_debugger_test_tick')
    require(call('debugger.control', {'action': 'run_to', 'address': hex(address)})['accepted'], 'run-to is accepted')
    stopped = wait('suspended')
    require(int(stopped['instructionPointer'], 16) == address, 'run-to stops at exported target function')
    call('debugger.control', {'action': 'step_into'})
    stepped = wait('suspended')
    require(stepped['instructionPointer'] != stopped['instructionPointer'], 'step-into advances the instruction pointer')
    call('debugger.control', {'action': 'step_over'})
    stepped_over = wait('suspended')
    require(stepped_over['instructionPointer'] != stepped['instructionPointer'], 'step-over advances the instruction pointer')
    call('debugger.registers', {'registerMode': 'named', 'names': ['RIP']})
    call('debugger.memory_read', {'address': hex(address), 'length': 8})
    call('debugger.breakpoints', {'action': 'delete', 'address': hex(address)})
    call('debugger.control', {'action': 'continue'})
    require(call('debugger.info')['state'] == 'running', 'continue resumes target execution')
    call('debugger.select', local, error='CONFLICT')
    call('debugger.configure', {'arguments': 'must-not-apply'}, error='CONFLICT')
    call('debugger.detach', error='CONFLICT')
    require(call('debugger.suspend')['accepted'], 'running target accepts pause')
    paused = wait('suspended')
    require(not paused['running'] and paused['suspended'], 'pause flags match the Gateway contract')
    require(call('debugger.configuration')['arguments'] == '', 'rejected running configuration leaves options unchanged')
    call('debugger.exit')
    wait('not_running')
    require(call('debugger.attach', {'pid': pid})['accepted'], 'attach to owned target is accepted')
    wait('suspended')
    require(call('debugger.detach')['accepted'], 'detach from owned target is accepted')
    wait('not_running')
    report['success'] = True
    report['detachedPid'] = pid
    save()

try:
    run()
except BaseException:
    report['success'] = False
    report['failure'] = traceback.format_exc()
    save()
finally:
    if ida_dbg.get_process_state() != ida_dbg.DSTATE_NOTASK:
        ida_dbg.exit_process()
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_ANY | ida_dbg.WFNE_SILENT, 5)
    idc.qexit(0 if report.get('success') else 1)
