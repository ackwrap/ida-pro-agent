"""Exercise the built plugin through RPC against fixed unoptimized/optimized samples."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from plugin_rpc_client import PipeApi, RpcVerifier, require


def read_registry(path):
    if sys.platform == "linux":
        return json.loads(path.read_text(encoding="utf-8"))
    import msvcrt
    # RegistryFile holds DELETE access for its lifetime; readers must share it.
    api = PipeApi()
    handle = api.kernel32.CreateFileW(str(path), api.GENERIC_READ, 7, None,
                                      api.OPEN_EXISTING, 0, None)
    if handle == api.INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY)
    except Exception:
        api.close(handle)
        raise
    with os.fdopen(fd, 'r', encoding='utf-8') as source:
        return json.loads(source.read(1 << 20))


def run(args):
    root = Path(tempfile.mkdtemp(prefix='ida-semantic-'))
    user = root / 'ida-user'
    plugins = user / 'plugins'
    plugins.mkdir(parents=True, mode=0o700)
    linux = sys.platform == 'linux'
    shutil.copy2(args.plugin, plugins / ('ida-agent-plugin.so' if linux else 'ida-agent-plugin.dll'))
    instances = root / 'instances'
    ready, release = root / 'ready.json', root / 'release'
    env = dict(os.environ, IDAUSR=str(user), IDA_AGENT_INSTANCE_DIR=str(instances),
               IDA_AGENT_TEST_READY_FILE=str(ready), IDA_AGENT_TEST_RELEASE_FILE=str(release))
    command = [str(Path(args.ida_dir) / ('idat' if linux else 'idat.exe')), '-A', '-c', '-L' + str(root / 'ida.log'),
               '-o' + str(root / 'sample.i64'), '-S' + str(Path(__file__).with_name('semantic_hold.py')),
               str(Path(args.sample).resolve())]
    print('Semantic integration artifacts: ' + str(root), flush=True)
    with (root / 'process.log').open('wb') as log:
        if linux:
            from linux_test_environment import configure_linux_user
            configure_linux_user(args.ida_dir, user, env, log)
        process = subprocess.Popen(command, cwd=root, env=env, stdout=log, stderr=log,
                                   creationflags=0 if linux else subprocess.CREATE_NO_WINDOW)
        try:
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline and process.poll() is None:
                descriptors = list(instances.glob('*.json'))
                if ready.exists() and descriptors:
                    try:
                        descriptor = read_registry(descriptors[0])
                        cases = json.loads(ready.read_text(encoding='utf-8'))
                        break
                    except (PermissionError, FileNotFoundError, json.JSONDecodeError):
                        pass  # The registry writer may still hold the publication lock.
                time.sleep(0.1)
            else:
                raise AssertionError('IDA fixture startup failed (exit=' + str(process.poll())
                                     + '); see ' + str(root / 'ida.log'))
            rpc = RpcVerifier(descriptor)
            results = {}
            for name, params in cases.items():
                params.update(maxNodes=500, maxWork=100000, maxGuards=64)
                print('Analyzing sample: ' + name, flush=True)
                results[name] = rpc.call('analysis.guard_evidence', params)
                (root / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
            (root / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
            exception_regions = {}
            for name, result in results.items():
                exception_regions[name] = rpc.call('exception.try_blocks', {
                    'address': result['entryAddress'], 'limit': 100})
            (root / 'exceptions.json').write_text(json.dumps(exception_regions, indent=2), encoding='utf-8')
            for name, result in results.items():
                require(result['model'] == 'microcode_reaching_definitions' and result['maturity'] == 'MMAT_CALLS', name + ': wrong model')
                require(not result['truncated'] and result['root'] is not None, name + ': incomplete sample analysis')
            checked = results['checked']['guards']
            require(not results['with_handler']['cfgComplete']
                    and 'exception_edges_not_modeled' in results['with_handler']['limitations'],
                    'real exception handlers must retain conservative CFG reporting')
            require(any(g['requiredBranch'] in ('true', 'false') and g['valueRelation'] == 'same_value' for g in checked), 'early-return check was not recognized')
            require(all(g['requiredBranch'] == 'neither' for g in results['diamond']['guards']) and results['diamond']['guards'], 'diamond incorrectly reported a required branch')
            require(all(g['valueRelation'] != 'same_value' for g in results['overwritten']['guards']), 'old value check applied to replacement')
            require(any(g['valueRelation'] == 'derived_value' for g in results['converted']['guards']), 'integer conversion evidence was lost')
            require(any(n['kind'] == 'merge' for n in results['merge']['nodes']), 'multiple sources were lost')
            require(any(n['value'] == '0xffffffffffffffff' for n in results['constant']['nodes']), '64-bit constant was corrupted')
            trace = rpc.call('analysis.trace_argument', cases['checked'])
            require(trace['guards'] == [] and trace['root'] is not None, 'trace-only contract')
            partial = rpc.call('analysis.guard_evidence', dict(cases['checked'], maxWork=100000, maxNodes=1))
            require(partial['truncated'] and partial['status'] == 'partial', 'node budget did not truncate')
            rpc.call_error('analysis.trace_argument', dict(cases['checked'], argumentIndex=255), {'INVALID_ARGUMENT'})
            caller_params = dict(callAddress=cases['leaf']['callAddress'], argumentIndex=0,
                                 maxDepth=2, maxContexts=16, maxCallers=8, maxNodes=1000, maxWork=100000)
            callers = rpc.call('analysis.trace_argument_callers', caller_params)
            (root / 'callers.json').write_text(json.dumps(callers, indent=2), encoding='utf-8')
            require(len(callers['contexts']) == 4 and len(callers['links']) == 3,
                    'caller contexts missing: ' + json.dumps(callers['boundaries']))
            values = {n['value'] for c in callers['contexts'] for n in c['trace']['nodes'] if n['kind'] == 'constant'}
            require({'0x1122', '0x3344'} <= values, 'two-hop and alternate caller constants missing')
            require(any(c['depth'] == 2 for c in callers['contexts']), 'second caller hop missing')
            require(callers['status'] == 'partial' and 'caller_set_not_proven_complete' in callers['limitations'], 'caller-set uncertainty lost')
            for field, value, reason in [('maxDepth', 0, 'depth_budget'), ('maxContexts', 1, 'context_budget'),
                                         ('maxCallers', 1, 'caller_budget')]:
                limited = rpc.call('analysis.trace_argument_callers', dict(caller_params, **{field: value}))
                require(limited['truncated'] and any(b['reason'] == reason for b in limited['boundaries']), field + ' not enforced')
            limited = rpc.call('analysis.trace_argument_callers', dict(caller_params, maxWork=1))
            require(limited['truncated'] and limited['visitedWork'] <= 1, 'shared work budget not enforced')
            recursive = rpc.call('analysis.trace_argument_callers', dict(caller_params, callAddress=cases['recursive']['callAddress']))
            (root / 'recursive.json').write_text(json.dumps(recursive, indent=2), encoding='utf-8')
            require(any(b['reason'] == 'recursive_call' for b in recursive['boundaries']), 'recursion was not bounded')
            print('Semantic integration passed: ' + str(args.sample), flush=True)
        finally:
            release.touch()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        require(process.returncode == 0, 'IDA failed to exit cleanly')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--ida-dir', required=True)
    parser.add_argument('--plugin', required=True)
    parser.add_argument('--sample', required=True)
    run(parser.parse_args())
