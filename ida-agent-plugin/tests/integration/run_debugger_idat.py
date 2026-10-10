"""Launch an owned sample and an isolated idat instance; retain all evidence."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def run(args):
    root = Path(tempfile.mkdtemp(prefix='ida-debugger-integration-')).resolve()
    (root / 'ida-user').mkdir()
    env = dict(os.environ, IDAUSR=str(root / 'ida-user'),
               IDA_AGENT_INSTANCE_DIR=str(root / 'instances'),
               IDA_AGENT_DEBUGGER_TEST_ROOT=str(root),
               IDA_AGENT_DEBUGGER_TEST_DRIVER=str(Path(args.driver).resolve()),
               IDA_AGENT_DEBUGGER_TEST_SAMPLE=str(Path(args.sample).resolve()))
    print('Debugger integration artifacts: ' + str(root), flush=True)
    target = subprocess.Popen([env['IDA_AGENT_DEBUGGER_TEST_SAMPLE']], cwd=root,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              creationflags=subprocess.CREATE_NO_WINDOW)
    env['IDA_AGENT_DEBUGGER_TEST_ATTACH_PID'] = str(target.pid)
    command = [str(Path(args.ida_dir) / 'idat.exe'), '-A', '-c', '-L' + str(root / 'ida.log'),
               '-o' + str(root / 'debugger.i64'),
               '-S' + str(Path(__file__).with_name('debugger_idat.py').resolve()),
               env['IDA_AGENT_DEBUGGER_TEST_SAMPLE']]
    process = None
    try:
        with (root / 'process.log').open('wb') as log:
            process = subprocess.Popen(command, cwd=root, env=env, stdout=log, stderr=log,
                                       creationflags=subprocess.CREATE_NO_WINDOW)
            process.wait(timeout=150)
        result = json.loads((root / 'debugger-results.json').read_text(encoding='utf-8'))
        if process.returncode != 0 or not result.get('success'):
            raise AssertionError(result.get('failure', 'idat exit=' + str(process.returncode)))
        if target.poll() is not None:
            raise AssertionError('detach terminated the owned target')
        result['detachedTargetStillAlive'] = True
        (root / 'debugger-results.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        print('Real IDA debugger integration passed; detached target remains alive', flush=True)
    finally:
        for owned in (process, target):
            if owned is not None and owned.poll() is None:
                owned.kill()
                owned.wait(timeout=10)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--ida-dir', required=True)
    parser.add_argument('--driver', required=True)
    parser.add_argument('--sample', required=True)
    run(parser.parse_args())
