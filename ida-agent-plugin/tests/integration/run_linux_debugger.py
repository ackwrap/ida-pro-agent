"""Run production Linux debugger services against runner-owned processes only."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

from linux_test_environment import configure_linux_user


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ida-dir", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--sample", type=Path, required=True)
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="ida-debugger-"))
    print("artifacts=" + str(root), flush=True)
    user = root / "user"
    user.mkdir(mode=0o700)
    pid_file = root / "target.pid"
    environment = dict(os.environ, IDAUSR=str(user), IDA_AGENT_INSTANCE_DIR=str(root / "instances"),
        IDA_AGENT_DEBUGGER_TEST_ROOT=str(root),
        IDA_AGENT_DEBUGGER_TEST_DRIVER=str(args.driver.resolve()),
        IDA_AGENT_DEBUGGER_TEST_SAMPLE=str(args.sample.resolve()),
        IDA_AGENT_DEBUGGER_TEST_BACKEND="linux", IDA_AGENT_DEBUGGER_TEST_PID_FILE=str(pid_file))
    driver = Path(__file__).with_name("debugger_idat.py").resolve()
    command = [str(args.ida_dir.resolve() / "idat"), "-A", "-c", f"-L{root / 'ida.log'}",
        f"-o{root / 'sample.i64'}", f"-S{driver}", str(args.sample.resolve())]
    ida = target = None
    try:
        with (root / "process.log").open("wb") as log:
            configure_linux_user(args.ida_dir.resolve(), user, environment, log)
            ida = subprocess.Popen(command, cwd=root, env=environment, stdout=log, stderr=log)
            target = subprocess.Popen([str(args.sample.resolve()), str(ida.pid)], cwd=root,
                stdout=log, stderr=log)
            temporary = root / "target.pid.tmp"
            temporary.write_text(str(target.pid), encoding="ascii")
            temporary.replace(pid_file)
            ida.wait(timeout=150)
        result = json.loads((root / "debugger-results.json").read_text(encoding="utf-8"))
        assert ida.returncode == 0 and result.get("success"), result.get("failure", result)
        assert target.poll() is None, "detach terminated the owned target"
        result["detachedTargetStillAlive"] = True
        (root / "debugger-results.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        print("linux_debugger=ok start=ok step=ok pause=ok exit=ok attach=ok detach=ok", flush=True)
    finally:
        for owned in (ida, target):
            if owned is not None and owned.poll() is None:
                owned.kill()
                owned.wait(timeout=10)


if __name__ == "__main__":
    main()
