"""Configure a private IDA user directory without changing the installed user's settings."""
import os
from pathlib import Path
import shutil
import subprocess
import sys


def configure_linux_user(ida_dir, user, environment, log):
    existing = Path(os.environ.get("IDAUSR", str(Path.home() / ".idapro"))) / "ida.reg"
    # Copy already accepted terms; never synthesize acceptance or copy a license.
    if existing.is_file():
        shutil.copy2(existing, user / "ida.reg")
    command = [str(Path(ida_dir) / "idapyswitch"), "--auto-apply"]
    if sys.platform == "darwin" and environment.get("IDA_AGENT_TEST_PYTHON_LIBRARY"):
        command += ["--force-path", environment["IDA_AGENT_TEST_PYTHON_LIBRARY"]]
    subprocess.run(command,
        cwd=ida_dir, env=environment, stdout=log, stderr=subprocess.STDOUT,
        timeout=30, check=True)
