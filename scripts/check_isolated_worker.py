"""Check the isolated worker through the real broker, shim, and Docker."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from run_synthetic_trace import ROOT, SESSION, TRAIL, binaries, require, running_broker


PROBE = """
import os
from pathlib import Path
import socket
import sys

assert os.getuid() == os.getgid() == 65532
assert {name for _, name in socket.if_nameindex()} == {"lo"}
status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
assert int(status["CapEff"], 16) == 0
assert int(status["NoNewPrivs"]) == 1
assert int(status["Seccomp"]) == 2
assert os.statvfs("/").f_flag & os.ST_RDONLY
assert not Path("/tmp/" + sys.argv[1]).exists()
Path("/tmp/worker-can-write").write_text("isolated")
print("worker-isolated")
"""

PARENT = """
import subprocess
import sys

subprocess.run([sys.executable, "-c", sys.argv[1], sys.argv[2]], check=True)
"""


def launch(command, token, env):
    return subprocess.run(
        command, input=token, env=env, capture_output=True, text=True, timeout=45,
    )


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python scripts/check_isolated_worker.py <local-linux-image-id>")
    image = sys.argv[1]
    spoor, shim = binaries()
    env = dict(os.environ, ARTEX_SESSION_ID=SESSION, ARTEX_TASK_ID="")
    with tempfile.TemporaryDirectory() as folder:
        directory = Path(folder)
        with tempfile.NamedTemporaryFile(prefix="spoor-host-only-", dir="/tmp") as host_file:
            launcher = [sys.executable, ROOT / "scripts" / "run_isolated_worker.py"]
            options = ["--state-dir", directory / "worker-approvals"]
            request = [
                image, "/usr/local/bin/python", "-c", PARENT,
                PROBE, Path(host_file.name).name,
            ]
            approve = launcher + ["approve", *options, *request]
            command = launcher + ["run", "--shim", shim, *options, *request]
            token = subprocess.check_output(approve, text=True, timeout=10)
            with running_broker(spoor, directory, env) as broker_env:
                changed = launch(command + ["extra-argument"], token, broker_env)
                require(changed.returncode == 1 and "different request" in changed.stderr
                        and not changed.stdout, "The changed worker request should be refused.")
                result = launch(command, token, broker_env)
                repeated = launch(command, token, broker_env)
            require(result.returncode == 0, f"Isolated worker failed. {result.stderr}")
            require(result.stdout.strip() == "worker-isolated", "The worker probe did not complete.")
            require(not result.stderr, f"The shim or runtime reported an error. {result.stderr}")
            require(repeated.returncode == 1 and "used" in repeated.stderr
                    and not repeated.stdout, "Replaying an approval should be refused.")

        trail = (directory / TRAIL).read_text(encoding="utf-8")
        require(token.strip() not in trail, "The trail exposed the approval token.")
        events = [json.loads(line) for line in trail.splitlines()]
        require(len(events) == 2, "Expected one decision and one completion.")
        decision, completion = events
        require(
            decision["type"] == "decide" and decision["decision"] == "allow"
            and completion["type"] == "report" and completion["exit_code"] == 0
            and decision["call_id"] == completion["call_id"]
            and decision["session"] == completion["session"] == SESSION,
            "The worker's audit records did not pair by call ID.",
        )

        blocked = directory / "blocked"
        blocked.mkdir()
        (blocked / TRAIL).mkdir()
        with running_broker(spoor, blocked, env) as broker_env:
            result = launch(command, subprocess.check_output(approve, text=True, timeout=10),
                            broker_env)
        require(
            result.returncode == 126 and not result.stdout and "audit-unavailable" in result.stderr,
            f"Strict audit should stop the worker before execution. {result.stderr}",
        )
        nonstrict = directory / "nonstrict"
        nonstrict.mkdir()
        with running_broker(spoor, nonstrict, env, strict=False) as broker_env:
            result = launch(command, subprocess.check_output(approve, text=True, timeout=10),
                            broker_env)
        require(
            result.returncode == 126 and not result.stdout and "strict-audit-required" in result.stderr,
            f"The worker must require strict audit. {result.stderr}",
        )
    print("Worker isolation, one-time approval, matched audit records, and strict audit refusal passed.")


if __name__ == "__main__":
    main()
