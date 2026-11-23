"""Check the isolated worker through the real broker, shim, and Docker."""

import argparse
from contextlib import contextmanager
from importlib.metadata import version
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time
from urllib.request import Request, urlopen

from run_synthetic_trace import ROOT, SESSION, TRAIL, binaries, forward_trace, require, running_broker


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


@contextmanager
def running_agentmetry(directory):
    require(version("agentmetry") == "0.13.0", "Install Agentmetry v0.13.0 for this check.")
    directory.mkdir()
    profile = directory / "profile"
    profile.mkdir()
    api_key = secrets.token_hex(32)
    env = {
        name: value for name, value in os.environ.items()
        if not name.startswith("AGENTMETRY_") and name != "OPERATOR_ID"
    }
    env.update(
        AGENTMETRY_DATA_DIR=str(directory),
        AGENTMETRY_USER_PROFILE_DIR=str(profile),
        AGENTMETRY_API_KEY=api_key,
        AGENTMETRY_AUDIT_SINK="file",
        AGENTMETRY_AUTO_INSTALL_HOOKS="0",
    )
    log_path = directory / "agentmetry.log"
    with log_path.open("wb") as log, subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "agentmetry.api.main:app",
         "--host", "127.0.0.1", "--port", "0", "--no-access-log"],
        cwd=directory, env=env, stdout=log, stderr=subprocess.STDOUT,
    ) as process:
        try:
            for _ in range(200):
                log_text = log_path.read_text(encoding="utf-8", errors="replace")
                if process.poll() is not None:
                    break
                match = re.search(r"Uvicorn running on (http://127\.0\.0\.1:\d+)", log_text)
                if match:
                    yield match[1], api_key
                    return
                time.sleep(0.05)
            raise SystemExit(
                "Agentmetry did not start.\n" + log_text[-3000:].replace(api_key, "[redacted]")
            )
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()


def check_agentmetry(spoor, directory, decision, approval):
    recorder = directory / "agentmetry"
    with running_agentmetry(recorder) as (base, api_key):
        env = dict(
            os.environ, AGENTMETRY_URL=base, AGENTMETRY_API_KEY=api_key,
            BROKER_DATA_DIR=str(directory), SPOOR_STATE_DIR=str(directory),
            SPOOR_SOURCE="broker", SPOOR_DRY_RUN="0",
        )
        env.pop("AGENTMETRY_HOST_HEADER", None)
        forward_trace(spoor, env)
        request = Request(f"{base}/api/v1/audit/tail?limit=20", headers={"X-API-Key": api_key})
        with urlopen(request, timeout=5) as response:
            readback = response.read()

    saved = (recorder / "audit-forward.jsonl").read_text(encoding="utf-8")
    require(approval not in readback.decode("utf-8") and approval not in saved,
            "Agentmetry exposed the worker approval token.")
    stored = [json.loads(line) for line in saved.splitlines()]
    stored_ids = {row.get("event", row)["event_id"] for row in stored}
    rows = [row for row in json.loads(readback)["events"] if row["session_id"] == SESSION]
    require(len(rows) == 2, "Agentmetry should store one authorization and one completion.")
    require(all(
        row["source"]["adapter"] == "spoor"
        and row["event_id"] in stored_ids
        and row["tool"]["arguments"]["call_id"] == decision["call_id"]
        for row in rows), "Agentmetry lost the Spoor adapter or worker call ID.")
    phases = {row["tool"]["arguments"]["phase"]: row for row in rows}
    require(set(phases) == {"authorization", "completion"}
            and phases["authorization"]["action"]["outcome"] == "pending"
            and phases["completion"]["action"]["outcome"] == "success"
            and phases["completion"]["tool"]["arguments"]["exit_code"] == 0,
            "Agentmetry lost the worker authorization or exit result.")
    print("Agentmetry v0.13.0 stored both worker events with the same call ID and no approval token.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", help="Local Linux image ID")
    parser.add_argument("--agentmetry", action="store_true", help="Verify against installed Agentmetry v0.13.0")
    args = parser.parse_args()
    spoor, shim = binaries()
    env = dict(os.environ, ARTEX_SESSION_ID=SESSION, ARTEX_TASK_ID="")
    with tempfile.TemporaryDirectory() as folder:
        directory = Path(folder)
        with tempfile.NamedTemporaryFile(prefix="spoor-host-only-", dir="/tmp") as host_file:
            launcher = [sys.executable, ROOT / "scripts" / "run_isolated_worker.py"]
            options = ["--state-dir", directory / "worker-approvals"]
            request = [
                args.image, "/usr/local/bin/python", "-c", PARENT,
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

        rejected = subprocess.check_output(launcher + ["rejections", *options], text=True, timeout=10)
        require(token.strip() not in rejected, "The rejection export exposed the approval token.")
        records = [json.loads(line) for line in rejected.splitlines()]
        require(
            [record["reason"] for record in records] == ["approval_request_mismatch", "approval_reused"]
            and all(
                set(record) == {"type", "timestamp_utc", "request_fingerprint", "reason"}
                and record["type"] == "worker_approval_rejected"
                for record in records
            ),
            "The launcher must export exactly one minimal record per rejected approval.",
        )

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
        if args.agentmetry:
            check_agentmetry(spoor, directory, decision, token.strip())

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
    print("Worker isolation, one-time approval, rejection records, and strict audit passed.")


if __name__ == "__main__":
    main()
