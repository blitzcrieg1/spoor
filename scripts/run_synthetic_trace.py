"""Run two harmless commands through the real shim, broker, and audit watcher."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "rust" / "Cargo.toml"
POLICY = ROOT / "rust" / "policy.json"
TRAIL = "broker-events.jsonl"
SESSION = "spoor-demo-session"


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def binaries():
    cargo = ["cargo", "build", "--locked", "--manifest-path", str(MANIFEST), "--workspace"]
    subprocess.run(cargo, cwd=ROOT, check=True)
    metadata = subprocess.check_output(
        ["cargo", "metadata", "--locked", "--manifest-path", str(MANIFEST),
         "--format-version", "1", "--no-deps"], cwd=ROOT,
    )
    target = Path(json.loads(metadata)["target_directory"]) / "debug"
    suffix = ".exe" if os.name == "nt" else ""
    return target / ("spoor" + suffix), target / ("spoor-shim" + suffix)


@contextmanager
def running_broker(spoor, directory, env, strict=True):
    env = dict(env, BROKER_DATA_DIR=str(directory), SPOOR_STATE_DIR=str(directory),
               BROKER_APPROVALS=str(directory / "approvals"),
               BROKER_LISTEN="127.0.0.1:0", SPOOR_STRICT_AUDIT="1" if strict else "0")
    log_path = directory / "broker.log"
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            [spoor, "broker", "--policy", POLICY], cwd=directory, env=env,
            stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            for _ in range(100):
                require(process.poll() is None, "The demo broker exited during startup.")
                log_text = log_path.read_text(encoding="utf-8", errors="replace")
                address = re.search(r"broker on (http://127\.0\.0\.1:\d+)", log_text)
                if address:
                    yield dict(env, ARTEX_BROKER_URL=address[1])
                    return
                time.sleep(0.05)
            raise SystemExit("The demo broker did not start within five seconds.")
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)


def run_calls(shim, env):
    for code in (0, 7):
        result = subprocess.run(
            [shim, sys.executable, "-c", f"raise SystemExit({code})"],
            env=env, capture_output=True, text=True, timeout=10,
        )
        require(result.returncode == code and not result.stderr,
                f"Expected shim exit {code}. Got {result.returncode}. {result.stderr}")


def forward_trace(spoor, env):
    subprocess.run(
        [spoor, "watch", "--once", "--policy", POLICY], cwd=ROOT, env=env,
        check=True, timeout=20,
    )


def check_pairs(directory, received, session):
    trail = [json.loads(line) for line in
             (directory / TRAIL).read_text(encoding="utf-8").splitlines()]
    require(len(trail) == 4 and len(received) == 4,
            "Expected two decisions and two reports in both the trail and collector.")
    decisions = {row["call_id"]: row for row in trail if row["type"] == "decide"}
    reports = {row["call_id"]: row for row in trail if row["type"] == "report"}
    require(len(decisions) == 2 and decisions.keys() == reports.keys(),
            "The broker trail did not pair two distinct calls.")
    require({row["exit_code"] for row in reports.values()} == {0, 7},
            "The broker trail lost one of the tool exit codes.")
    for call_id in decisions:
        decision, report = decisions[call_id], reports[call_id]
        rows = [row for row in received if row["tool"]["arguments"]["call_id"] == call_id]
        expected_outcome = "success" if report["exit_code"] == 0 else "error"
        expected_event = "tool_called" if report["exit_code"] == 0 else "tool_failed"
        parent = decision.get("parent_command_line")
        require(decision["decision"] == "allow" and report["command"] == decision["command"]
                and report["command"].endswith(f"raise SystemExit({report['exit_code']})")
                and report.get("parent_command_line") == parent
                and report["session"] == decision["session"] == session, "Broker pair diverged.")
        require(len(rows) == 2 and
                [row["tool"]["arguments"]["phase"] for row in rows] == ["authorization", "completion"]
                and [(row["event_type"], row["outcome"]) for row in rows]
                == [("tool_authorized", "pending"), (expected_event, expected_outcome)]
                and "exit_code" not in rows[0]["tool"]["arguments"]
                and rows[1]["tool"]["arguments"]["exit_code"] == report["exit_code"]
                and all(row["session_id"] == session and row["correlation_id"] == session
                        and row["tool"]["arguments"]["command"] == decision["command"]
                        and row["tool"]["arguments"].get("parent_command_line") == parent
                        for row in rows),
                f"The collector lost the decision or outcome for {call_id}.")
        print(f"{call_id}  authorized -> {expected_outcome} (exit {report['exit_code']})")


def check_strict_mode(spoor, shim, directory, env):
    directory.mkdir()
    (directory / TRAIL).mkdir()  # A directory cannot be opened as an append-only file.
    with running_broker(spoor, directory, env) as broker_env:
        result = subprocess.run(
            [shim, sys.executable, "-c", "print('unexpected execution')"],
            env=broker_env, capture_output=True, text=True, timeout=10,
        )
        require(result.returncode == 126 and not result.stdout
                and "audit-unavailable" in result.stderr,
                "Strict audit did not refuse the unrecordable action.")
        require("audit append failed" in (directory / "broker.log").read_text(encoding="utf-8"),
                "The broker did not log the audit error.")
    print("Strict audit refused a call when the decision trail was unavailable.")


def check_ingest_recovery(spoor, shim, directory, env, reject_completion, received):
    directory.mkdir()
    queue = directory / "failed-queue.rust.jsonl"
    queue.mkdir()
    checkpoint = directory / "spoor.rust-state.json"
    events_before = len(received)

    def wait_for_offset(expected):
        for _ in range(150):
            if checkpoint.exists() and json.loads(checkpoint.read_text(encoding="utf-8"))["offset"] == expected:
                return
            time.sleep(0.05)
        raise SystemExit(f"Watcher did not reach the expected checkpoint at byte {expected}.")

    with running_broker(spoor, directory, env) as broker_env:
        run_calls(shim, broker_env)
        trail = (directory / TRAIL).read_bytes()
        prefix_end = trail.index(b"\n") + 1
        reject_completion.set()
        with (directory / "watcher.log").open("wb") as log:
            with subprocess.Popen(
                [spoor, "watch", "--policy", POLICY], cwd=ROOT, env=broker_env,
                stdout=log, stderr=subprocess.STDOUT,
            ) as watcher:
                try:
                    wait_for_offset(prefix_end)
                    for _ in range(100):
                        log_text = (directory / "watcher.log").read_text(encoding="utf-8", errors="replace")
                        if "broker trail checkpoint held" in log_text:
                            break
                        time.sleep(0.05)
                    else:
                        raise SystemExit("Watcher did not report the blocked checkpoint.")
                    require(len(received) == events_before + 1,
                            "Watcher attempted events after an unsaved completion.")
                    reject_completion.clear()
                    queue.rmdir()
                    wait_for_offset(len(trail))
                    require(len(received) == events_before + 4,
                            "Recovery lost an event or repeated the acknowledged prefix.")
                finally:
                    reject_completion.clear()
                    if watcher.poll() is None:
                        watcher.terminate()
                    watcher.wait(timeout=5)
    print("Watcher held its checkpoint and resumed after the failed delivery recovered.")


def main():
    spoor, shim = binaries()
    demo_dir = ROOT / ".spoor-demo"
    demo_dir.mkdir(exist_ok=True)
    received = []
    reject_completion = threading.Event()

    class Collector(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != "/api/v1/audit/ingest":
                self.send_error(404)
                return
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if reject_completion.is_set() and payload["tool"]["arguments"]["phase"] == "completion":
                self.send_error(400)
                return
            received.append(payload)
            self.send_response(204)
            self.end_headers()

        def log_message(self, *_):
            pass

    with tempfile.TemporaryDirectory(dir=demo_dir) as folder:
        directory = Path(folder)
        with ThreadingHTTPServer(("127.0.0.1", 0), Collector) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            env = dict(os.environ, ARTEX_SESSION_ID=SESSION, ARTEX_TASK_ID="",
                       SPOOR_SOURCE="broker", SPOOR_DRY_RUN="0",
                       AGENTMETRY_URL=f"http://127.0.0.1:{server.server_port}",
                       AGENTMETRY_HOST_HEADER="localhost", AGENTMETRY_API_KEY="")
            try:
                with running_broker(spoor, directory, env) as broker_env:
                    run_calls(shim, broker_env)
                    forward_trace(spoor, broker_env)
                check_pairs(directory, received, SESSION)
                check_ingest_recovery(
                    spoor, shim, directory / "ingest-recovery", env, reject_completion, received,
                )
            finally:
                server.shutdown()
                thread.join()
        check_strict_mode(spoor, shim, directory / "strict-audit", env)


if __name__ == "__main__":
    main()
