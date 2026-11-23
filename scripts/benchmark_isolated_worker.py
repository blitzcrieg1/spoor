"""Measure the end-to-end strict-audit Linux worker launch on a warm image."""

import argparse
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import time

from check_isolated_worker import launch
from run_synthetic_trace import ROOT, TRAIL, binaries, require, running_broker


WARMUPS = 3
SAMPLES = 25
SESSION = "spoor-worker-latency"


def measure(image):
    spoor, shim = binaries()
    environment = dict(os.environ, ARTEX_SESSION_ID=SESSION, ARTEX_TASK_ID="")
    with tempfile.TemporaryDirectory(prefix="spoor-latency-") as folder:
        directory = Path(folder)
        launcher = [sys.executable, ROOT / "scripts" / "run_isolated_worker.py"]
        options = ["--state-dir", directory / "worker-approvals"]
        request = [image, "/usr/local/bin/python", "-c", "raise SystemExit(0)"]
        approve = launcher + ["approve", *options, *request]
        command = launcher + ["run", "--shim", shim, *options, *request]
        samples = []
        with running_broker(spoor, directory, environment, strict=True) as broker_env:
            for index in range(WARMUPS + SAMPLES):
                token = subprocess.check_output(approve, text=True, timeout=10)
                start = time.perf_counter_ns()
                result = launch(command, token, broker_env)
                duration_ms = (time.perf_counter_ns() - start) / 1_000_000
                require(
                    result.returncode == 0 and not result.stderr,
                    f"Worker launch {index + 1} failed. {result.stderr}",
                )
                if index >= WARMUPS:
                    samples.append(duration_ms)

        trail = (directory / TRAIL).read_text(encoding="utf-8").splitlines()
        events = [json.loads(line) for line in trail]
        allowed = {event["call_id"] for event in events
                   if event["type"] == "decide" and event["decision"] == "allow"}
        completed = {event["call_id"] for event in events
                     if event["type"] == "report" and event["exit_code"] == 0}
        require(
            len(events) == 2 * (WARMUPS + SAMPLES)
            and len(allowed) == WARMUPS + SAMPLES and allowed == completed,
            "Each worker needs one recorded authorization and successful completion.",
        )
    return samples


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", help="Full ID of a local python:3.12-alpine image")
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("Run the benchmark on the Linux worker host.")
    samples = measure(args.image)
    docker_version = subprocess.check_output(
        ["docker", "version", "--format", "{{.Server.Version}}"], text=True, timeout=10,
    ).strip()
    rust_version = subprocess.check_output(["rustc", "--version"], text=True, timeout=10).strip()
    print("### Strict-audit worker launch latency")
    print()
    print(f"- Host: {platform.freedesktop_os_release()['PRETTY_NAME']}, kernel {platform.release()}, "
          f"{platform.machine()}, {os.cpu_count()} logical CPUs")
    print(f"- Docker {docker_version}, {rust_version}, Cargo dev profile")
    print(f"- Worker image: `{args.image}`")
    print(f"- {len(samples)} sequential launches after {WARMUPS} warmups")
    print("- Includes Docker checks, approval consumption, the host broker's synced decision, "
          "container start and exit, and the synced exit report")
    print("- Approval issuance and image pull are outside the timed window")
    p95 = sorted(samples)[math.ceil(len(samples) * 0.95) - 1]
    print(f"- Median: {statistics.median(samples):.1f} ms, p95: {p95:.1f} ms (nearest rank)")


if __name__ == "__main__":
    main()
