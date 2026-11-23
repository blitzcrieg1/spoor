"""Run an operator-selected command in an offline Linux container through Spoor."""

import argparse
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys

from worker_approval import WorkerRequest, consume_approval, issue_approval, read_rejections


def run_worker(shim, request, state_dir, token):
    docker = shutil.which("docker")
    if docker is None:
        raise ValueError("Docker CLI is required.")
    shim = shim.resolve(strict=True)
    if not shim.is_file():
        raise ValueError("The shim path must point to a built spoor-shim binary.")

    docker = os.fspath(Path(docker).absolute())
    info = subprocess.run(
        [docker, "info", "--format", "{{json .}}"],
        check=True, capture_output=True, text=True, timeout=15,
    )
    daemon = json.loads(info.stdout)
    if daemon.get("OSType") != "linux":
        raise ValueError("The Docker daemon must run Linux containers.")
    limits = ("PidsLimit", "CpuCfsQuota", "MemoryLimit", "SwapLimit")
    if not all(daemon.get(limit) is True for limit in limits):
        raise ValueError("Docker must support PID, CPU, memory, and swap limits.")
    if not any(
        "name=seccomp" in option.split(",") and "profile=unconfined" not in option.split(",")
        for option in daemon.get("SecurityOptions", ())
    ):
        raise ValueError("Docker must have a seccomp profile enabled.")

    image_info = subprocess.run(
        [docker, "image", "inspect", "--format", "{{json .}}", request.image],
        check=True, capture_output=True, text=True, timeout=15,
    )
    metadata = json.loads(image_info.stdout)
    if metadata["Id"] != request.image or metadata["Os"] != "linux":
        raise ValueError("The worker image must be a local Linux image with the requested ID.")
    if metadata["Config"].get("Volumes"):
        raise ValueError("Worker images must not declare Docker volumes.")

    if not consume_approval(state_dir, request, token):
        raise ValueError("Approval is missing, expired, used, or bound to a different request.")

    return subprocess.run([
        os.fspath(shim), docker, "run", "--rm", "--pull=never",
        *request.isolation_profile, "--entrypoint", request.executable, request.image,
        *request.arguments,
    ], stdin=subprocess.DEVNULL, env=dict(os.environ, SPOOR_REQUIRE_STRICT_AUDIT="1")).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    approve = commands.add_parser("approve", help="Create a five-minute, single-use approval")
    run = commands.add_parser("run", help="Read an approval from standard input and start the worker")
    rejections = commands.add_parser("rejections", help="Print approval rejection records as JSONL")
    run.add_argument("--shim", required=True, type=Path, help="Path to the built spoor-shim binary")
    for command in (approve, run, rejections):
        command.add_argument("--state-dir", required=True, type=Path, help="Private approval directory")
    for command in (approve, run):
        command.add_argument("image", help="Full Docker image ID beginning with sha256:")
        command.add_argument("executable", help="Absolute path inside the image")
        command.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        if args.command == "rejections":
            if sys.platform != "linux":
                raise ValueError("Worker approval records are available on the Linux host.")
            for record in read_rejections(args.state_dir):
                print(json.dumps(record))
            return 0
        request = WorkerRequest.from_cli(args.image, args.executable, args.arguments)
        if args.command == "approve":
            print(issue_approval(args.state_dir, request))
            return 0
        token = sys.stdin.readline(64).removesuffix("\n")
        return run_worker(args.shim, request, args.state_dir, token)
    except subprocess.CalledProcessError as error:
        parser.exit(1, f"spoor worker: Docker preflight failed: {error.stderr.strip()}\n")
    except (ValueError, OSError, sqlite3.Error, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"spoor worker: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
