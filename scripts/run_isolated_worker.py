"""Run an operator-selected command in an offline Linux container through Spoor."""

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess


def run_worker(shim, image, executable, arguments):
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
        raise ValueError("Use the full ID of a locally available Linux image.")
    if not PurePosixPath(executable).is_absolute() or executable == "/":
        raise ValueError("Use an absolute executable path inside the image.")

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
        [docker, "image", "inspect", "--format", "{{json .}}", image],
        check=True, capture_output=True, text=True, timeout=15,
    )
    metadata = json.loads(image_info.stdout)
    if metadata["Id"] != image or metadata["Os"] != "linux":
        raise ValueError("The worker image must be a local Linux image with the requested ID.")
    if metadata["Config"].get("Volumes"):
        raise ValueError("Worker images must not declare Docker volumes.")

    return subprocess.run([
        os.fspath(shim), docker, "run", "--rm", "--pull=never",
        "--network=none", "--read-only", "--user=65532:65532", "--cap-drop=ALL",
        "--security-opt=no-new-privileges=true", "--ipc=none", "--no-healthcheck",
        "--log-driver=none", "--pids-limit=64", "--cpus=1",
        "--memory=128m", "--memory-swap=128m",
        "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777", "--workdir=/tmp",
        "--entrypoint", executable, image, *arguments,
    ]).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shim", required=True, type=Path, help="Path to the built spoor-shim binary")
    parser.add_argument("image", help="Full Docker image ID beginning with sha256:")
    parser.add_argument("executable", help="Absolute path inside the image")
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        return run_worker(args.shim, args.image, args.executable, args.arguments)
    except subprocess.CalledProcessError as error:
        parser.exit(1, f"spoor worker: Docker preflight failed: {error.stderr.strip()}\n")
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"spoor worker: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
