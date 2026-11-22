"""Single-use approvals kept in the trusted Linux operator's local store."""

from contextlib import closing, contextmanager
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import secrets
import sqlite3
import stat
import sys
import time


ISOLATION_PROFILE = (
    "--network=none", "--read-only", "--user=65532:65532", "--cap-drop=ALL",
    "--security-opt=no-new-privileges=true", "--ipc=none", "--no-healthcheck",
    "--log-driver=none", "--pids-limit=64", "--cpus=1",
    "--memory=128m", "--memory-swap=128m",
    "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777", "--workdir=/tmp",
)
APPROVAL_TTL = 300


@dataclass(frozen=True)
class WorkerRequest:
    caller_uid: int
    image: str
    executable: str
    arguments: tuple[str, ...]
    isolation_profile: tuple[str, ...] = ISOLATION_PROFILE

    @classmethod
    def from_cli(cls, image, executable, arguments):
        if sys.platform != "linux":
            raise ValueError("Worker approvals run on the Linux host.")
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
            raise ValueError("Use the full ID of a locally available Linux image.")
        if not PurePosixPath(executable).is_absolute() or executable == "/":
            raise ValueError("Use an absolute executable path inside the image.")
        return cls(os.geteuid(), image, executable, tuple(arguments))

    def fingerprint(self):
        return digest(json.dumps(asdict(self), sort_keys=True, separators=(",", ":")))


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@contextmanager
def approval_store(directory):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("The approval directory must be private and owned by the operator.")

    path = directory / "approvals.sqlite3"
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("The approval database must be a private regular file.")
    finally:
        os.close(fd)
    with closing(sqlite3.connect(path)) as database:
        database.execute("PRAGMA synchronous = FULL")
        database.execute(
            "CREATE TABLE IF NOT EXISTS approvals ("
            "token_hash TEXT PRIMARY KEY, request_hash TEXT NOT NULL, expires_at REAL NOT NULL)"
        )
        with database:
            yield database


def issue_approval(directory, request):
    token = secrets.token_urlsafe(32)
    with approval_store(directory) as database:
        now = time.time()
        database.execute("DELETE FROM approvals WHERE expires_at <= ?", (now,))
        database.execute(
            "INSERT INTO approvals VALUES (?, ?, ?)",
            (digest(token), request.fingerprint(), now + APPROVAL_TTL),
        )
    return token


def consume_approval(directory, request, token):
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
        return False
    with approval_store(directory) as database:
        # Take the write lock before reading the clock, so expiry includes time
        # spent waiting for another launcher to commit.
        database.execute("BEGIN IMMEDIATE")
        consumed = database.execute(
            "DELETE FROM approvals WHERE token_hash = ? AND request_hash = ? AND expires_at > ?",
            (digest(token), request.fingerprint(), time.time()),
        ).rowcount
    return consumed == 1
