"""Single-use approvals kept in the trusted Linux operator's local store."""

from contextlib import closing, contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
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
APPROVAL_HISTORY_TTL = 3600


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
        database.executescript("""
            CREATE TABLE IF NOT EXISTS approvals (
                token_hash TEXT PRIMARY KEY, request_hash TEXT NOT NULL, expires_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS used_approvals (
                token_hash TEXT PRIMARY KEY, expires_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS approval_rejections (
                id INTEGER PRIMARY KEY, timestamp_utc TEXT NOT NULL,
                request_fingerprint TEXT NOT NULL, reason TEXT NOT NULL
            );
        """)
        with database:
            yield database


def issue_approval(directory, request):
    token = secrets.token_urlsafe(32)
    with approval_store(directory) as database:
        now = time.time()
        cutoff = now - APPROVAL_HISTORY_TTL
        database.execute("DELETE FROM approvals WHERE expires_at <= ?", (cutoff,))
        database.execute("DELETE FROM used_approvals WHERE expires_at <= ?", (cutoff,))
        database.execute(
            "INSERT INTO approvals VALUES (?, ?, ?)",
            (digest(token), request.fingerprint(), now + APPROVAL_TTL),
        )
    return token


def _consume_token(database, token, request_hash, now):
    if not token:
        return "approval_missing"
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
        return "approval_invalid"
    token_hash = digest(token)
    cutoff = now - APPROVAL_HISTORY_TTL
    approval = database.execute(
        "SELECT request_hash, expires_at FROM approvals WHERE token_hash = ? AND expires_at > ?",
        (token_hash, cutoff),
    ).fetchone()
    if approval is None:
        used = database.execute(
            "SELECT 1 FROM used_approvals WHERE token_hash = ? AND expires_at > ?",
            (token_hash, cutoff),
        ).fetchone()
        return "approval_reused" if used else "approval_unknown"
    approved_request, expires_at = approval
    if expires_at <= now:
        return "approval_expired"
    if approved_request != request_hash:
        return "approval_request_mismatch"

    database.execute("DELETE FROM approvals WHERE token_hash = ?", (token_hash,))
    database.execute("INSERT INTO used_approvals VALUES (?, ?)", (token_hash, expires_at))
    return None


def consume_approval(directory, request, token):
    request_hash = request.fingerprint()
    with approval_store(directory) as database:
        # Take the write lock before reading the clock, so expiry includes time
        # spent waiting for another launcher to commit.
        database.execute("BEGIN IMMEDIATE")
        now = time.time()
        reason = _consume_token(database, token, request_hash, now)
        if reason is not None:
            timestamp = datetime.fromtimestamp(now, timezone.utc).isoformat(timespec="milliseconds")
            database.execute(
                "INSERT INTO approval_rejections (timestamp_utc, request_fingerprint, reason) "
                "VALUES (?, ?, ?)",
                (timestamp, request_hash, reason),
            )
    return reason is None


def read_rejections(directory):
    with approval_store(directory) as database:
        database.row_factory = sqlite3.Row
        rows = database.execute(
            "SELECT 'worker_approval_rejected' AS type, timestamp_utc, request_fingerprint, reason "
            "FROM approval_rejections ORDER BY id"
        )
        yield from map(dict, rows)
