"""Regression tests for the Linux worker approval store."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
from subprocess import CompletedProcess
import tempfile
import unittest
from unittest.mock import patch

from run_isolated_worker import run_worker
from worker_approval import (
    APPROVAL_TTL, WorkerRequest, consume_approval, digest, issue_approval, read_rejections,
)


class WorkerApprovalTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name) / "approvals"
        self.request = WorkerRequest.from_cli("sha256:" + "0" * 64, "/bin/echo", ["hello"])

    def test_approval_is_bound_to_every_request_field(self):
        token = issue_approval(self.directory, self.request)
        changes = {
            "caller_uid": self.request.caller_uid + 1,
            "image": "sha256:" + "1" * 64,
            "executable": "/bin/false",
            "arguments": ("different",),
            "isolation_profile": (),
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                changed = replace(self.request, **{field: value})
                self.assertFalse(consume_approval(self.directory, changed, token))
        self.assertTrue(consume_approval(self.directory, self.request, token))
        self.assertFalse(consume_approval(self.directory, self.request, token))
        records = list(read_rejections(self.directory))
        self.assertEqual(
            [record["reason"] for record in records],
            ["approval_request_mismatch"] * len(changes) + ["approval_reused"],
        )
        for (field, value), record in zip(changes.items(), records):
            self.assertEqual(
                record["request_fingerprint"], replace(self.request, **{field: value}).fingerprint(),
            )

    def test_approval_expires(self):
        with patch("worker_approval.time.time", return_value=1000):
            token = issue_approval(self.directory, self.request)
        with patch("worker_approval.time.time", return_value=1000 + APPROVAL_TTL):
            issue_approval(self.directory, self.request)
            self.assertFalse(consume_approval(self.directory, self.request, token))
        record, = read_rejections(self.directory)
        self.assertEqual(record["reason"], "approval_expired")
        self.assertEqual(record["timestamp_utc"], "1970-01-01T00:21:40.000+00:00")

    def test_only_one_concurrent_consumer_succeeds(self):
        token = issue_approval(self.directory, self.request)
        with ThreadPoolExecutor(max_workers=2) as pool:
            attempts = [
                pool.submit(consume_approval, self.directory, self.request, token)
                for _ in range(2)
            ]
            self.assertEqual(sum(attempt.result() for attempt in attempts), 1)
        record, = read_rejections(self.directory)
        self.assertEqual(record["reason"], "approval_reused")

    def test_replay_records_one_rejection_and_never_launches_a_container(self):
        token = issue_approval(self.directory, self.request)
        self.assertTrue(consume_approval(self.directory, self.request, token))
        shim = self.directory.parent / "shim"
        shim.touch()
        daemon = {
            "OSType": "linux", "PidsLimit": True, "CpuCfsQuota": True,
            "MemoryLimit": True, "SwapLimit": True, "SecurityOptions": ["name=seccomp"],
        }
        image = {"Id": self.request.image, "Os": "linux", "Config": {}}
        with (
            patch("run_isolated_worker.shutil.which", return_value="/usr/bin/docker"),
            patch("run_isolated_worker.subprocess.run", side_effect=[
                CompletedProcess([], 0, stdout=json.dumps(daemon)),
                CompletedProcess([], 0, stdout=json.dumps(image)),
            ]) as commands,
        ):
            with self.assertRaisesRegex(ValueError, "used"):
                run_worker(shim, self.request, self.directory, token)
        self.assertEqual([call.args[0][1] for call in commands.call_args_list], ["info", "image"])
        record, = read_rejections(self.directory)
        self.assertEqual(set(record), {"type", "timestamp_utc", "request_fingerprint", "reason"})
        self.assertEqual(record["type"], "worker_approval_rejected")
        self.assertEqual(record["request_fingerprint"], self.request.fingerprint())
        self.assertEqual(record["reason"], "approval_reused")
        exported = json.dumps(record)
        self.assertNotIn(token, exported)
        self.assertNotIn(self.request.arguments[0], exported)

    def test_missing_malformed_and_unknown_approvals_have_distinct_reasons(self):
        for token in ("", "malformed", "z" * 43):
            self.assertFalse(consume_approval(self.directory, self.request, token))
        self.assertEqual(
            [record["reason"] for record in read_rejections(self.directory)],
            ["approval_missing", "approval_invalid", "approval_unknown"],
        )

    def test_upgrade_preserves_approvals_from_the_previous_store(self):
        token = "x" * 43
        self.directory.mkdir(mode=0o700)
        path = self.directory / "approvals.sqlite3"
        with closing(sqlite3.connect(path)) as database, database:
            database.execute(
                "CREATE TABLE approvals ("
                "token_hash TEXT PRIMARY KEY, request_hash TEXT NOT NULL, expires_at REAL NOT NULL)"
            )
            database.execute("INSERT INTO approvals VALUES (?, ?, ?)",
                             (digest(token), self.request.fingerprint(), 1200))
        path.chmod(0o600)
        with patch("worker_approval.time.time", return_value=1000):
            self.assertTrue(consume_approval(self.directory, self.request, token))
            self.assertFalse(consume_approval(self.directory, self.request, token))
        record, = read_rejections(self.directory)
        self.assertEqual(record["reason"], "approval_reused")

    def test_shared_directory_is_rejected(self):
        self.directory.mkdir()
        self.directory.chmod(0o775)
        with self.assertRaisesRegex(ValueError, "private"):
            issue_approval(self.directory, self.request)


if __name__ == "__main__":
    unittest.main()
