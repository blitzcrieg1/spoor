"""Regression tests for the Linux worker approval store."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from worker_approval import APPROVAL_TTL, WorkerRequest, consume_approval, issue_approval


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

    def test_approval_expires(self):
        with patch("worker_approval.time.time", return_value=1000):
            token = issue_approval(self.directory, self.request)
        with patch("worker_approval.time.time", return_value=1000 + APPROVAL_TTL):
            self.assertFalse(consume_approval(self.directory, self.request, token))

    def test_only_one_concurrent_consumer_succeeds(self):
        token = issue_approval(self.directory, self.request)
        with ThreadPoolExecutor(max_workers=2) as pool:
            attempts = [
                pool.submit(consume_approval, self.directory, self.request, token)
                for _ in range(2)
            ]
            self.assertEqual(sum(attempt.result() for attempt in attempts), 1)

    def test_shared_directory_is_rejected(self):
        self.directory.mkdir()
        self.directory.chmod(0o775)
        with self.assertRaisesRegex(ValueError, "private"):
            issue_approval(self.directory, self.request)


if __name__ == "__main__":
    unittest.main()
