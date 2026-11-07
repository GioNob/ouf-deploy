"""Offline guards for the separate synthetic dump/restore laboratory."""
from pathlib import Path
from subprocess import CompletedProcess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import run_storage_postgres_logical_restore as restore


class LogicalRestoreContractTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.archive = self.root / "catalog.dump"
        self.archive.write_bytes(b"PGDMPtest-fixture")
        self.checksum = restore.archive_digest(self.archive)
        self.destination = SimpleNamespace(
            socket=self.root / "private-socket",
            binary=lambda name: self.root / name,
        )

    def test_wrong_archive_identity_is_denied_before_invoking_restore(self):
        self.archive.write_bytes(b"PGDMPdifferent-catalog")
        with patch.object(restore.native, "run") as command:
            with self.assertRaisesRegex(RuntimeError, "^POSTGRES_DUMP_SHA256_MISMATCH$"):
                restore.restore_archive(self.destination, self.archive, self.checksum, self.root)
        command.assert_not_called()

    def test_destination_copy_changed_during_restore_cannot_pass(self):
        def mutate(argv, *, timeout):
            self.archive.write_bytes(b"PGDMPmodified-during-restore")
            return CompletedProcess(argv, 0, b"", b"")

        with patch.object(restore.native, "run", side_effect=mutate):
            with self.assertRaisesRegex(RuntimeError, "^POSTGRES_DUMP_CHANGED_DURING_RESTORE$"):
                restore.restore_archive(self.destination, self.archive, self.checksum, self.root)

    def test_restore_uses_private_destination_socket_and_exact_archive(self):
        with patch.object(restore.native, "run", return_value=CompletedProcess([], 0, b"", b"")) as command:
            restore.restore_archive(self.destination, self.archive, self.checksum, self.root)
        argv = command.call_args.args[0]
        self.assertIn("--host=" + str(self.destination.socket), argv)
        self.assertIn("--single-transaction", argv)
        self.assertIn("--exit-on-error", argv)
        self.assertEqual(argv[-1], str(self.archive))

    def test_non_custom_or_oversized_archive_is_rejected(self):
        self.archive.write_bytes(b"-- plain SQL")
        with self.assertRaisesRegex(RuntimeError, "^POSTGRES_CUSTOM_DUMP_REQUIRED$"):
            restore.archive_digest(self.archive)
        with self.archive.open("ab") as stream:
            stream.truncate(restore.DUMP_LIMIT + 1)
        with self.assertRaisesRegex(RuntimeError, "^BOUNDED_REGULAR_POSTGRES_DUMP_REQUIRED$"):
            restore.archive_digest(self.archive)
