"""Recovery mountinfo reader regressions with explicit simulated procfs reads.

The inherited guard runs against a fixture owner and clock. No kernel mount,
native process binding, token admission or target readiness is qualified here.
"""
import os
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'semantic_application_cutover'))
from tools.semantic_registry_recovery_execution import mount_observation as m
from tools.semantic_registry_recovery_execution.core import RecoveryDenied
from tools.semantic_lease_recovery.bounded_recovery import fingerprint


class Mountinfo(unittest.TestCase):
    def setUp(self):
        # Isolate the read method, retaining its real inherited guard. The
        # constructor's native binding is outside this unit qualification.
        self.reader=m.RecoveryTokenMountObservation.__new__(m.RecoveryTokenMountObservation)
        self.reader.expected={'ownerBindingHash':'a'*64}
        self.reader.policy_hash=fingerprint(self.reader.expected)
        self.reader.owner=SimpleNamespace(guard=Mock())
        self.now=0.0
        self.reader.clock=lambda:self.now
        self.reader.deadline=10.0
        self.open=patch.object(m.os,'open',return_value=123).start()
        self.close=patch.object(m.os,'close').start()
        self.addCleanup(patch.stopall)

    def read(self,chunks):
        with patch.object(m.os,'read',side_effect=chunks) as read:
            raw=self.reader.mountinfo(4242)
        self.open.assert_called_once_with('/proc/4242/mountinfo',os.O_RDONLY|os.O_NOFOLLOW)
        self.close.assert_called_once_with(123)
        return raw,read

    def test_short_read_continues_until_eof_and_preserves_late_token_row(self):
        prefix=b'1 0 0:1 / / rw,relatime - overlay overlay rw\n'
        target=b'597 1 0:2 / /run/fixture-token ro,relatime - ext4 fixture rw\n'
        raw,read=self.read([prefix,target[:17],target[17:],b''])
        self.assertEqual(raw,prefix+target)
        self.assertEqual(read.call_count,4)
        self.assertEqual([r.split()[4] for r in raw.splitlines()].count(b'/run/fixture-token'),1)
        self.assertEqual(self.reader.owner.guard.call_count,9)

    def test_exact_byte_limit_requires_positive_size_eof_probe(self):
        raw,read=self.read([b'x'*65536,b'y'*65536,b''])
        self.assertEqual(len(raw),131072)
        self.assertEqual([call.args[1] for call in read.call_args_list],[131073,65537,1])

    def test_one_byte_beyond_limit_fails_without_returning_truncated_table(self):
        with patch.object(m.os,'read',side_effect=[b'x'*131072,b'y']) as read:
            with self.assertRaisesRegex(RecoveryDenied,'BOUNDED_MOUNTINFO_REQUIRED'):
                self.reader.mountinfo(4242)
        self.assertEqual(read.call_count,2)
        self.close.assert_called_once_with(123)

    def test_empty_table_is_returned_only_after_eof_for_inherited_validation(self):
        raw,read=self.read([b''])
        self.assertEqual(raw,b'');self.assertEqual(read.call_count,1)

    def test_deadline_expiring_during_short_read_stops_before_another_read(self):
        def expired(_fd,_size):
            self.now=10.0
            return b'partial'
        with patch.object(m.os,'read',side_effect=expired) as read:
            with self.assertRaisesRegex(ValueError,'MOUNT_OBSERVATION_DEADLINE_OR_POLICY_DRIFT'):
                self.reader.mountinfo(4242)
        self.assertEqual(read.call_count,1)
        self.close.assert_called_once_with(123)

    def test_deadline_expiring_during_eof_probe_does_not_publish_bytes(self):
        def expired(_fd,_size):
            self.now=11.0
            return b''
        with patch.object(m.os,'read',side_effect=expired):
            with self.assertRaisesRegex(ValueError,'MOUNT_OBSERVATION_DEADLINE_OR_POLICY_DRIFT'):
                self.reader.mountinfo(4242)
        self.close.assert_called_once_with(123)

    def test_current_owner_refusal_between_reads_is_not_retried(self):
        self.reader.owner.guard.side_effect=[None,None,RuntimeError('FIXTURE_AUTHORITY_REVOKED')]
        with patch.object(m.os,'read',return_value=b'partial') as read:
            with self.assertRaisesRegex(RuntimeError,'FIXTURE_AUTHORITY_REVOKED'):
                self.reader.mountinfo(4242)
        self.assertEqual(read.call_count,1)
        self.close.assert_called_once_with(123)

    def test_read_failure_closes_fd_and_is_not_retried(self):
        with patch.object(m.os,'read',side_effect=OSError('fixture read failure')) as read:
            with self.assertRaisesRegex(OSError,'fixture read failure'):
                self.reader.mountinfo(4242)
        self.assertEqual(read.call_count,1)
        self.close.assert_called_once_with(123)

    def test_expired_guard_prevents_opening_procfs(self):
        self.now=10.0
        with self.assertRaisesRegex(ValueError,'MOUNT_OBSERVATION_DEADLINE_OR_POLICY_DRIFT'):
            self.reader.mountinfo(4242)
        self.open.assert_not_called();self.close.assert_not_called()


if __name__=='__main__':
    unittest.main()
