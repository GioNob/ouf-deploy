"""Actual sealed bytes above512KiB, bounds, duplicate keys and custody drift."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_chatbot_cohort_containers as bootstrap
from tools.chatbot_file_cohort import action_process as p
from tools.chatbot_file_cohort import entry


class SnapshotReader(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(dir=bootstrap.ROOT,prefix='snapshot-reader-')
        self.addCleanup(temp.cleanup);self.root=Path(temp.name);self.root.chmod(0o700)
        self.path=self.root/'child-bundle.json'

    def write(self,raw):self.path.write_bytes(raw);self.path.chmod(0o600)

    def test_complete_artifact_bound_is_not_the_smaller_iam_snapshot_protocol(self):
        value={'schema':'synthetic-closed-source-bundle','body':'x'*700000}
        raw=p.encoded(value);self.write(raw)
        with p.protected_directory(self.root)as directory:
            with self.assertRaisesRegex(p.evidence.CandidateDenied,'PRIVATE_SNAPSHOT_CUSTODY_UNPROVEN'):
                p.evidence.read_member(directory,self.path.name)
        decoded,binding=p.observed_private_json(self.path,8388608)
        self.assertEqual(decoded,value);self.assertEqual(binding,{'path':str(self.path),'sha256':hashlib.sha256(raw).hexdigest()})
        self.assertEqual(self.path.read_bytes(),raw)

    def test_caller_exact_limit_is_enforced_before_read_and_cannot_be_unbounded(self):
        raw=p.encoded({'body':'x'*700000});self.write(raw)
        self.assertEqual(p.observed_private_json(self.path,len(raw))[0]['body'],'x'*700000)
        for limit in (len(raw)-1,0,True,8388609):
            with (self.subTest(limit=limit),patch.object(p.os,'read',side_effect=AssertionError('MUST_NOT_READ')),
                self.assertRaisesRegex(Exception,'BOUNDED_PREVIOUS_ACTION_RECORD_REQUIRED')):
                p.observed_private_json(self.path,limit)

    def test_mode_symlink_and_hardlink_are_rejected_before_body_read(self):
        self.write(b'{"private":"not printed"}');self.path.chmod(0o644)
        with self.assertRaisesRegex(Exception,'PRIVATE_SNAPSHOT_CUSTODY_UNPROVEN'):p.observed_private_json(self.path,8388608)
        self.path.chmod(0o600);linked=self.root/'linked.json';os.link(self.path,linked)
        with self.assertRaisesRegex(Exception,'PRIVATE_SNAPSHOT_CUSTODY_UNPROVEN'):p.observed_private_json(self.path,8388608)
        linked.unlink();self.path.rename(self.root/'original.json');self.path.symlink_to(self.root/'original.json')
        with self.assertRaisesRegex(Exception,'PRIVATE_SNAPSHOT_CUSTODY_UNPROVEN'):p.observed_private_json(self.path,8388608)

    def test_same_bytes_in_replaced_inode_are_not_adopted_mid_read(self):
        raw=p.encoded({'body':'x'*700000});self.write(raw)
        replacement=self.root/'replacement.json';replacement.write_bytes(raw);replacement.chmod(0o600)
        native_read=os.read;swapped=False
        def replace_after_read(fd,count):
            nonlocal swapped
            value=native_read(fd,count)
            if not swapped:os.replace(replacement,self.path);swapped=True
            return value
        with patch.object(p.os,'read',side_effect=replace_after_read),self.assertRaisesRegex(Exception,'PREVIOUS_ACTION_READ_DRIFT'):
            p.observed_private_json(self.path,8388608)

    def test_duplicate_keys_remain_denied_in_large_json(self):
        self.write(b'{"same":1,"same":2,"body":"'+b'x'*700000+b'"}')
        with self.assertRaisesRegex(Exception,'DUPLICATE_SNAPSHOT_KEY'):p.observed_private_json(self.path,8388608)

    def test_public_parent_keeps_the_same_private_member_guards(self):
        self.write(p.encoded({'body':'x'*700000}));self.root.chmod(0o755)
        with patch.object(p.evidence,'PARENT',self.root):
            self.assertEqual(len(p.observed_private_json(self.path,8388608)[0]['body']),700000)
            self.path.chmod(0o644)
            with self.assertRaisesRegex(Exception,'PRIVATE_SNAPSHOT_CUSTODY_UNPROVEN'):p.observed_private_json(self.path,8388608)

    def test_failure_diagnostic_contains_code_locations_without_private_text(self):
        def fail():raise RuntimeError('DO_NOT_PRINT_SECRET_OR_PATH')
        try:fail()
        except Exception as error:diagnostic=entry.safe_failure_locations(error)
        self.assertNotIn('DO_NOT_PRINT',str(diagnostic));self.assertFalse(diagnostic['messagesPrinted'])
        self.assertFalse(diagnostic['pathsPrinted']);self.assertFalse(diagnostic['localValuesPrinted'])


if __name__=='__main__':unittest.main()
