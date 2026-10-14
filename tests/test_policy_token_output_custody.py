"""Native roots/signatures, durable fork crashes and group custody; no target."""
import fcntl
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tests')]
import test_policy_token_migration_root_custody as fixtures
roots=fixtures.roots
binding=roots.binding

class OutputCustodyTest(unittest.TestCase):
    def setUp(self):
        self.r=fixtures.RootCustodyTest();self.r.setUp();self.addCleanup(self.r.doCleanups)
        operation=self.r.action();row=operation.run()
        self.root_hash=binding.sha(binding.encoded(row));self.root_source=operation.scope['sourceClosureHash']
        self.root_ledger=self.r.f.f.root/operation.name;self.root_raw=self.root_ledger.read_bytes()
        self.scope=self.make().scope
        self.sign()
    def make(self):
        return roots.TokenOutputCustody(self.r.f.f.gate(),self.r.f.f.authority,
            self.r.f.raw,self.root_hash,self.root_source)
    def sign(self,alter=None):
        def change(a):
            a['policyTokenOutputCustody']=self.scope
            if alter:alter(a)
        self.r.f.sign(change)
    def tearDown(self):
        self.assertEqual(self.root_ledger.read_bytes(),self.root_raw)
    def test_one_child_and_restart_preserve_existing_roots_and_output_identity(self):
        before={k:Path(p).stat()for k,p in self.r.paths.items()}
        action=self.make();row=action.run()
        self.assertEqual(row['state'],'OUTPUT_CUSTODIED_NOT_RUNTIME_ACCEPTED')
        child=action.path.stat();self.assertEqual((child.st_uid,child.st_gid,child.st_mode&0o777),(0,10001,0o750))
        self.assertEqual(row['outputIdentity'],{'device':child.st_dev,'inode':child.st_ino})
        for k,path in self.r.paths.items():
            after=Path(path).stat();self.assertEqual((after.st_dev,after.st_ino,after.st_uid,after.st_gid,after.st_mode),
                (before[k].st_dev,before[k].st_ino,0,0,before[k].st_mode))
        with patch.object(roots.os,'mkdir',side_effect=AssertionError('no recreation')):
            self.assertEqual(self.make().run(),row)
    def test_unknown_directory_and_symlink_are_never_adopted(self):
        action=self.make();action.path.mkdir(mode=0o755)
        original=action.path.stat()
        with self.assertRaisesRegex(binding.CandidateDenied,'NO_ADOPTION'):action.run()
        self.assertEqual(action.path.stat(),original)
        action.path.rmdir();action.path.symlink_to(self.r.f.f.root,target_is_directory=True)
        with self.assertRaisesRegex(binding.CandidateDenied,'NO_ADOPTION'):action.run()
        self.assertFalse((self.r.f.f.root/action.name).exists())
    def test_missing_signed_scope_and_revocation_deny_effects(self):
        self.sign(lambda a:a.pop('policyTokenOutputCustody'))
        with self.assertRaisesRegex(binding.CandidateDenied,'SIGNED_TOKEN_OUTPUT'):self.make().run()
        self.sign();self.r.f.f.approval['state']='REVOKED'
        self.r.f.f.write(self.r.f.f.mandate,binding.encoded(self.r.f.f.approval))
        with self.assertRaises(Exception):self.make().run()
        self.assertFalse(Path(self.scope['path']).exists())
    def test_crash_after_mkdir_never_adopts_or_replays(self):
        action=self.make();mkdir=roots.os.mkdir;pid=os.fork()
        if pid==0:
            def crash(*a,**kw):mkdir(*a,**kw);os._exit(0)
            with patch.object(roots.os,'mkdir',side_effect=crash):
                try:action.run()
                except Exception:os._exit(91)
            os._exit(92)
        _,status=os.waitpid(pid,0);self.assertEqual(os.waitstatus_to_exitcode(status),0)
        row=json.loads((self.r.f.f.root/action.name).read_bytes())
        self.assertTrue(row['mkdirAttemptConsumed']);self.assertIsNone(row['outputIdentity'])
        before=action.path.stat()
        with patch.object(roots.os,'mkdir',side_effect=AssertionError('no replay')):
            with self.assertRaisesRegex(binding.CandidateDenied,'NO_MKDIR_REPLAY'):self.make().run()
        self.assertEqual(action.path.stat(),before)
    def test_failed_absent_attempt_is_consumed_and_new_approval_cannot_reset_it(self):
        action=self.make()
        with patch.object(roots.os,'mkdir',side_effect=OSError('failure before effect')):
            with self.assertRaises(OSError):action.run()
        self.assertFalse(action.path.exists());self.sign()
        with patch.object(roots.os,'mkdir',side_effect=AssertionError('no replay')):
            with self.assertRaisesRegex(binding.CandidateDenied,'NO_MKDIR_REPLAY'):self.make().run()
    def test_completed_child_missing_or_metadata_drift_is_not_repaired(self):
        action=self.make();action.run();action.path.chmod(0o700)
        with self.assertRaisesRegex(binding.CandidateDenied,'NO_RECREATE'):self.make().run()
        action.path.chmod(0o750);action.path.rmdir()
        with patch.object(roots.os,'mkdir',side_effect=AssertionError('no recreate')):
            with self.assertRaises(FileNotFoundError):self.make().run()
    def test_parallel_fence_and_durable_deadline(self):
        action=self.make();fd=os.open(self.r.f.f.root/(action.name+'.lock'),os.O_CREAT|os.O_RDWR,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):action.run()
        finally:os.close(fd)
        row=action.run()
        with patch.object(roots,'time',types.SimpleNamespace(monotonic=lambda:row['expiresMonotonic'])):
            with self.assertRaisesRegex(binding.CandidateDenied,'BUDGET_EXPIRED'):self.make().run()
        self.assertEqual(json.loads((self.r.f.f.root/action.name).read_bytes())['expiresMonotonic'],row['expiresMonotonic'])
    def test_parent_permissions_changed_are_denied_without_widening(self):
        self.make().path.parent.chmod(0o750)
        with self.assertRaisesRegex(binding.CandidateDenied,'CUSTODY_DRIFT'):self.make().run()
        self.assertFalse(Path(self.scope['path']).exists())

if __name__=='__main__':unittest.main()
