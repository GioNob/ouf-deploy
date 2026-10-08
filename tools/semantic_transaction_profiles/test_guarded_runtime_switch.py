"""Real private-file/lock tests only; no target authority or Docker activation."""
import fcntl
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE));sys.path.insert(0,str(HERE.parent/'semantic_frame_compiler'))
sys.path.insert(0,str(HERE.parent/'semantic_cohort_admission/cohort-draft'))
from guarded_runtime_switch import custody, switch_existing_wrapper, wrapper_bytes
from authenticate_provider_transaction import TransactionDenied
from assemble_provider_profiles import digest


class GuardedSwitchTest(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(),0)
        self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TRANSACTION_TEST_ROOT',Path.cwd()),prefix='switch-test-')
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.evidence=self.root/'transaction';self.evidence.mkdir(mode=0o700)
        self.wrapper=self.root/'wrapper';self.old=b'#!/bin/sh\nexit 99\n';self.write(self.wrapper,self.old,0o755)
        self.lock=self.root/'native.lock';self.write(self.lock,b'',0o600)
        self.lock_identity=custody(self.lock,0o600)[1]
        self.new=wrapper_bytes('/usr/bin/python3.13',self.root/'source',self.root/'proposal.json')
        self.phases=[]

    def write(self,path,raw,mode):path.write_bytes(raw);path.chmod(mode)

    def verify(self,fd,phase):
        self.assertEqual(os.fstat(fd).st_ino,self.lock_identity[1]);self.phases.append(phase)

    def switch(self,verify=None,expected=None):
        return switch_existing_wrapper(self.wrapper,expected or digest(self.old),self.new,self.evidence,
                                       self.lock,self.lock_identity,verify or self.verify)

    def test_atomic_single_wrapper_switch_retains_prior_bytes(self):
        result=self.switch();self.assertEqual(result['status'],'WRAPPER_SWITCHED')
        self.assertEqual(self.phases,['BEFORE_CLAIM','BEFORE_RENAME','AFTER_RENAME'])
        self.assertEqual(custody(self.wrapper,0o755)[0],self.new)
        self.assertEqual((self.evidence/'prior-runtime-wrapper.sh').read_bytes(),self.old)
        self.assertEqual(result['containerLifecycleOperations'],0)

    def test_wrong_expected_hash_has_no_claim_or_write(self):
        with self.assertRaisesRegex(TransactionDenied,'INSTALLED_WRAPPER_HASH_DRIFT'):self.switch(expected='0'*64)
        self.assertEqual(self.wrapper.read_bytes(),self.old);self.assertEqual(list(self.evidence.iterdir()),[])

    def test_native_guard_lock_conflict_denies_before_claim(self):
        fd=os.open(self.lock,os.O_RDWR)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(TransactionDenied):self.switch()
        finally:os.close(fd)
        self.assertEqual(list(self.evidence.iterdir()),[]);self.assertEqual(self.wrapper.read_bytes(),self.old)

    def test_authority_failure_before_rename_retains_claim_and_refuses_replay(self):
        def verify(fd,phase):
            self.verify(fd,phase)
            if phase=='BEFORE_RENAME':raise TransactionDenied('AUTHENTICATE_TARGET','TARGET_MANDATE_EXPIRED')
        with self.assertRaisesRegex(TransactionDenied,'TARGET_MANDATE_EXPIRED'):self.switch(verify)
        self.assertEqual(self.wrapper.read_bytes(),self.old)
        denial=json.loads((self.evidence/'runtime-switch-denial.json').read_bytes())
        self.assertTrue(denial['doNotRerunApply']);self.assertFalse(denial['wrapperReplaced'])
        with self.assertRaisesRegex(TransactionDenied,'EXISTING_RUNTIME_SWITCH_CLAIM_PRESERVED'):self.switch()

    def test_readback_failure_preserves_switched_state_without_automatic_rollback(self):
        def verify(fd,phase):
            if phase=='AFTER_RENAME':raise TransactionDenied('OBSERVE_TARGET','TARGET_GENERATION_DRIFT')
        with self.assertRaisesRegex(TransactionDenied,'TARGET_GENERATION_DRIFT'):self.switch(verify)
        denial=json.loads((self.evidence/'runtime-switch-denial.json').read_bytes())
        self.assertTrue(denial['wrapperReplaced']);self.assertTrue(denial['doNotRerunApply'])
        self.assertEqual(self.wrapper.read_bytes(),self.new)
        self.assertFalse((self.evidence/'runtime-switch-receipt.json').exists())

    def test_changed_native_lock_inode_is_rejected_before_rename(self):
        def verify(fd,phase):
            if phase=='BEFORE_RENAME':
                replacement=self.root/'other.lock';self.write(replacement,b'',0o600);os.replace(replacement,self.lock)
        with self.assertRaisesRegex(TransactionDenied,'NATIVE_GUARD_LOCK_REPLACED'):self.switch(verify)
        self.assertEqual(self.wrapper.read_bytes(),self.old)

    def test_shell_path_injection_refused(self):
        with self.assertRaisesRegex(TransactionDenied,'CLOSED_WRAPPER_PATH_REQUIRED'):
            wrapper_bytes('/usr/bin/python3.13',self.root/'source',str(self.root)+'/proposal;evil.json')

    def test_false_verifier_result_cannot_be_silently_accepted(self):
        with self.assertRaisesRegex(TransactionDenied,'LOCKED_VERIFIER_MUST_RAISE_ON_DENIAL'):
            self.switch(lambda fd,phase:False)
        self.assertEqual(self.wrapper.read_bytes(),self.old);self.assertEqual(list(self.evidence.iterdir()),[])


if __name__=='__main__':unittest.main()
