import copy
import importlib.util
import os
from pathlib import Path
import platform
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('inter33',ROOT/'scripts/storage-generation33-interrename-crash.py')
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)

class MixedPhaseTests(unittest.TestCase):
    def fixture(self):
        before={'.dat':{'bytes':5243072,'sha256':'old','inode':1},'.idx':{'bytes':48,'sha256':'old-index','inode':2}}
        first={**copy.deepcopy(before),'.cpd':{'bytes':1048688,'sha256':'new','inode':3},
               '.cpx':{'bytes':16,'sha256':'new-index','inode':4},'.cpc':{'bytes':0,'inode':5}}
        frozen={'.dat':copy.deepcopy(first['.cpd']),'.idx':copy.deepcopy(before['.idx']),
                '.cpx':copy.deepcopy(first['.cpx']),'.cpc':copy.deepcopy(first['.cpc'])}
        return before,first,frozen,{'12':'t','13':'t'},{'operation':'exit','returnValue':0,'isError':False}

    def test_only_dat_native_rename_qualifies(self):c.validate_mixed(*self.fixture())

    def test_missing_marker_precommit_or_both_renamed_rejected(self):
        for change in ('marker','cpd','cpx'):
            args=self.fixture()
            if change=='marker':del args[2]['.cpc']
            elif change=='cpd':args[2]['.cpd']=args[1]['.cpd']
            else:del args[2]['.cpx']
            with self.assertRaisesRegex(ValueError,'FILE_SET'):c.validate_mixed(*args)

    def test_old_dat_or_copy_to_different_inode_rejected(self):
        for change in ('old','inode','bytes'):
            args=self.fixture()
            if change=='old':args[2]['.dat']=args[0]['.dat']
            else:args[2]['.dat'][change]+=1
            with self.assertRaisesRegex(ValueError,'DAT_INODE'):c.validate_mixed(*args)

    def test_already_promoted_index_rejected(self):
        args=self.fixture();args[2]['.idx']=args[1]['.cpx']
        with self.assertRaisesRegex(ValueError,'OLD_IDX'):c.validate_mixed(*args)

    def test_changed_pending_index_or_marker_rejected(self):
        for ext in ('.cpx','.cpc'):
            args=self.fixture();args[2][ext]['inode']+=1
            with self.assertRaisesRegex(ValueError,'PENDING_INDEX_AND_MARKER'):c.validate_mixed(*args)

    def test_unsuccessful_first_rename_cannot_qualify(self):
        for result in ({},{'operation':'entry','returnValue':0},{'operation':'exit','returnValue':-5,'isError':True}):
            args=self.fixture()
            with self.assertRaisesRegex(ValueError,'SUCCESSFUL_EXIT'):c.validate_mixed(*args[:4],result)

    def test_partial_stop_rejected(self):
        args=self.fixture();args[3]['13']='R'
        with self.assertRaisesRegex(ValueError,'THREADS_STOPPED'):c.validate_mixed(*args)

    def test_recovery_preserves_new_dat_and_promotes_only_pending_index(self):
        mixed=self.fixture()[2];valid={'.dat':mixed['.dat'],'.idx':mixed['.cpx']};c.validate_pair(mixed,valid)
        for ext in ('.dat','.idx'):
            bad=copy.deepcopy(valid);bad[ext]['inode']+=1
            with self.assertRaisesRegex(ValueError,'EXACT_PENDING'):c.validate_pair(mixed,bad)
        with self.assertRaisesRegex(ValueError,'REMOVES'):c.validate_pair(mixed,{**valid,'.cpc':mixed['.cpc']})

    def test_unselected_raw_storage_cannot_change(self):
        before={'target':{'.dat':1},'other':{'.dat':2,'.idx':3}};after=copy.deepcopy(before)
        after['target']['.dat']=4;c.validate_unselected(before,after,'target')
        after['other']['.idx']=4
        with self.assertRaisesRegex(ValueError,'UNSELECTED'):c.validate_unselected(before,after,'target')

    def witness(self):
        witness=c.relocation.identity({'volumeId':'3','datFile':'ouf-identity-fixture_3.dat'})
        body=c.relocation.body();size=len(body)+10
        data=b'\x03'+b'\0'*7+struct.pack('>IQiI',int(witness['cookieHex'],16),witness['needleId'],size,len(body))+body
        old=struct.pack('>QIi',witness['needleId'],4194392//8,size)
        pending=struct.pack('>QIi',witness['needleId'],1,size)
        return old,pending,data,witness

    def test_old_offset_is_invalid_but_pending_index_binds_real_body(self):
        result=c.mixed_witness(*self.witness());self.assertTrue(result['oldIndexInvalidForNewDat'])
        self.assertEqual(result['pendingNeedleOffset'],8)
        old,pending,data,witness=self.witness()
        with self.assertRaisesRegex(ValueError,'OUTSIDE'):c.mixed_witness(pending,pending,data,witness)

    def test_wrong_pending_index_or_body_is_rejected(self):
        old,pending,data,witness=self.witness()
        with self.assertRaisesRegex(ValueError,'RELOCATES'):c.mixed_witness(old,old,data,witness)
        with self.assertRaisesRegex(ValueError,'EXACT_WITNESS_BODY'):c.mixed_witness(old,pending,data[:-1]+bytes([data[-1]^1]),witness)

    def test_mode_is_exclusive_before_any_environment_action(self):
        spec=importlib.util.spec_from_file_location('inter_lab33',ROOT/'scripts/run-storage-generation33-lateral-isolation.py')
        lab=importlib.util.module_from_spec(spec);spec.loader.exec_module(lab)
        for flag in ('crash_volume','crash_filer','crash_master','crash_all','interrupt_stream','cleanup_stream','compact_stream',
                     'restart_compact','relocate_live','crash_compact','crash_commit'):
            with self.assertRaisesRegex(ValueError,'ONE_CRASH_ROLE'):lab.run(None,None,None,None,crash_rename=True,**{flag:True})

@unittest.skipUnless(platform.system()=='Linux' and platform.machine()=='x86_64','Linux ptrace mechanics required')
class NativeInterRenameTests(unittest.TestCase):
    def test_execute_first_real_rename_and_hold_second_until_kill(self):
        code='''
import os,pathlib,sys,threading,time
root=pathlib.Path(sys.argv[1]);stem=root/'ouf-identity-fixture_3'
threading.Thread(target=lambda:time.sleep(60),daemon=True).start()
(root/'ready').write_text('ready')
while not (root/'go').exists():time.sleep(.002)
def commit():
    stem.with_suffix('.cpd').write_bytes(b'compacted-data-contents')
    stem.with_suffix('.cpx').write_bytes(b'compacted-index!')
    fd=os.open(stem.with_suffix('.cpc'),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.fsync(fd);os.close(fd)
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
    os.rename(stem.with_suffix('.cpd'),stem.with_suffix('.dat'))
    os.rename(stem.with_suffix('.cpx'),stem.with_suffix('.idx'))
    (root/'unexpected-second-rename').write_text('failed')
threading.Thread(target=commit).start();time.sleep(60)
'''
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);target='ouf-identity-fixture_3.dat'
            (root/target).write_bytes(b'old-data'*100);(root/target).with_suffix('.idx').write_bytes(b'old-index')
            before=c.pre.files(root,target);child=subprocess.Popen([sys.executable,'-I','-B','-S','-c',code,temp]);observer=None
            try:
                deadline=time.monotonic()+10
                while not (root/'ready').exists():
                    self.assertLess(time.monotonic(),deadline);self.assertIsNone(child.poll());time.sleep(.01)
                observer=c.Observer(child.pid,root,target,namespace_root=temp);observer.attach();(root/'go').write_text('go')
                first=observer.observe(timeout=15);first_files=c.pre.files(root,target)
                c.commit.validate_phase(before,first_files,first['threadStates'],first['successfulSyncs'])
                second=observer.observe_second(first);mixed=c.pre.files(root,target)
                c.validate_mixed(before,first_files,mixed,second['threadStates'],second['firstRenameResult'])
                self.assertTrue(second['cloneEvents']);self.assertTrue(second['oldPath'].endswith('.cpx'))
                self.assertFalse((root/'unexpected-second-rename').exists())
                os.kill(child.pid,signal.SIGKILL);observer.wait_for_kill(timeout=10)
                self.assertEqual(c.pre.files(root,target),mixed)
                self.assertFalse((root/'unexpected-second-rename').exists())
            finally:
                try:os.kill(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                if observer and observer.tids:
                    try:observer.wait_for_kill(timeout=5)
                    except (ValueError,ChildProcessError):pass
                child.wait(timeout=10)

if __name__=='__main__':unittest.main()
