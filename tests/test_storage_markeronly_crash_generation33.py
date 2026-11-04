import copy
import importlib.util
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('marker33',ROOT/'scripts/storage-generation33-markeronly-crash.py')
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)

class MarkerPhaseTests(unittest.TestCase):
    def fixture(self):
        first={'.dat':{'bytes':5000,'inode':1},'.idx':{'bytes':48,'inode':2},
               '.cpd':{'bytes':1000,'inode':3},'.cpx':{'bytes':16,'inode':4},'.cpc':{'bytes':0,'inode':5}}
        mixed={'.dat':copy.deepcopy(first['.cpd']),'.idx':copy.deepcopy(first['.idx']),
               '.cpx':copy.deepcopy(first['.cpx']),'.cpc':copy.deepcopy(first['.cpc'])}
        frozen={'.dat':copy.deepcopy(first['.cpd']),'.idx':copy.deepcopy(first['.cpx']),'.cpc':copy.deepcopy(first['.cpc'])}
        return first,mixed,frozen,{'12':'t','13':'t'},{'operation':'exit','returnValue':0,'isError':False},[{'kind':'directory','returnValue':0}]
    def test_exact_markeronly_state_qualifies(self):c.validate_phase(*self.fixture())
    def test_marker_must_still_exist(self):
        args=self.fixture();del args[2]['.cpc']
        with self.assertRaisesRegex(ValueError,'ONLY_MARKER'):c.validate_phase(*args)
    def test_no_temporary_copy_may_remain(self):
        for ext in ('.cpd','.cpx'):
            args=self.fixture();args[2][ext]=args[0][ext]
            with self.assertRaisesRegex(ValueError,'ONLY_MARKER'):c.validate_phase(*args)
    def test_old_or_modified_dat_rejected(self):
        args=self.fixture();args[2]['.dat']=args[0]['.dat']
        with self.assertRaisesRegex(ValueError,'EXACT_BOTH'):c.validate_phase(*args)
    def test_old_index_rejected(self):
        args=self.fixture();args[2]['.idx']=args[0]['.idx']
        with self.assertRaisesRegex(ValueError,'EXACT_BOTH'):c.validate_phase(*args)
    def test_copy_to_new_inode_does_not_qualify(self):
        for ext in ('.dat','.idx'):
            args=self.fixture();args[2][ext]['inode']+=20
            with self.assertRaisesRegex(ValueError,'EXACT_BOTH'):c.validate_phase(*args)
    def test_marker_identity_and_empty_contents_preserved(self):
        for key in ('inode','bytes'):
            args=self.fixture();args[2]['.cpc'][key]+=1
            with self.assertRaisesRegex(ValueError,'SAME_MARKER'):c.validate_phase(*args)
    def test_missing_failed_or_wrong_order_fsync_rejected(self):
        for syncs in ([],[{'kind':'marker','returnValue':0}],[{'kind':'directory','returnValue':-5}],
                      [{'kind':'directory','returnValue':0}]*2):
            args=self.fixture()
            with self.assertRaisesRegex(ValueError,'POST_RENAME_DIRECTORY'):c.validate_phase(*args[:5],syncs)
    def test_second_syscall_must_exit_successfully(self):
        for result in ({},{'operation':'entry','returnValue':0},{'operation':'exit','returnValue':-5,'isError':True}):
            args=self.fixture()
            with self.assertRaisesRegex(ValueError,'SECOND_RENAME_SUCCESS'):c.validate_phase(*args[:4],result,args[5])
    def test_all_threads_must_be_stopped(self):
        args=self.fixture();args[3]['13']='R'
        with self.assertRaisesRegex(ValueError,'THREADS_STOPPED'):c.validate_phase(*args)
    def test_recovery_only_removes_marker_without_replacing_pair(self):
        frozen=self.fixture()[2];valid={k:v for k,v in frozen.items() if k!='.cpc'}
        c.validate_pair(frozen,valid)
        with self.assertRaisesRegex(ValueError,'REMOVES_MARKER'):c.validate_pair(frozen,frozen)
        for ext in valid:
            bad=copy.deepcopy(valid);bad[ext]['inode']+=1
            with self.assertRaisesRegex(ValueError,'PAIR_UNCHANGED'):c.validate_pair(frozen,bad)
    def test_mode_is_exclusive_before_environment_access(self):
        spec=importlib.util.spec_from_file_location('marker_lab33',ROOT/'scripts/run-storage-generation33-lateral-isolation.py')
        lab=importlib.util.module_from_spec(spec);spec.loader.exec_module(lab)
        for flag in ('crash_volume','crash_filer','crash_master','crash_all','interrupt_stream','cleanup_stream','compact_stream',
                     'restart_compact','relocate_live','crash_compact','crash_commit','crash_rename'):
            with self.assertRaisesRegex(ValueError,'ONE_CRASH_ROLE'):lab.run(None,None,None,None,crash_marker=True,**{flag:True})

@unittest.skipUnless(platform.system()=='Linux' and platform.machine()=='x86_64','Linux ptrace mechanics required')
class NativeMarkerOnlyTests(unittest.TestCase):
    def test_execute_both_renames_sync_and_hold_unlink_until_kill(self):
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
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
    os.unlink(stem.with_suffix('.cpc'))
    (root/'unexpected-marker-unlink').write_text('failed')
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
                c.inter.commit.validate_phase(before,first_files,first['threadStates'],first['successfulSyncs'])
                second=observer.observe_second(first);mixed=c.pre.files(root,target)
                c.inter.validate_mixed(before,first_files,mixed,second['threadStates'],second['firstRenameResult'])
                phase=observer.observe_marker(second);frozen=c.pre.files(root,target)
                c.validate_phase(first_files,mixed,frozen,phase['threadStates'],phase['secondRenameResult'],phase['postRenameDirectorySyncs'])
                self.assertTrue(phase['cloneEvents']);self.assertTrue(phase['path'].endswith('.cpc'))
                self.assertFalse((root/'unexpected-marker-unlink').exists())
                os.kill(child.pid,signal.SIGKILL);observer.wait_for_kill(timeout=10)
                self.assertEqual(c.pre.files(root,target),frozen)
                self.assertFalse((root/'unexpected-marker-unlink').exists())
            finally:
                try:os.kill(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                if observer and observer.tids:
                    try:observer.wait_for_kill(timeout=5)
                    except (ValueError,ChildProcessError):pass
                child.wait(timeout=10)

if __name__=='__main__':unittest.main()
