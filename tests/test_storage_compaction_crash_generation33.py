import copy
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('crash33',ROOT/'scripts/storage-generation33-compaction-crash.py')
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)

class PhaseTests(unittest.TestCase):
    def fixture(self):
        old={'.dat':{'bytes':6000000,'sha256':'old','inode':1},'.idx':{'bytes':48,'sha256':'index','inode':2}}
        frozen=copy.deepcopy(old);frozen['.cpd']={'bytes':1048600,'sha256':'copy','inode':3}
        return old,frozen

    def test_precommit_copy_with_old_pair_and_all_threads_stopped(self):
        old,frozen=self.fixture();c.validate_phase(old,frozen,{'1':'T','2':'T'})

    def test_commit_marker_including_empty_marker_is_not_precommit(self):
        old,frozen=self.fixture();frozen['.cpc']={'bytes':0}
        with self.assertRaisesRegex(ValueError,'MARKER_ABSENT'):c.validate_phase(old,frozen,{'1':'T'})

    def test_rename_even_to_identical_bytes_is_not_precommit(self):
        for ext in ('.dat','.idx'):
            old,frozen=self.fixture();frozen[ext]['inode']=99
            with self.assertRaisesRegex(ValueError,'NO_LIVE'):c.validate_phase(old,frozen,{'1':'T'})

    def test_changed_original_pair_is_rejected(self):
        for ext in ('.dat','.idx'):
            old,frozen=self.fixture();frozen[ext]['sha256']='new'
            with self.assertRaisesRegex(ValueError,'NO_LIVE'):c.validate_phase(old,frozen,{'1':'T'})

    def test_missing_or_header_only_copy_is_unqualified(self):
        for size in (None,0,8,6000000):
            old,frozen=self.fixture()
            if size is None:del frozen['.cpd']
            else:frozen['.cpd']['bytes']=size
            with self.assertRaisesRegex(ValueError,'OBSERVED_COMPACTION'):c.validate_phase(old,frozen,{'1':'T'})

    def test_partial_process_stop_is_rejected(self):
        old,frozen=self.fixture()
        for states in ({},{'1':'T','2':'S'},{'1':'R'},{'1':'t'}):
            with self.assertRaisesRegex(ValueError,'ALL_VOLUME_THREADS'):c.validate_phase(old,frozen,states)

    def test_preexisting_temporary_cannot_qualify(self):
        old,frozen=self.fixture();old['.cpd']={'bytes':100}
        with self.assertRaisesRegex(ValueError,'CLEAN_PRECOMMIT'):c.validate_phase(old,frozen,{'1':'T'})

class RollbackTests(unittest.TestCase):
    def fixture(self):
        return {'datFiles':{'v':{'bytes':6000000,'sha256':'old'}},'indexes':{'v':{'deletedNeedles':[4]}},
                'datBytes':6000000,'datAllocatedBytes':6000640,'orphanPayloadFiles':['v'],
                'temporaryCompactionFiles':[],'openDeletedFixtureFiles':[],'volumePid':123}

    def test_old_bytes_tombstone_and_allocation_are_valid_rollback(self):
        old=self.fixture();after=copy.deepcopy(old);after['volumePid']=456;c.validate_rollback(old,after)

    def test_new_compacted_pair_cannot_pass_as_rollback(self):
        old=self.fixture()
        for key in ('datFiles','indexes','datBytes','datAllocatedBytes','orphanPayloadFiles'):
            after=copy.deepcopy(old);after[key]=None
            with self.assertRaisesRegex(ValueError,'EXACT_PRECOMMIT'):c.validate_rollback(old,after)

    def test_temporary_files_are_allowed_only_before_exec(self):
        old=self.fixture();after=copy.deepcopy(old);after['temporaryCompactionFiles']=['v.cpd']
        c.validate_rollback(old,after,gated=True)
        with self.assertRaisesRegex(ValueError,'TEMPORARIES_REMOVED'):c.validate_rollback(old,after)

    def test_unlinked_open_files_are_never_allowed(self):
        old=self.fixture();after=copy.deepcopy(old);after['openDeletedFixtureFiles']=['v.cpd (deleted)']
        for gated in (False,True):
            with self.assertRaisesRegex(ValueError,'NO_OPEN_DELETED'):c.validate_rollback(old,after,gated=gated)

class ModeTests(unittest.TestCase):
    def test_crash_mode_is_exclusive(self):
        spec=importlib.util.spec_from_file_location('lab33',ROOT/'scripts/run-storage-generation33-lateral-isolation.py')
        lab=importlib.util.module_from_spec(spec);spec.loader.exec_module(lab)
        for flag in ('crash_volume','crash_filer','crash_master','crash_all','interrupt_stream','cleanup_stream','compact_stream','restart_compact','relocate_live'):
            with self.assertRaisesRegex(ValueError,'ONE_CRASH_ROLE'):lab.run(None,None,None,None,crash_compact=True,**{flag:True})
        args=(None,'name','network',Path('/data'),Path('/config'),Path('/gate'),'volume',Path('/release'))
        self.assertNotIn('-compactionMBps=1',lab.container_argv(*args))
        self.assertIn('-compactionMBps=1',lab.container_argv(*args,slow_compaction=True))

if __name__=='__main__':unittest.main()
