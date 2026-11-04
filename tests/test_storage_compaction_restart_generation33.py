import copy
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('compact_restart33',ROOT/'scripts/run-storage-generation33-lateral-isolation.py')
lab=importlib.util.module_from_spec(spec);spec.loader.exec_module(lab)

class CompactionRestartTests(unittest.TestCase):
    def snapshot(self):
        return {'volumePid':123,'datFiles':{'v.dat':{'bytes':8,'allocatedBytes':4096,'sha256':'a'*64}},
            'indexes':{'v.idx':{'bytes':0,'sha256':'b'*64,'liveNeedles':{},'deletedNeedles':[]}},
            'datBytes':8,'datAllocatedBytes':4096,'orphanPayloadFiles':[],
            'temporaryCompactionFiles':[],'openDeletedFixtureFiles':[],'mutatingRequests':0}

    def test_exact_storage_survives_pid_change(self):
        before=self.snapshot();after=copy.deepcopy(before);after['volumePid']=456
        lab.compact.validate_restart(before,after)

    def test_pid_reuse_is_not_mistaken_for_container_identity(self):
        lab.compact.validate_restart(self.snapshot(),self.snapshot())

    def test_dat_and_index_corruption_or_missing_volume_rejected(self):
        before=self.snapshot()
        for field in ('datFiles','indexes'):
            for operation in ('hash','missing'):
                after=copy.deepcopy(before);name=next(iter(after[field]))
                if operation=='hash':after[field][name]['sha256']='c'*64
                else:del after[field][name]
                with self.assertRaisesRegex(ValueError,'EXACT_COMPACTED'):lab.compact.validate_restart(before,after)

    def test_reexpanded_allocation_or_length_rejected(self):
        before=self.snapshot()
        for field in ('datBytes','datAllocatedBytes'):
            after=copy.deepcopy(before);after[field]+=4096
            with self.assertRaisesRegex(ValueError,'EXACT_COMPACTED'):lab.compact.validate_restart(before,after)

    def test_resurrected_orphan_and_open_deleted_files_rejected(self):
        for field in ('orphanPayloadFiles','temporaryCompactionFiles','openDeletedFixtureFiles'):
            before=self.snapshot();after=copy.deepcopy(before);after[field]=['v.dat']
            with self.assertRaisesRegex(ValueError,'ORPHAN_OR_LEFTOVERS'):lab.compact.validate_restart(before,after)

    def test_live_needle_or_tombstone_change_rejected(self):
        for field,value in (('liveNeedles',{'4':{'dataSha256':'c'*64}}),('deletedNeedles',[4])):
            before=self.snapshot();after=copy.deepcopy(before);after['indexes']['v.idx'][field]=value
            with self.assertRaisesRegex(ValueError,'EXACT_COMPACTED'):lab.compact.validate_restart(before,after)

    def test_invalid_new_pid_rejected(self):
        for pid in (0,-1,'123',None):
            before=self.snapshot();after=copy.deepcopy(before);after['volumePid']=pid
            with self.assertRaisesRegex(ValueError,'LIVE_RESTART'):lab.compact.validate_restart(before,after)

    def test_restart_mode_excludes_all_other_modes(self):
        for flag in ('crash_volume','crash_filer','crash_master','crash_all','interrupt_stream','cleanup_stream','compact_stream'):
            with self.assertRaisesRegex(ValueError,'ONE_CRASH_ROLE'):
                lab.run(None,None,None,None,restart_compact=True,**{flag:True})

if __name__=='__main__':unittest.main()
