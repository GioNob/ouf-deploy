import copy
import importlib.util
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('compact_lab33',ROOT/'scripts/run-storage-generation33-lateral-isolation.py')
lab=importlib.util.module_from_spec(spec);spec.loader.exec_module(lab)
c=lab.compact

class CompactionTests(unittest.TestCase):
    def fixture(self,root):
        payload=lab.stream.body()[:c.CHUNK_BYTES]
        chunk={'volumeId':'3','datFile':'ouf-identity-fixture_3.dat','needleId':4,'fileId':'3,0412345678','dataSha256':c.sha(payload)}
        header=b'\x03'+b'\0'*7
        def record(nid,data):
            raw=struct.pack('>IQiI',0x12345678,nid,len(data)+10,len(data))+data+b'\0'*20
            return raw+b'\0'*((-len(raw))%8)
        live=record(2,b'live-baseline');orphan=record(4,payload);offset=8+len(live)
        dat=root/chunk['datFile'];idx=dat.with_suffix('.idx')
        dat.write_bytes(header+live+orphan+b'\0'*32)
        liveidx=struct.pack('>QIi',2,1,len(b'live-baseline')+10)
        idx.write_bytes(liveidx+struct.pack('>QIi',4,offset//8,len(payload)+10)+struct.pack('>QIi',4,(offset+len(orphan))//8,-1))
        other=root/'ouf-identity-fixture_5.dat';other.write_bytes(header+record(9,b'other-live'))
        other.with_suffix('.idx').write_bytes(struct.pack('>QIi',9,1,len(b'other-live')+10))
        with patch.object(c,'deleted_handles',return_value=[]):before=c.snapshot(root,chunk,os.getpid())
        dat.write_bytes(header+live);idx.write_bytes(liveidx)
        with patch.object(c,'deleted_handles',return_value=[]):after=c.snapshot(root,chunk,os.getpid())
        return chunk,before,after

    def test_command_is_exact_collection_volume_with_lock_and_no_retry(self):
        chunk={'volumeId':'3','datFile':'ouf-identity-fixture_3.dat'}
        self.assertEqual(c.command_script(chunk),'lock\nvolume.vacuum -collection=ouf-identity-fixture -volumeId=3 -garbageThreshold=0.01\nunlock\n')
        for vid in ('','0','3,4','3\nunlock','-1','4294967296'):
            with self.assertRaises(ValueError):c.command_script({**chunk,'volumeId':vid})

    def test_collection_cannot_be_changed(self):
        with self.assertRaises(ValueError):c.command_script({'volumeId':'3','datFile':'other_3.dat'})

    def test_real_snapshots_preserve_live_data_and_measure_both_sizes(self):
        with tempfile.TemporaryDirectory() as temp:
            chunk,before,after=self.fixture(Path(temp));r=c.validate(before,after,chunk)
            self.assertGreaterEqual(r['datBytesReclaimed'],c.CHUNK_BYTES)
            self.assertGreaterEqual(r['allocatedDatBytesReclaimed'],c.CHUNK_BYTES)
            self.assertEqual(before['indexes']['ouf-identity-fixture_3.idx']['deletedNeedles'],[4])
            self.assertEqual(after['indexes']['ouf-identity-fixture_3.idx']['deletedNeedles'],[])
            self.assertTrue(r['allLiveNeedlesPreserved']);self.assertFalse(r['postCompactionRestartQualified'])

    def test_live_chunk_corruption_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            chunk,before,after=self.fixture(Path(temp))
            after['indexes']['ouf-identity-fixture_3.idx']['liveNeedles']['2']['dataSha256']='0'*64
            with self.assertRaisesRegex(ValueError,'LIVE_NEEDLES'):c.validate(before,after,chunk)

    def test_retained_payload_or_tombstone_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            chunk,before,after=self.fixture(Path(temp))
            for which in ('payload','index'):
                bad=copy.deepcopy(after)
                if which=='payload':bad['orphanPayloadFiles']=[chunk['datFile']]
                else:bad['indexes']['ouf-identity-fixture_3.idx']['deletedNeedles']=[4]
                with self.assertRaises(ValueError):c.validate(before,bad,chunk)

    def test_logical_shrink_without_allocated_block_recovery_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            chunk,before,after=self.fixture(Path(temp));after['datAllocatedBytes']=before['datAllocatedBytes']
            with self.assertRaisesRegex(ValueError,'ALLOCATION_REDUCTION'):c.validate(before,after,chunk)

    def test_unselected_volume_or_volume_set_changes_fail(self):
        with tempfile.TemporaryDirectory() as temp:
            chunk,before,after=self.fixture(Path(temp))
            for which in ('bytes','removed'):
                bad=copy.deepcopy(after)
                if which=='bytes':bad['datFiles']['ouf-identity-fixture_5.dat']['sha256']='0'*64
                else:del bad['datFiles']['ouf-identity-fixture_5.dat']
                with self.assertRaises(ValueError):c.validate(before,bad,chunk)

    def test_leftovers_or_deleted_open_handles_prevent_reclamation_claim(self):
        with tempfile.TemporaryDirectory() as temp:
            chunk,before,after=self.fixture(Path(temp))
            for field in ('temporaryCompactionFiles','openDeletedFixtureFiles'):
                bad=copy.deepcopy(after);bad[field]=['old.dat']
                with self.assertRaisesRegex(ValueError,'LEFTOVERS'):c.validate(before,bad,chunk)

    def test_restart_during_compaction_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            chunk,before,after=self.fixture(Path(temp));after['volumePid']+=1
            with self.assertRaisesRegex(ValueError,'SAME_LIVE_VOLUME'):c.validate(before,after,chunk)

    def test_snapshot_rejects_truncated_index_and_symlink_data(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);chunk,_,_=self.fixture(root);idx=root/'ouf-identity-fixture_3.idx';idx.write_bytes(b'bad')
            with self.assertRaises(ValueError):c.snapshot(root,chunk,os.getpid())
            dat=root/chunk['datFile'];dat.unlink();dat.symlink_to(root/'ouf-identity-fixture_5.dat')
            with self.assertRaises(ValueError):c.snapshot(root,chunk,os.getpid())

    def test_deleted_handle_scan_is_scoped_and_bounded(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);fds=root/'123/fd';fds.mkdir(parents=True)
            target='/data/ouf-identity-fixture_3.dat (deleted)'
            (fds/'1').symlink_to(target);(fds/'2').symlink_to('/unrelated/file (deleted)')
            self.assertEqual(c.deleted_handles('123',root),[target])
            for n in range(3,258):(fds/str(n)).symlink_to('/unrelated')
            with self.assertRaisesRegex(ValueError,'BOUNDED_VOLUME_FDS'):c.deleted_handles('123',root)

    def test_gate_marker_is_complete_before_it_becomes_visible(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);original=Path.replace;observations=[]
            def replace(source,target):
                observations.append((source.read_bytes(),target.exists()))
                return original(source,target)
            with patch.object(Path,'replace',replace):lab.publish_gate(root)
            self.assertEqual(observations,[(b'READY\n',False)])
            self.assertEqual((root/'open').read_bytes(),b'READY\n');self.assertFalse((root/'open.tmp').exists())

    def test_stale_temporary_marker_in_last_gate_blocks_every_release(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);gates={r:root/r for r in lab.SERVICES}
            for p in gates.values():p.mkdir()
            (gates['s3']/'open.tmp').write_text('partial')
            with self.assertRaises(ValueError):lab.release_replacement_gates(gates)
            self.assertTrue(all(not (p/'open').exists() for p in gates.values()))

    def test_compaction_mode_cannot_combine_fault_modes(self):
        for flag in ('crash_volume','crash_filer','crash_master','crash_all','interrupt_stream','cleanup_stream'):
            with self.assertRaisesRegex(ValueError,'ONE_CRASH_ROLE'):
                lab.run(None,None,None,None,compact_stream=True,**{flag:True})

if __name__=='__main__':unittest.main()
