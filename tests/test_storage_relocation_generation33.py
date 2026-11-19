import copy
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('relocation_lab33',ROOT/'scripts/run-storage-generation33-lateral-isolation.py')
lab=importlib.util.module_from_spec(spec);spec.loader.exec_module(lab)
r=lab.relocation

class RelocationTests(unittest.TestCase):
    def fixture(self,root):
        payload=lab.stream.body()[:4194304];header=b'\3'+b'\0'*7
        chunk={'volumeId':'3','datFile':'ouf-identity-fixture_3.dat','needleId':4,'needleOffset':8,
               'dataBytes':len(payload),'dataSha256':r.sha(payload),'fileId':'3,0412345678'}
        def record(nid,cookie,data):
            raw=struct.pack('>IQiI',cookie,nid,len(data)+12,len(data))+data+b'\0'*20
            return raw+b'\0'*((-len(raw))%8)
        orphan=record(4,0x12345678,payload);dat=root/chunk['datFile'];idx=dat.with_suffix('.idx')
        dat.write_bytes(header+orphan+b'\0'*32)
        deleted=struct.pack('>QIi',4,1,len(payload)+12)+struct.pack('>QIi',4,(8+len(orphan))//8,-1)
        idx.write_bytes(deleted)
        def snapshot():
            with patch.object(lab.compact,'deleted_handles',return_value=[]):return lab.compact.snapshot(root,chunk,123)
        initial=snapshot();w=r.prepare(initial,chunk);offset=dat.stat().st_size
        live=record(r.NEEDLE_ID,int(r.COOKIE,16),r.body());dat.write_bytes(dat.read_bytes()+live)
        entry=struct.pack('>QIi',r.NEEDLE_ID,offset//8,r.BYTES+12);idx.write_bytes(deleted+entry)
        before=snapshot();obs_before=r.observe(root,w)
        dat.write_bytes(header+live);idx.write_bytes(struct.pack('>QIi',r.NEEDLE_ID,1,r.BYTES+12))
        after=snapshot();obs_after=r.observe(root,w)
        return chunk,w,initial,before,after,obs_before,obs_after

    def test_exact_native_offset_shift_body_and_allocation(self):
        with tempfile.TemporaryDirectory(dir=ROOT.parent) as tmp:
            c,w,i,b,a,ob,oa=self.fixture(Path(tmp));r.validate_append(i,b,w,ob)
            reclaimed=lab.compact.validate(b,a,c);proof=r.validate(ob,oa,c,reclaimed)
            self.assertGreaterEqual(proof['offsetReduction'],4194304);self.assertEqual(oa['needleOffset'],8)
            self.assertEqual(proof['dataSha256'],r.sha(r.body()))

    def test_reserved_id_collision_in_any_volume_is_rejected(self):
        c={'volumeId':'3','datFile':'ouf-identity-fixture_3.dat','needleId':4}
        for kind in ('live','deleted'):
            snapshot={'indexes':{'ouf-identity-fixture_3.idx':{'liveNeedles':{},'deletedNeedles':[4]},
                       'other.idx':{'liveNeedles':{str(r.NEEDLE_ID):{}} if kind=='live' else {},'deletedNeedles':[r.NEEDLE_ID] if kind=='deleted' else []}}}
            with self.assertRaisesRegex(ValueError,'UNUSED'):r.prepare(snapshot,c)

    def test_identity_rejects_unbound_volume_and_collection(self):
        for c in ({'volumeId':'3\n','datFile':'ouf-identity-fixture_3.dat'}, {'volumeId':'3','datFile':'other_3.dat'}):
            with self.assertRaises(ValueError):r.identity(c)

    def test_append_must_preserve_exact_old_prefix(self):
        with tempfile.TemporaryDirectory(dir=ROOT.parent) as tmp:
            c,w,i,b,a,ob,oa=self.fixture(Path(tmp))
            for field in ('prefixSha256','indexPrefixSha256'):
                bad=copy.deepcopy(ob);bad[field]='0'*64
                with self.assertRaisesRegex(ValueError,'PREFIX'):r.validate_append(i,b,w,bad)

    def test_nonmoving_or_wrong_distance_is_not_relocation(self):
        with tempfile.TemporaryDirectory(dir=ROOT.parent) as tmp:
            c,w,i,b,a,ob,oa=self.fixture(Path(tmp));reclaimed=lab.compact.validate(b,a,c)
            for off in (ob['needleOffset'],16):
                bad=copy.deepcopy(oa);bad['needleOffset']=off
                with self.assertRaisesRegex(ValueError,'REAL_RELOCATION'):r.validate(ob,bad,c,reclaimed)

    def test_changed_cookie_body_or_identity_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=ROOT.parent) as tmp:
            c,w,i,b,a,ob,oa=self.fixture(Path(tmp));reclaimed=lab.compact.validate(b,a,c)
            for key in ('cookieHex','dataSha256','fileId','needleSize'):
                bad=copy.deepcopy(oa);bad[key]='invalid'
                with self.assertRaisesRegex(ValueError,'IDENTITY_AND_BODY'):r.validate(ob,bad,c,reclaimed)

    def test_native_corruption_and_index_truncation_are_rejected(self):
        with tempfile.TemporaryDirectory(dir=ROOT.parent) as tmp:
            root=Path(tmp);c,w,*_=self.fixture(root);dat=root/w['datFile'];raw=bytearray(dat.read_bytes());raw[28]^=255;dat.write_bytes(raw)
            with self.assertRaisesRegex(ValueError,'EXACT_NATIVE'):r.observe(root,w)
            dat.with_suffix('.idx').write_bytes(b'bad')
            with self.assertRaisesRegex(ValueError,'COMPLETE_RELOCATION_INDEX'):r.observe(root,w)

    def test_symlink_storage_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=ROOT.parent) as tmp:
            root=Path(tmp);c,w,*_=self.fixture(root);dat=root/w['datFile'];dat.unlink();dat.symlink_to(root/'elsewhere')
            with self.assertRaisesRegex(ValueError,'BOUNDED_RELOCATION_DAT'):r.observe(root,w)

    def http_connections(self,pre=404,post=201):
        a,b=Mock(),Mock();a.getresponse.return_value.status=pre;a.getresponse.return_value.read.return_value=b'absent'
        b.getresponse.return_value.status=post;b.getresponse.return_value.read.return_value=json.dumps({'size':r.BYTES}).encode()
        return a,b

    def test_upload_is_single_native_post_after_absence(self):
        a,b=self.http_connections();w=r.identity({'volumeId':'3','datFile':'ouf-identity-fixture_3.dat'})
        with patch.object(r.http.client,'HTTPConnection',side_effect=[a,b]):proof=r.upload('fixture',w)
        self.assertEqual(a.request.call_args.args[:2],('GET','/'+w['fileId']))
        self.assertEqual(b.request.call_args.args[:2],('POST','/'+w['fileId']))
        self.assertEqual(b.request.call_args.kwargs['body'],r.body());self.assertEqual(b.request.call_count,1)
        self.assertEqual(proof['nativeWriteRequests'],1);self.assertEqual(proof['mutatingRetries'],0)

    def test_preexisting_witness_prevents_mutation(self):
        a,b=self.http_connections(pre=200);w=r.identity({'volumeId':'3','datFile':'ouf-identity-fixture_3.dat'})
        with patch.object(r.http.client,'HTTPConnection',side_effect=[a,b]):
            with self.assertRaisesRegex(ValueError,'ABSENT_BEFORE_WRITE'):r.upload('fixture',w)
        b.request.assert_not_called()

    def test_failed_post_is_not_retried(self):
        a,b=self.http_connections(post=503);w=r.identity({'volumeId':'3','datFile':'ouf-identity-fixture_3.dat'})
        with patch.object(r.http.client,'HTTPConnection',side_effect=[a,b]):
            with self.assertRaisesRegex(ValueError,'ACKNOWLEDGED'):r.upload('fixture',w)
        self.assertEqual(b.request.call_count,1)

    def test_relocation_mode_excludes_other_modes(self):
        for flag in ('crash_volume','crash_filer','crash_master','crash_all','interrupt_stream','cleanup_stream','compact_stream','restart_compact'):
            with self.assertRaisesRegex(ValueError,'ONE_CRASH_ROLE'):lab.run(None,None,None,None,relocate_live=True,**{flag:True})

if __name__=='__main__':unittest.main()
