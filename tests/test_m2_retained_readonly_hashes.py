"""Actual prior producer output and regular-file hashing; Engine/pins modeled."""
import copy,hashlib,json,os,sys,unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_retained_mount_intake as fixture
from tools.m2_discovery_installation_profile import retained_readonly_hashes as m


class ReadonlyHashes(unittest.TestCase):
    def prepared(self,*,seed_transform=None,extra_file=False):
        case=fixture.Intake();self.addCleanup(case.doCleanups)
        def ready(root,mounted):
            (mounted/'credential').chmod(0o600)
            if extra_file:(mounted/'empty').touch(mode=0o600)
        capture,args,seed,root,mounted,reads,candidate,result,bindings,_=case.prepared(
            before_capture=ready,seed_transform=seed_transform)
        selected={'candidatePath':str(capture.scope/'retained-mounts.private.json'),
            'resultPath':str(capture.scope/'result.json'),'seedPath':str(args['seed_path']),
            'candidateHash':bindings['candidate_hash'],'resultHash':bindings['result_hash'],
            'seedHash':bindings['seed_hash'],'failedScope':str(args['predecessor_root'])}
        for name,value in {'CASE':selected,'ROSTER':bindings['roster'],
            'RetainedEngine':args['engine_factory'],'process_pin':args['pin'],'BOOT_PATH':args['boot_path']}.items():
            context=patch.object(m,name,value);context.start();self.addCleanup(context.stop)
        c=m.ReadonlyHashPreparation(root/'hash-preparation');reads.clear()
        return c,root,mounted,reads,args,candidate,selected

    def test_only_unique_readonly_regular_file_bytes_hashed_no_fifo_or_mutable_read_no_raw_export(self):
        c,root,mounted,reads,args,_,selected=self.prepared()
        history={str(p):p.read_bytes() for directory in (Path(selected['failedScope']),Path(selected['candidatePath']).parent)
            for p in directory.iterdir()}
        original_open=os.open;original_dup=os.dup;opened={}
        allowed={str(mounted/'credential'),selected['candidatePath'],selected['resultPath'],selected['seedPath'],
            str(Path(selected['failedScope'])/'result.json')}
        def closed(path,flags,*a,**kw):
            resolved=os.path.normpath(str(path)) if Path(path).is_absolute() else (
                os.path.normpath(str(Path(opened[kw['dir_fd']])/path)) if kw.get('dir_fd') in opened else None)
            if not flags&(os.O_DIRECTORY|os.O_PATH|os.O_WRONLY|os.O_RDWR):self.assertIn(resolved,allowed)
            fd=original_open(path,flags,*a,**kw)
            if resolved is not None:opened[fd]=resolved
            return fd
        def duplicate(fd):
            copy=original_dup(fd)
            if fd in opened:opened[copy]=opened[fd]
            return copy
        with patch.object(os,'open',side_effect=closed),patch.object(os,'dup',side_effect=duplicate):result=m.collect(c)
        self.assertEqual(len(reads),20);self.assertEqual(result['counts']['readonlyRegularFilesHashed'],1)
        self.assertEqual(result['counts']['readonlyFileBytesHashed'],len(b'NEVER_READ_MOUNTED_FILE_CONTENT'))
        self.assertEqual(result['cumulativeDirectEngineGets'],40);self.assertEqual(result['cumulativeControlAttempts'],3)
        private=json.loads((c.scope/'readonly-content-hashes.private.json').read_bytes())
        self.assertEqual(set(private['files']),{str(mounted/'credential')})
        self.assertEqual(private['files'][str(mounted/'credential')]['sha256'],hashlib.sha256(b'NEVER_READ_MOUNTED_FILE_CONTENT').hexdigest())
        public=json.dumps(result);raw=(c.scope/'readonly-content-hashes.private.json').read_text()
        for sentinel in ('NEVER_READ_MOUNTED_FILE_CONTENT','NEVER_ENUMERATE_MUTABLE_CONTENT','fixture-sensitive'):
            self.assertNotIn(sentinel,raw+public)
        self.assertNotIn(str(mounted),public);self.assertNotIn(private['files'][str(mounted/'credential')]['sha256'],public)
        self.assertTrue(result['regularReadonlyContentsReadForHashingOnly'])
        self.assertTrue(result['credentialOrKeyFilesMayHaveBeenHashed'])
        self.assertNotIn('credentialFileReads',result['counts'])
        self.assertFalse(result['completePrivateCustodyProven']);self.assertFalse(result['targetApplyAuthorized'])
        self.assertFalse(result['rawValuesOrIndividualFileHashesPrinted'])
        self.assertEqual(history,{p:Path(p).read_bytes() for p in history})
        self.assertEqual((c.scope/'readonly-content-hashes.private.json').stat().st_mode&0o777,0o600)

    def test_byte_limits_refuse_before_any_content_open_and_scope_never_replays(self):
        c,_,mounted,_,_,_,_=self.prepared()
        with self.assertRaisesRegex(ValueError,'CONSUMED_NO_REPLAY'):m.ReadonlyHashPreparation(c.scope)
        original=os.open;content_reads=[]
        def check(path,flags,*a,**kw):
            if str(path)=='credential' and not flags&(os.O_PATH|os.O_DIRECTORY):content_reads.append(path)
            return original(path,flags,*a,**kw)
        with patch.dict(m.PROFILE,maximumTotalHashedBytes=1),patch.object(os,'open',side_effect=check),self.assertRaisesRegex(ValueError,'HASH_BYTES_REQUIRED'):
            m.collect(c)
        self.assertFalse(content_reads);self.assertFalse(c.hashes)
        self.assertFalse((c.scope/'readonly-content-hashes.private.json').exists())

    def test_predecessor_successful_scope_candidate_or_process_drift_denies_without_engine(self):
        for kind in ('old-extra','success-extra','candidate','result','seed','pin'):
            c,_,_,reads,_,_,selected=self.prepared()
            if kind=='old-extra':(Path(selected['failedScope'])/'unexpected').touch()
            elif kind=='success-extra':(Path(selected['candidatePath']).parent/'unexpected').touch()
            elif kind in ('candidate','result','seed'):Path(selected[kind+'Path']).write_bytes(b'{}')
            else:
                context=patch.object(m,'process_pin',lambda pid:{'pid':pid,'changed':True});context.start();self.addCleanup(context.stop)
            with self.subTest(kind=kind),self.assertRaises((ValueError,KeyError)):m.collect(c)
            self.assertFalse(reads);self.assertFalse(c.hashes)

    def test_readonly_link_hardlink_or_metadata_drift_cannot_be_hashed(self):
        for kind in ('link','hardlink','mode'):
            c,root,mounted,_,_,_,_=self.prepared();secret=mounted/'credential'
            if kind=='link':secret.unlink();secret.symlink_to(root/'mutable/private-data')
            elif kind=='hardlink':os.link(secret,mounted/'alias')
            else:secret.chmod(0o400)
            with self.subTest(kind=kind),self.assertRaises((ValueError,OSError)):m.collect(c)
            self.assertFalse(c.hashes)

    def test_file_content_drift_while_reading_keeps_no_positive_hash_candidate(self):
        c,_,mounted,_,_,_,_=self.prepared();original=os.read;inode=(mounted/'credential').stat().st_ino
        changed=[]
        def mutate(fd,amount):
            raw=original(fd,amount)
            if os.fstat(fd).st_ino==inode and not changed:
                changed.append(True);(mounted/'credential').write_bytes(b'CHANGED_SAME_OPERATION')
            return raw
        with patch.object(os,'read',side_effect=mutate),self.assertRaisesRegex(ValueError,'CHANGED_DURING_HASH_READ'):m.collect(c)
        self.assertFalse((c.scope/'readonly-content-hashes.private.json').exists())

    def test_mutable_payload_changes_are_not_read_or_promoted_to_content_policy(self):
        c,root,_,_,_,_,_=self.prepared()
        (root/'mutable/private-data').write_text('CHANGED_MUTABLE_PAYLOAD')
        (root/'mutable/new').write_text('UNREAD')
        result=m.collect(c)
        self.assertFalse(result['mutableContentsObserved']);self.assertFalse(result['expectedPermissionOrContentPolicyEstablished'])
        self.assertEqual(len(c.hashes),1)

    def test_readonly_alias_of_declared_mutable_source_denies_before_any_hash(self):
        def overlap(seed):
            for row in seed['observations'].values():
                row['Mounts'].append({'Type':'bind','Source':row['Mounts'][0]['Source'],
                    'Destination':'/mutable-alias','RW':True})
        c,*_=self.prepared(seed_transform=overlap)
        with self.assertRaisesRegex(ValueError,'OVERLAPS_CAPTURED_MUTABLE_SOURCE'):m.collect(c)
        self.assertFalse(c.hashes);self.assertEqual(c.counts['readonlyFileBytesHashed'],0)

    def test_empty_readonly_regular_file_has_explicit_empty_hash_without_extra_reads(self):
        c,_,mounted,*_=self.prepared(extra_file=True);result=m.collect(c)
        self.assertEqual(result['counts']['readonlyRegularFilesHashed'],2)
        self.assertEqual(c.hashes[str(mounted/'empty')]['sha256'],hashlib.sha256(b'').hexdigest())
        self.assertEqual(c.hashes[str(mounted/'empty')]['bytes'],0)

    def test_engine_connection_failure_is_not_retried_or_erased(self):
        c,_,_,reads,_,_,_=self.prepared()
        class Down:
            def __init__(self,*args):pass
            def get(self,cid):reads.append(cid);raise TimeoutError('fixture')
        with patch.object(m,'RetainedEngine',Down),self.assertRaises(TimeoutError):m.collect(c)
        self.assertEqual(len(reads),1);self.assertFalse(c.hashes)
        self.assertTrue((c.scope/'readonly-hash-preparation.claim.json').exists())

    def test_production_entrypoint_has_no_path_mode_or_callback_override(self):
        c,*_=self.prepared()
        with self.assertRaises(TypeError):m.collect(c,seed_path='/arbitrary')
        with self.assertRaises(TypeError):m.collect(c,engine_factory=lambda *a:None)


if __name__=='__main__':unittest.main()
