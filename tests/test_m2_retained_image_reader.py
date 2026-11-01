"""Seven real producer record sets and real archive bytes; modeled Engine/proc.

The separate native suite supplies actual Docker29 exports and kernel pins.
"""
import contextlib,copy,hashlib,io,json,os,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tests/fixtures')]
from retained_image_bytes import fixture as image_fixture
import test_m2_retained_view_intake as views_fixture
import test_m2_retained_mount_capture as first_fixture
from tools.m2_discovery_installation_profile import retained_image_capture as producer
from tools.m2_discovery_installation_profile import retained_image_reader as m
from tools.m2_discovery_installation_profile.custody_capture import encoded


class Reader(unittest.TestCase):
    def failed_predecessor(self,entry,root,observer):
        profile={**copy.deepcopy(entry.PREDECESSOR_PROFILE),'candidateHash':observer.bindings['candidateHash'],
            'captureResultHash':observer.bindings['resultHash']}
        prior=m.Capture(root/'consumed-byte-verification')
        prior.put('image-byte-verification.claim.json',{'schema':'ouf.image-byte-verification-claim.v1',
            'profile':profile,'automaticReplayAllowed':False})
        receipt=json.loads((ROOT/'evidence/m2-image-byte-verification-target-stop-20261101.json').read_bytes())['receipt']
        self.assertEqual(m.digest(receipt),entry.FAILED_RESULT_HASH)
        prior.put('result.json',receipt)
        for name,value in (('FAILED_SCOPE',prior.scope),('PREDECESSOR_PROFILE',profile)):
            context=patch.object(entry,name,value);context.start();self.addCleanup(context.stop)
        return prior.scope

    def prepared(self):
        images={role:image_fixture(role=role) for role in m.ROSTER}
        original=first_fixture.RetainedMetadata.prepared
        def with_images(case):
            result=original(case);_,args,seed,*_=result
            for role,row in seed['observations'].items():row['Image']=images[role][1]
            args['seed_path'].write_bytes(encoded(seed))
            args['seed_hash']=m.digest(seed);return result
        context=patch.object(first_fixture.RetainedMetadata,'prepared',with_images);context.start();self.addCleanup(context.stop)
        case=views_fixture.ViewIntake();self.addCleanup(case.doCleanups)
        views,record,receipt,capture,oldcase,auth,database,keys,root,args,_,history=case.prepared()
        selected={**oldcase,'viewCandidatePath':str(views.view_path),
            'viewCandidateHash':m.digest(record),'viewResultHash':m.digest(receipt)}
        class ExportedArchive:
            def __init__(self,c,binding,ids):self.c=c
            def export(self,image,role):
                raw,wanted,_=images[role];assert image==wanted
                path=self.c.scope/('image-'+role+'.docker.tar');path.write_bytes(raw);path.chmod(0o400)
                self.c.counts['engineGets']+=1;self.c.counts['engineBytes']+=len(raw)
                self.c.counts['imageArchiveBytes']+=len(raw);self.c.counts['imageArchivesCaptured']+=1
                return {'imageIdRequested':image,'filename':path.name,'bytes':len(raw),
                    'sha256':hashlib.sha256(raw).hexdigest(),
                    'metadata':m.attrs(path.lstat()),'nativeIdentityAndSourceAdmissionEstablished':False}
        for mod,values in ((producer,{'CASE':selected,'BOOT_PATH':args['boot_path'],'process_pin':args['pin'],
            'ROSTER':views_fixture.producer.ROSTER,'ImageEngine':ExportedArchive}),
            (m,{'CASE':selected,'BOOT_PATH':args['boot_path'],'process_pin':args['pin']})):
            for name,value in values.items():
                context=patch.object(mod,name,value);context.start();self.addCleanup(context.stop)
        context=patch.object(producer.shutil,'disk_usage',return_value=type('Space',(),{'free':12*1024**3})())
        context.start();self.addCleanup(context.stop)
        c=producer.ImageCapture(root/'image-capture');result=producer.collect(c);c.put('result.json',result)
        index=json.loads((c.scope/'native-image-archives.private.json').read_bytes())
        for name,value in {'CANDIDATE':c.scope/'native-image-archives.private.json',
            'CANDIDATE_HASH':m.digest(index),'RESULT_HASH':m.digest(result),'ROSTER':producer.ROSTER}.items():
            context=patch.object(m,name,value);context.start();self.addCleanup(context.stop)
        observer=m.RetainedArchiveReader()
        return observer,index,result,root,args,images

    def test_actual_producer_index_and_inert_native_bytes_are_read_without_writes_or_private_output(self):
        observer,index,result,root,args,images=self.prepared()
        before={str(p):m.attrs(p.lstat()) for p in root.rglob('*')}
        private,public=observer.read_set()
        self.assertEqual(public['imageCount'],13);self.assertEqual(public['archiveBytesVerified'],result['counts']['imageArchiveBytes'])
        self.assertEqual(set(private['images']),set(m.ROSTER));self.assertEqual(public['privateByteEvidenceHash'],m.digest(private))
        self.assertEqual(public['directEngineGets'],0);self.assertEqual(public['mountedHostFileContentBytesRead'],0)
        self.assertTrue(public['allSevenInputScopesPreserved']);self.assertTrue(public['nativeOrClassicImageByteIdentityProven'])
        self.assertFalse(public['sourcePublisherAuthenticated']);self.assertFalse(public['runtimeAuthorityIssued'])
        self.assertEqual(before,{str(p):m.attrs(p.lstat()) for p in root.rglob('*')})
        for value in ('PRIVATE_IMAGE','NEVER_EMIT_CONFIG_ENV',str(root),'image-mcp.docker.tar'):
            self.assertNotIn(value,json.dumps(public))

    def test_scope_extra_entry_archived_mode_hardlink_and_changed_receipt_deny_before_identity(self):
        for kind in ('extra','mode','hardlink','receipt','claim'):
            observer,_,_,root,*_=self.prepared();folder=observer.path.parent
            if kind=='extra':(folder/'unexpected').touch()
            elif kind=='mode':(folder/'image-mcp.docker.tar').chmod(0o600)
            elif kind=='hardlink':os.link(folder/'image-mcp.docker.tar',root/'extra-link')
            elif kind=='receipt':(folder/'result.json').write_text('{}')
            else:(folder/'native-image-archive.claim.json').write_text('{}')
            with patch.object(m,'verified_image',side_effect=AssertionError('NO_UNADMITTED_IMAGE_BYTE_READ')):
                with self.subTest(kind=kind),self.assertRaises((ValueError,KeyError)):observer.observe()

    def test_root_generation_history_or_archive_bytes_drift_denies(self):
        for kind in ('root','history','archive'):
            observer,_,_,_,_,_=self.prepared()
            if kind=='root':
                with patch.object(m,'process_pin',return_value={}):
                    with self.assertRaisesRegex(ValueError,'ROOT_ENGINE_GENERATION'):observer.observe()
            elif kind=='history':
                path=Path(observer.case['viewCandidatePath']);path.write_text('{}')
                with self.assertRaises((ValueError,KeyError)):observer.observe()
            else:
                path=observer.path.parent/'image-mcp.docker.tar';raw=path.read_bytes()
                path.chmod(0o600);path.write_bytes(raw[:-512]+b'x'*512);path.chmod(0o400)
                with self.assertRaises(ValueError):observer.observe()

    def test_no_arbitrary_path_engine_or_positive_authority_override(self):
        observer,*_=self.prepared()
        with self.assertRaises(TypeError):m.RetainedArchiveReader(path=observer.path)
        with self.assertRaises(TypeError):observer.observe(engine=lambda:True)
        observer.bindings['candidateHash']='0'*64
        with self.assertRaises(ValueError):observer.observe()

    def test_durable_verification_control_writes_private_proofs_once_and_preserves_replay(self):
        observer,_,_,root,*_=self.prepared()
        from tools.m2_discovery_installation_profile import retained_image_verification as entry
        profile={**copy.deepcopy(entry.PROFILE),'candidateHash':observer.bindings['candidateHash'],
            'captureResultHash':observer.bindings['resultHash']};scope=root/'verification-control'
        previous=self.failed_predecessor(entry,root,observer)
        previous_frames={str(p):m.attrs(p.lstat()) for p in previous.rglob('*')}
        with patch.object(entry,'OUTPUT',scope),patch.object(entry,'PROFILE',profile),patch.object(sys,'argv',['verify.py']):
            output=io.StringIO()
            with contextlib.redirect_stdout(output):code=entry.main()
            self.assertEqual(code,0);public=json.loads(output.getvalue())
            self.assertEqual(public['cumulativeControlAttempts'],9);self.assertEqual(public['cumulativeDirectEngineGets'],35)
            self.assertTrue(public['allEightPriorScopesPreserved']);self.assertFalse(public['oldVerificationScopeRearmed'])
            self.assertTrue(public['newVerificationControlScopeCreated'])
            self.assertEqual(public['witness']['imageCount'],13)
            self.assertEqual((scope/'image-byte-evidence.private.json').stat().st_mode&0o777,0o600)
            before={p.name:p.read_bytes() for p in scope.iterdir()}
            with contextlib.redirect_stdout(io.StringIO()):self.assertEqual(entry.main(),1)
            self.assertEqual(before,{p.name:p.read_bytes() for p in scope.iterdir()})
        self.assertEqual(previous_frames,{str(p):m.attrs(p.lstat()) for p in previous.rglob('*')})

    def test_reconciliation_requires_exact_failed_scope_profile_and_receipt_before_archive_reads(self):
        from tools.m2_discovery_installation_profile import retained_image_verification as entry
        for kind in ('receipt','profile','extra','symlink'):
            observer,_,_,root,*_=self.prepared();previous=self.failed_predecessor(entry,root,observer)
            if kind=='receipt':(previous/'result.json').write_bytes(b'{}')
            elif kind=='profile':(previous/'image-byte-verification.claim.json').write_bytes(b'{}')
            elif kind=='extra':(previous/'unexpected').touch()
            else:
                (previous/'result.json').rename(previous/'other.json')
                (previous/'result.json').symlink_to(previous/'other.json');(previous/'other.json').unlink()
            with patch.object(entry,'OUTPUT',root/'byte-reconciliation-control'),patch.object(sys,'argv',['verify.py']),\
                    patch.object(entry.RetainedArchiveReader,'read_set',side_effect=AssertionError('NO_IMAGE_READ')):
                output=io.StringIO()
                with contextlib.redirect_stdout(output):self.assertEqual(entry.main(),1)
                public=json.loads(output.getvalue());self.assertTrue(public['newVerificationControlScopeCreated'])
                self.assertEqual(public['cumulativeControlAttempts'],9)
                self.assertFalse((root/'byte-reconciliation-control'/'image-byte-evidence.private.json').exists())

    def test_changed_failed_predecessor_during_verification_prevents_success_proof(self):
        observer,_,_,root,*_=self.prepared()
        from tools.m2_discovery_installation_profile import retained_image_verification as entry
        previous=self.failed_predecessor(entry,root,observer);original=entry.RetainedArchiveReader.read_set
        def changed(reader):
            result=original(reader);(previous/'result.json').write_bytes(b'{}');return result
        scope=root/'byte-reconciliation-control'
        with patch.object(entry,'OUTPUT',scope),patch.object(sys,'argv',['verify.py']),\
                patch.object(entry.RetainedArchiveReader,'read_set',changed):
            output=io.StringIO()
            with contextlib.redirect_stdout(output):self.assertEqual(entry.main(),1)
            self.assertEqual(json.loads(output.getvalue())['reasonCode'],
                'CONSUMED_IMAGE_VERIFICATION_CHANGED_DURING_RECONCILIATION')
            self.assertFalse((scope/'image-byte-evidence.private.json').exists())

    def test_failed_private_verification_keeps_claim_and_no_false_proof_or_argument_echo(self):
        observer,_,_,root,*_=self.prepared()
        from tools.m2_discovery_installation_profile import retained_image_verification as entry
        scope=root/'failed-verification';(observer.path.parent/'result.json').write_text('{}')
        with patch.object(entry,'OUTPUT',scope),patch.object(sys,'argv',['verify.py']):
            output=io.StringIO()
            with contextlib.redirect_stdout(output):self.assertEqual(entry.main(),1)
            self.assertTrue(json.loads(output.getvalue())['scopeConsumed'])
            self.assertTrue((scope/'image-byte-verification.claim.json').exists())
            self.assertFalse((scope/'image-byte-evidence.private.json').exists())
        other=root/'unused'
        with patch.object(entry,'OUTPUT',other),patch.object(sys,'argv',['verify.py','PRIVATE_ARGUMENT_SENTINEL']):
            output=io.StringIO()
            with contextlib.redirect_stdout(output):self.assertEqual(entry.main(),1)
            self.assertNotIn('PRIVATE_ARGUMENT_SENTINEL',output.getvalue());self.assertFalse(other.exists())


if __name__=='__main__':unittest.main()
