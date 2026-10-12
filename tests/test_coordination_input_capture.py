"""Actual private POSIX fixture inputs; no target, keys or runtime authority."""
import contextlib,hashlib,importlib.util,io,json,os,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=load('capture',ROOT/'scripts/capture-native-v11-coordination-inputs.py')
atomic=load('atomic_capture',ROOT/'tools/semantic_application_cutover/atomic_review_intake.py')
custody=load('custody_capture',ROOT/'tests/fixtures/custody.py') if not (ROOT/'tools/semantic_target_review/prepare_application_runtime_inputs.py').exists() else load('custody_capture',ROOT/'tools/semantic_target_review/prepare_application_runtime_inputs.py')

class Capture(unittest.TestCase):
    def fixture(self):
        self.assertEqual(os.geteuid(),0,'ROOT_PRIVATE_POSIX_FIXTURE_REQUIRED')
        temp=tempfile.TemporaryDirectory(prefix='ouf-capture-test-',dir=ROOT);self.addCleanup(temp.cleanup);base=Path(temp.name);base.chmod(0o700)
        def write(path,value):
            path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);path.write_bytes(m.encoded(value));path.chmod(0o600);return m.sha(path.read_bytes())
        previous=base/'previous';native=write(previous/'intake.json',{'schema':'ouf.native-v11-atomic-review-intake.v1','observationsAreHistorical':True,'applicationCutoverAuthorized':False,'productionApplyReady':False,'runtimeAuthorityIssued':False})
        secret=base/'private-key.pem';secret.write_text('fixture-only-private-key-marker');secret.chmod(0o600)
        authority=base/'authority.json';ah=write(authority,{'schema':'ouf.semantic-existing-installation-authority-bindings.v1','keyBindings':{'attestor':{'path':str(secret)}}})
        coordinator=base/'coordinator.json';ch=write(coordinator,{'fixtureConfigurationValue':'PRIVATE_FIXTURE_COORDINATION_VALUE'})
        ctx=base/'context';execution=write(ctx/'execution-configuration.json',{'commandBindings':{'fixture':{'path':'/fixture/only','sha256':'a'*64}}});write(ctx/'human-approval-binding.json',{'configurationHash':execution,'historicalApprovalOnly':True})
        r12=base/'r12';r12.mkdir(mode=0o700);source=r12/'fixture_program.py';source.write_bytes(b'fixture program bytes only');source.chmod(0o600)
        programs={source.name:m.sha(source.read_bytes())};boot='fixture-only-boot';incident='d'*64
        p=patch.object(m,'boot_id',return_value=boot);p.start();self.addCleanup(p.stop)
        claim=base/'r12.claim';claim_value={'startAuthorized':False,'fixture':True};write(claim,claim_value)
        auth={'schema':'ouf.provider-resilient-r12-authorization.v1','programHashes':programs,'hostBootId':boot,'incidentRef':incident,'ownerConfigurationHash':ch,'generationRef':'e'*64,'automaticRestart':False,'enableAtBoot':False,'activationClaim':claim_value}
        auth['contextRef']=m.sha(m.encoded(auth));auth_hash=write(r12/'authorization.json',auth)
        write(r12/'worker-invocation-claim.json',{'contextRef':auth['contextRef'],'pid':1234,'hostBootId':boot})
        write(r12/'worker-status.json',{'schema':'ouf.provider-resilient-worker-status.v1','workerPid':1234,'incidentRef':incident,'doNotRerunApply':True,'startAuthorized':False})
        write(r12/'retry/recovery.json',{'contextRef':auth['contextRef'],'generationRef':'e'*64,'timeAccountingProfile':'ouf.lease-cumulative-recovery-time.v1','attempts':12,'publicationCount':1943,'fixturePrivateValue':'PRIVATE_FIXTURE_HISTORY_VALUE'})
        prepare=types.SimpleNamespace(R12=r12,R12_CLAIM=claim,R12_INCIDENT=incident,R12_PROGRAMS=programs)
        constants={'BASE':base,'COORDINATOR':coordinator,'COORDINATOR_HASH':ch,'CONTEXT':ctx,'AUTHORITY':authority,'AUTHORITY_HASH':ah,'R12_AUTH_HASH':auth_hash,'NATIVE_INTAKE_HASH':native,'NATIVE_INTAKE':previous}
        for k,v in constants.items():p=patch.object(m,k,v);p.start();self.addCleanup(p.stop)
        return base,prepare,secret
    def execute(self,modules):
        output=io.StringIO()
        with patch.object(m,'modules',return_value=modules),patch.object(m.sys,'flags',types.SimpleNamespace(isolated=True)),patch.object(m.sys,'dont_write_bytecode',True),patch.object(m.sys,'argv',['fixture.py']),contextlib.redirect_stdout(output):code=m.main()
        return code,json.loads(output.getvalue().split('=',1)[1]),output.getvalue()
    def test_full_entry_publishes_complete_private_snapshot_without_reading_key_or_printing_values(self):
        base,prepare,secret=self.fixture();opened=[];original=custody.file_bytes
        def read(path,*args,**kwargs):opened.append(Path(path));return original(path,*args,**kwargs)
        with patch.object(custody,'file_bytes',side_effect=read):code,report,raw=self.execute({'prepare':prepare,'custody':custody,'atomic':atomic})
        self.assertEqual(code,0,report);self.assertNotIn(secret,opened);self.assertNotIn('PRIVATE_FIXTURE',raw)
        self.assertEqual(report['protectedFileWrites'],11);self.assertTrue(report['publicationIsAtomic']);self.assertFalse(report['runtimeAuthorityIssued'])
        published=Path(report['directory']);self.assertEqual(len(list(published.iterdir())),11)
        self.assertEqual((published/'r12-recovery-history.json').read_bytes(),(prepare.R12/'retry/recovery.json').read_bytes())
        code,repeat,_=self.execute({'prepare':prepare,'custody':custody,'atomic':atomic});self.assertEqual(code,0);self.assertEqual(repeat['protectedFileWrites'],0)
    def test_changed_history_or_context_denies_before_any_private_publication(self):
        for change in ('history','context'):
            base,prepare,secret=self.fixture()
            if change=='context':
                p=prepare.R12/'worker-invocation-claim.json';value=json.loads(p.read_bytes());value['contextRef']='f'*64;p.write_bytes(m.encoded(value))
                code,report,_=self.execute({'prepare':prepare,'custody':custody,'atomic':atomic})
            else:
                original=custody.file_bytes;count=[0];history=prepare.R12/'retry/recovery.json'
                def read(path,*args,**kwargs):
                    if Path(path)==history:
                        count[0]+=1
                        if count[0]==2:
                            value=json.loads(history.read_bytes());value['publicationCount']+=1;history.write_bytes(m.encoded(value))
                    return original(path,*args,**kwargs)
                with patch.object(custody,'file_bytes',side_effect=read):code,report,_=self.execute({'prepare':prepare,'custody':custody,'atomic':atomic})
            self.assertEqual(code,1);self.assertEqual(report['protectedFileWrites'],0)
    def test_all_source_hashes_precede_module_execution(self):
        sources={k:b'raise RuntimeError("EXECUTED_UNVERIFIED_SOURCE")' for k in m.HASHES}
        with self.assertRaisesRegex(ValueError,'COORDINATION_SOURCE_HASH_MISMATCH'):m.modules(sources)
    def test_partial_private_write_counts_attempt_and_retains_ambiguity(self):
        base,prepare,secret=self.fixture()
        def fail(base,files,manifest,uid,checkpoint):checkpoint('BEFORE_FILE_fixture.json');raise OSError('private failure')
        with patch.object(atomic,'publish',side_effect=fail):code,report,raw=self.execute({'prepare':prepare,'custody':custody,'atomic':atomic})
        self.assertEqual(code,1);self.assertEqual(report['protectedFileWriteAttempts'],1);self.assertIsNone(report['protectedFileWrites'])
        self.assertTrue(report['privateWriteOutcomeRequiresReconciliation']);self.assertTrue(report['publicationOutcomeRequiresReconciliation'])

if __name__=='__main__':unittest.main()
