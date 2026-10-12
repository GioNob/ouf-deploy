"""Actual private capture-to-scope derivation; fixture sources/installation only."""
import json,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover')]
import test_coordination_input_capture as capture_fixture
m,custody,atomic=capture_fixture.m,capture_fixture.custody,capture_fixture.atomic
import r12_retirement_scope as scope
from transition_journal import digest

class Scope(unittest.TestCase):
    def fixture(self):
        base,p,secret=capture_fixture.Capture.fixture(self)
        def write(path,v):path.write_bytes(m.encoded(v));path.chmod(0o600)
        for i in range(14):
            path=p.R12/('fixture'+str(i)+'.py');path.write_bytes(b'# source bytes not executed\n');path.chmod(0o600);p.R12_PROGRAMS[path.name]=m.sha(path.read_bytes())
        auth=json.loads((p.R12/'authorization.json').read_bytes());auth.update(programHashes=p.R12_PROGRAMS,serviceUnit=scope.UNIT)
        auth.pop('contextRef');auth['contextRef']=digest(auth);write(p.R12/'authorization.json',auth)
        ah=m.sha((p.R12/'authorization.json').read_bytes());q=patch.object(m,'R12_AUTH_HASH',ah);q.start();self.addCleanup(q.stop)
        for path in (p.R12/'worker-invocation-claim.json',p.R12/'retry/recovery.json'):
            v=json.loads(path.read_bytes());v['contextRef']=auth['contextRef'];write(path,v)
        files,bindings=m.collect(p,custody)
        manifest={'schema':'ouf.native-v11-atomic-review-intake.v1','collectionKind':'EXISTING_COORDINATOR_AND_CUMULATIVE_HISTORY_INPUTS','fileHashes':{n:m.sha(raw) for n,raw in files.items()},'bindings':bindings,'runtimeAuthorityIssued':False,'applicationCutoverAuthorized':False,'productionApplyReady':False,'observationsAreHistorical':True}
        result=atomic.publish(base,files,manifest,0)
        for k,v in {'BASE':base,'R12':p.R12,'GUARD':base/'guard','CONTEXT':base/'context','CLAIM':str(p.R12_CLAIM),'EXPECTED_AUTH':ah,'EXPECTED_OWNER':m.COORDINATOR_HASH,'EXPECTED_EXECUTION':bindings['executionConfigurationHash']}.items():
            q=patch.object(scope,k,v);q.start();self.addCleanup(q.stop)
        intake={'path':str(Path(result['directory'])/'intake.json'),'sha256':result['intakeHash']}
        return intake,p,secret
    def test_derives_current_original_bindings_from_private_capture_without_key_reads(self):
        intake,p,secret=self.fixture();reads=[];original=custody.file_bytes
        def read(path,*args,**kwargs):reads.append(Path(path));return original(path,*args,**kwargs)
        with patch.object(custody,'file_bytes',side_effect=read):derived=scope.derive(intake,custody,p.R12_PROGRAMS)
        self.assertEqual(derived['workerPid'],1234);self.assertEqual(derived['authorizationBinding']['path'],str(p.R12/'authorization.json'));self.assertEqual(len(derived['programHashes']),15)
        self.assertNotIn(secret,reads);self.assertEqual(derived['executionBinding']['sha256'],scope.EXPECTED_EXECUTION)
    def test_changed_capture_or_unreviewed_program_set_does_not_derive_scope(self):
        intake,p,secret=self.fixture()
        with self.assertRaises(ValueError):scope.derive(intake,custody,{})
        path=Path(intake['path']);raw=path.read_bytes();path.write_bytes(raw+b'\n')
        with self.assertRaises(ValueError):scope.derive(intake,custody,p.R12_PROGRAMS)
    def test_historical_capture_never_becomes_self_issued_runtime_authority(self):
        intake,p,secret=self.fixture();path=Path(intake['path']);manifest=json.loads(path.read_bytes());manifest['runtimeAuthorityIssued']=True
        raw=m.encoded(manifest);path.write_bytes(raw);forged={'path':str(path),'sha256':m.sha(raw)}
        with self.assertRaises(ValueError):scope.derive(forged,custody,p.R12_PROGRAMS)

if __name__=='__main__':unittest.main()
