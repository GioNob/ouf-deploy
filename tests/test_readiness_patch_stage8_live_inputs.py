"""Real private prefix/capture fences; synthetic GET/generation peers explicitly.

Full generation predicates are exercised separately on real Docker fixtures.
"""
import copy,hashlib,json,os,sys,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_readiness_patch_stopped_snapshot as stopped
from tools.ingestion_readiness_patch_execution import stage8_live_inputs as live,stage8_live_delivery as delivery

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','root private fixture required')
class LiveInputs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):stopped.StoppedSnapshot.setUpClass()
    def setUp(self):
        self.s=stopped.StoppedSnapshot();self.s.setUp();self.addCleanup(self.s.doCleanups)
        self.f=self.s.f;c=live.e.c;j=live.e.Journal(self.f.target);row=j.read()
        effects=copy.deepcopy(row['effects']);effects[6]['nativeResource']={'containerId':'c'*64}
        effects[7]['nativeResource']={'containerId':'c'*64,'pid':222,'startedAt':'synthetic-first-process'}
        j.compare_and_save(row,{**row,'effects':effects,'expiresAt':time.time()-10,'expiresMonotonic':time.monotonic()-10})
        self.s.case['recordedExpiresAt']=j.read()['expiresAt']
        self.case={'schema':live.SCHEMA,'snapshotCase':self.s.case,
            'expectedSnapshot':live.stopped_patch_snapshot.inspect(self.s.case),
            'readerSourceHash':hashlib.sha256((ROOT/'tools/ingestion_readiness_patch_execution/stage8_live_inputs.py').read_bytes()).hexdigest()}
        p=patch.object(live,'__qualified_source_sha256__',self.case['readerSourceHash'],create=True);p.start();self.addCleanup(p.stop)
        self.gets=[]
        def init(obj,path,binding):obj.path=path;obj.binding=binding
        def request(obj,method,path,body=None):self.gets.append((method,path,body));return 200,{'Id':path.split('/')[3]}
        for p in (patch.object(live.Engine,'__init__',init),patch.object(live.Engine,'check_socket'),
                  patch.object(live.Engine,'request',request),patch.object(live,'verify_rows',side_effect=lambda a,b,c,d,e,rows:copy.deepcopy(rows))):
            p.start();self.addCleanup(p.stop)
    def call(self):return live.execute('prepare',None,self.case,{},'d'*64)
    def test_one_use_fourteen_gets_preserves_old_bytes_and_no_credentials(self):
        before={str(p):p.read_bytes()for p in self.f.target.rglob('*')if p.is_file()}
        with patch.object(live.e.human_reader,'open_existing',side_effect=AssertionError('HUMAN read forbidden')):
            result=self.call()
        self.assertEqual(result['engineGets'],14);self.assertEqual(len(self.gets),14)
        self.assertTrue(all(m=='GET'and b is None for m,_,b in self.gets))
        self.assertEqual(len(set(p for _,p,_ in self.gets)),7)
        self.assertEqual(before,{str(p):p.read_bytes()for p in self.f.target.rglob('*')if p.is_file()})
        with self.assertRaises(Exception):self.call()
        self.assertEqual(len(self.gets),14)
        self.assertEqual(live.custody.read(result['contextPath']+'/recovery.json')['state'],'COMPLETE')
    def test_lost_get_keeps_partial_claim_and_cannot_replay(self):
        with patch.object(live.Engine,'request',side_effect=OSError('synthetic lost GET')):
            with self.assertRaises(OSError):self.call()
        with self.assertRaises(Exception):self.call()
        target=self.f.root/('ingestion-readiness-stage8-live-inputs-'+live.e.c.digest(self.case))
        self.assertEqual(live.custody.read(str(target/'recovery.json'))['engineGets'],1)
    def test_drift_or_foreign_snapshot_blocks_before_engine_and_claim(self):
        self.case['expectedSnapshot']['prefixHash']='f'*64
        with self.assertRaises(Exception):self.call()
        self.assertEqual(self.gets,[])
        self.assertFalse(list(self.f.root.glob('ingestion-readiness-stage8-live-*.claim.json')))
    def test_sealed_capsule_deterministic_and_invalid_mode_has_no_effects(self):
        import subprocess
        raw,decl=delivery.generate(ROOT,self.case);self.assertEqual(raw,delivery.generate(ROOT,self.case)[0])
        p=self.f.root/'capture.py';p.write_bytes(raw)
        result=subprocess.run([sys.executable,'-I','-B','-S',str(p),'step'],capture_output=True,text=True)
        self.assertEqual(result.returncode,2,result.stdout+result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'],'STOP_RECONCILE');self.assertEqual(self.gets,[])
    def test_exact_production_case_and_capsule_reproduce(self):
        case=json.loads((ROOT/'releases/ingestion-readiness-stage8-live-case-20261022.json').read_bytes())
        raw,decl=delivery.generate(ROOT,case)
        self.assertEqual(raw,(ROOT/'scripts/capture-ingestion-readiness-stage8-live-20261022.py').read_bytes())
        pins=json.loads((ROOT/'evidence/ingestion-readiness-stage8-live-pins-20261022.json').read_bytes())
        self.assertEqual(pins['artifactSha256'],hashlib.sha256(raw).hexdigest())
        self.assertEqual(pins['sealedSourceModules'],decl['moduleCount'])
        self.assertFalse(pins['newBudgetGranted']);self.assertFalse(pins['targetCommandExecuted'])
        sh=delivery.launcher(raw)
        self.assertEqual(sh,(ROOT/pins['launcher']['path']).read_bytes())
        self.assertNotIn(b'grant-budget',sh)
        import subprocess
        self.assertEqual(subprocess.run(['bash','-n'],input=sh,capture_output=True).returncode,0)

if __name__=='__main__':unittest.main()
