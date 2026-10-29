"""Actual root-private journals; synthetic completed-stage peers, no runtime I/O."""
import copy,json,os,sys,subprocess,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_readiness_patch_successor_control as fixture
from tools.ingestion_readiness_patch_execution import stopped_patch_snapshot as s,stopped_patch_delivery as d

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','root private fixture required')
class StoppedSnapshot(unittest.TestCase):
    @classmethod
    def setUpClass(cls):fixture.OperatorControl.setUpClass()
    def setUp(self):
        self.f=fixture.OperatorControl();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.f.review();self.f.approve();self.f.call('initialize')
        with patch.object(fixture.e,'NativePorts',self.f.peers()):
            for _ in range(8):self.f.call('step')
        with patch.object(fixture.e,'execute',side_effect=OSError('explicit stopped fixture')):
            with self.assertRaises(OSError):self.f.call('step')
        row=fixture.e.Journal(self.f.target).read()
        self.case={'contextPath':str(self.f.target),'runtimeCaseHash':fixture.e.c.digest(self.f.case),
            'nextStage':8,'readAttempts':8,'recordedExpiresAt':row['expiresAt']}
    def test_read_only_prefix_and_exact_residual_stages(self):
        before={str(p):p.read_bytes()for p in self.f.target.rglob('*')if p.is_file()}
        value=s.inspect(self.case);self.assertEqual(value['nextStageName'],'ingestion.READINESS')
        self.assertEqual(len(value['remainingStages']),4);self.assertFalse(value['pendingStageClaim'])
        self.assertEqual(value['appliedStageCount'],8);self.assertEqual(value['engineRequests'],0)
        self.assertEqual(before,{str(p):p.read_bytes()for p in self.f.target.rglob('*')if p.is_file()})
    def test_changed_prefix_or_expiry_refused(self):
        for key,value in [('nextStage',9),('readAttempts',9),('recordedExpiresAt',1)]:
            case={**self.case,key:value}
            with self.assertRaises(Exception):s.inspect(case)
        p=self.f.target/'recovery.json';row=json.loads(p.read_bytes());row['effects'][0]['state']='CLAIMED'
        p.write_bytes(fixture.e.c.encoded(row))
        with self.assertRaises(Exception):s.inspect(self.case)
    def test_concurrent_native_invocation_or_wrong_custody_blocks(self):
        import fcntl
        fd=os.open(self.f.target/'invocation.lock',os.O_RDONLY)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):s.inspect(self.case)
        finally:os.close(fd)
        p=self.f.target/'review.json';p.chmod(0o400)
        with self.assertRaises(Exception):s.inspect(self.case)

    def test_real_isolated_cli_and_production_artifact_reproduce(self):
        raw=d.generate(ROOT,self.case);self.assertEqual(raw,d.generate(ROOT,self.case))
        p=self.f.root/'reader.py';p.write_bytes(raw)
        value=subprocess.run([sys.executable,'-I','-B','-S',str(p)],capture_output=True,text=True)
        self.assertEqual(value.returncode,0,value.stdout+value.stderr)
        self.assertEqual(json.loads(value.stdout)['nextStage'],8)
        case=json.loads((ROOT/'releases/ingestion-readiness-stopped-case-20261022.json').read_bytes())
        self.assertEqual(d.generate(ROOT,case),(ROOT/'scripts/read-ingestion-readiness-stopped-20261022.py').read_bytes())

if __name__=='__main__':unittest.main()
