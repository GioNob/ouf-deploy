"""Real Docker generations and exact sealed GET-only capture after a stopped prefix.

HUMAN/Owner are explicit fixtures. Expiry/stop is modeled after real APPLIED
stages; no production source or isolated capsule is patched in the child.
"""
import copy,hashlib,json,os,subprocess,sys,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_readiness_patch_successor_platform as base
import test_readiness_patch_operator_delivery as tty
from tools.ingestion_readiness_patch_execution import stage8_live_delivery as d,stopped_patch_snapshot as snap,entry_v2 as e

@unittest.skipUnless(os.environ.get('OUF_ISOLATED_NATIVE_PLATFORM')=='1','explicit disposable platform required')
class Stage8CapturePlatform(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base.WholeControllerPlatform.setUpClass()
        cls.addClassCleanup(base.WholeControllerPlatform.doClassCleanups)
    def test_real_replacement_old_generation_and_four_unchanged_apps_plus_pg(self):
        f=base.WholeControllerPlatform();f.setUp();self.addCleanup(f.doCleanups)
        f.call('review',str(f.profile));review=json.loads((f.target/'review.json').read_bytes())
        tty.OperatorDelivery.tty_approve(f,'APPROVO '+e.c.digest(review));f.call('initialize')
        n=next(i+1 for i,s in enumerate(review['executionReview']['stages'])if s['name']=='ingestion.START_REPLACEMENT')
        for _ in range(n):f.call('step')
        # Explicit fixture stop/expiry: metadata-only reader never authenticates
        # or treats this old authority as current. No stage is replayed.
        native=e.Journal(f.target);row=native.read();expired=time.time()-10
        native.compare_and_save(row,{**row,'expiresAt':expired,'expiresMonotonic':time.monotonic()-10})
        control=e.Journal(f.target/'operator-control');r=control.read()
        control.compare_and_save(r,{**r,'state':'RECONCILE_REQUIRED'})
        sc={'contextPath':str(f.target),'runtimeCaseHash':e.c.digest(f.case),'nextStage':n,
            'readAttempts':native.read()['readAttempts'],'recordedExpiresAt':expired}
        case={'schema':'ouf.ingestion-readiness-stage8-live-input-case.v1','snapshotCase':sc,
            'expectedSnapshot':snap.inspect(sc),'readerSourceHash':hashlib.sha256((ROOT/'tools/ingestion_readiness_patch_execution/stage8_live_inputs.py').read_bytes()).hexdigest()}
        raw,decl=d.generate(ROOT,case);p=f.root/'live-capture.py';p.write_bytes(raw)
        before={str(p):p.read_bytes()for p in f.target.rglob('*')if p.is_file()}
        value=subprocess.run(['/usr/bin/python3','-I','-B','-S',str(p),'prepare'],capture_output=True,text=True,timeout=260)
        self.assertEqual(value.returncode,0,value.stdout+value.stderr)
        result=json.loads(value.stdout);self.assertEqual(result['engineGets'],14)
        self.assertTrue(result['replacementGenerationMatched']);self.assertFalse(result['applicationReadinessReverified'])
        self.assertEqual(result['remainingStages'],4)
        self.assertEqual(before,{str(p):p.read_bytes()for p in f.target.rglob('*')if p.is_file()})
        again=subprocess.run(['/usr/bin/python3','-I','-B','-S',str(p),'prepare'],capture_output=True,text=True,timeout=260)
        self.assertEqual(again.returncode,2);self.assertIn('ALREADY_CLAIMED',again.stdout)
        print('OUF_STAGE8_LIVE_CAPTURE_PROOF='+json.dumps({'complete':True,'engineGets':14,'engineWrites':0,
            'sealedSourceModules':decl['moduleCount'],'oldPrefixBytesUnchanged':True,'remainingStages':4,
            'fixtureAppliedStages':n,'targetAppliedStages':8,'syntheticStopAndExpiry':True,
            'syntheticHumanAndOwner':True,'targetEvidence':False}),flush=True)

if __name__=='__main__':unittest.main()
