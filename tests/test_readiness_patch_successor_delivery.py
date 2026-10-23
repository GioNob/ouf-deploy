"""Build-only exact successor and real isolated144-module admission failures.

Qualification references here are explicitly synthetic fixtures, not CI proof.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT)]
from tools.ingestion_readiness_patch_execution import production_successor as p,operator_delivery_v2 as d

class SuccessorDelivery(unittest.TestCase):
    def qualification(self):
        return {'sourceCommit':'1'*40,'runId':1,'pythonJobs':[{'id':1,'python':v,'tests':105,'skipped':0,
            'conclusion':'success'}for v in ('3.12','3.13.5')],
            'platformJob':{'id':1,'tests':5,'skipped':0,'conclusion':'success'}}
    def test_build_reproduces_and_binds_exact_stopped_journal_without_target_io(self):
        q=self.qualification();files,pins=p.build(ROOT,q)
        self.assertEqual(files,p.build(ROOT,q)[0]);self.assertFalse(pins['newBudgetGranted'])
        self.assertEqual(pins['currentCumulativeOAuthAttempts'],296)
        self.assertEqual(pins['maximumCumulativeOAuthAttempts'],296)
        self.assertEqual(pins['predecessorJournalHash'],'af07734945f3b4ea93282f43808634501d4633261617d767b1bfa2f68942c910')
        case=json.loads(files['releases/ingestion-readiness-successor-runtime-case-20261022.json'])
        self.assertEqual(case['requiredCumulativeOAuthAttempts'],300)
        self.assertEqual(case['predecessorResult']['retainedState'],'ISSUING')
        with tempfile.TemporaryDirectory()as folder:
            capsule=Path(folder)/'runtime.py';capsule.write_bytes(files['scripts/ingestion-readiness-successor-runtime-20261022.py'])
            # Full sealed imports must succeed before exact target absence stops.
            result=subprocess.run([sys.executable,'-I','-B','-S',str(capsule),'preflight'],capture_output=True,text=True)
            self.assertEqual(result.returncode,2,result.stdout+result.stderr)
            value=json.loads(result.stdout);self.assertEqual(value['status'],'STOP_RECONCILE')
            self.assertNotIn(value['reasonCode'],('SEALED_INSTALLER_IMPORT_FAILED','INSTALLER_DEPENDENCY_OUTSIDE_CLOSURE'))
        setup=files['scripts/prepare-ingestion-readiness-successor-20261022.sh']
        self.assertIn(b'bash \"$ouf_cache/runtime.sh\" preflight',setup)
        self.assertNotIn(b'bash \"$ouf_cache/human.sh\" prepare',setup)
        for name,raw in files.items():
            if name.endswith('.sh'):
                check=subprocess.run(['bash','-n'],input=raw,capture_output=True)
                self.assertEqual(check.returncode,0,check.stderr.decode())
    def test_exact_qualified_production_files_and_case_pins_reproduce(self):
        pins=json.loads((ROOT/'evidence/ingestion-readiness-successor-production-pins-20261022.json').read_bytes())
        files,current=p.build(ROOT,pins['qualification'])
        self.assertEqual(pins,current)
        for name,raw in files.items():self.assertEqual((ROOT/name).read_bytes(),raw,name)
        self.assertEqual(current['qualification']['sourceCommit'],'e776de2a261c7ce2318bcf6e6df5cf82d1028f6e')

    def test_incomplete_qualification_cannot_publish_successor(self):
        for key in ('pythonJobs','platformJob','sourceCommit'):
            q=self.qualification();q.pop(key)
            with self.assertRaises(ValueError):p.build(ROOT,q)
        q=self.qualification();q['platformJob']['conclusion']='failure'
        with self.assertRaises(ValueError):p.build(ROOT,q)

if __name__=='__main__':unittest.main()
