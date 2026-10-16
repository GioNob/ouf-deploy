import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('reader',ROOT/'scripts/read-chatbot-semantic-denial-20261016.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class ReaderTests(unittest.TestCase):
    def test_expired_stopped_delivery_does_not_require_renewal_or_print_secrets(self):
        p={'postGrantWorkerDirectory':'/fixture/worker'}
        declaration={'sourceCommit':m.SOURCE}
        process={'unit':m.UNIT,'authorityDirectory':str(m.CONTEXT),
                 'bundle':{'path':'/fixture/bundle','sha256':'a'*64}}
        scopes={'finiteActionProcess':process,'policyTokenOwnerInstallation':{'journalPath':'/fixture/worker'}}
        review={'sourceClosure':{'declaration':declaration,'executables':{'systemctl':{},'docker':{}}},
                'scopes':scopes,'privateInputHashes':{'preparedInputs':m.digest(p)}}
        authority={**scopes,'expiresAt':1}
        bundle={'prepared':p,'declaration':declaration}
        status={'authorityHash':m.AUTHORITY,'phase':'PAUSED_REQUIRES_RECONCILIATION','private':'DO_NOT_PRINT'}
        rows={'review.json':review,'authority.json':authority,'bundle':bundle,'delivery-status.json':status,
              'recovery.json':{'state':'CANCELLED','attempts':1,'controlledCumulativeGrantAttempts':11,'token':'DO_NOT_PRINT'},
              'owner-session.json':{'state':'EXHAUSTED'},'owner-admission.json':{'state':'BLOCKED'},
              'owner-status.json':{'state':'CANCELLED','attempts':1}}
        def read(path,*args):return rows[Path(path).name]
        stopped={'ActiveState':'inactive','MainPID':'0'}
        output=io.StringIO()
        with patch.object(m,'read',side_effect=read),patch.object(m,'service_state',return_value=stopped),\
             patch.object(m,'executable',return_value='/usr/bin/docker'),\
             patch.object(m,'bounded',return_value=(0,b'STALE_POLICY_BUNDLE DO_NOT_PRINT',b'',38)),\
             patch.object(m.os,'geteuid',return_value=0),patch.object(m.sys,'flags',type('Flags',(),{'isolated':1})),\
             patch.object(m.signal,'alarm'),contextlib.redirect_stdout(output):
            m.main()
        raw=output.getvalue();self.assertNotIn('DO_NOT_PRINT',raw)
        result=[json.loads(line)for line in raw.splitlines()]
        self.assertTrue(result[-1]['complete'])
        self.assertTrue(next(r for r in result if r['check']=='DELIVERY')['authorityExpiredAtRead'])
        worker=next(r for r in result if r['check']=='WORKER')
        self.assertEqual(worker['controlledCumulativeGrantAttempts'],11)
        self.assertFalse(worker['liveStateProven'])
        self.assertEqual(next(r for r in result if r['check']=='REGISTRY_LOG_SAMPLE')['markerCounts']['STALE_POLICY_BUNDLE'],1)

    def test_untrusted_status_values_and_boolean_counters_block(self):
        for row in ({'reason':'secret value'},{'attempts':True},{'attempts':-1}):
            with self.assertRaises(m.ReadDenied):m.safe_status(row)

    def test_unknown_cumulative_count_is_not_inferred(self):
        self.assertEqual(m.safe_status({'attempts':2,'priorAttempts':10}),{'attempts':2})

    def test_log_markers_are_bounded_tokens(self):
        row=m.log_markers(b'STALE_POLICY_BUNDLE_SUFFIX STALE_POLICY_BUNDLE\nSEM_CAPABILITY_REQUIRED:ouf.semantic.propose')
        self.assertEqual(row['STALE_POLICY_BUNDLE'],1)
        self.assertEqual(row['SEM_CAPABILITY_REQUIRED:ouf.semantic.propose'],1)

    def test_native_subprocess_output_bound_and_drain(self):
        with self.assertRaises(m.ReadDenied):
            m.bounded([sys.executable,'-c','print("x"*5000)'],maximum=100)
        code,out,err,count=m.bounded([sys.executable,'-c','import sys; print("ok"); print("err",file=sys.stderr)'])
        self.assertEqual((code,out,err,count),(0,b'ok\n',b'err\n',3))

if __name__=='__main__':unittest.main()
