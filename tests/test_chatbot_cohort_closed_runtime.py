"""Actual isolated imports of every source in the complete action closure."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
PATH=ROOT/'tools/chatbot_file_cohort/runtime.py'
spec=importlib.util.spec_from_file_location('cohort_runtime_qualification',PATH)
runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)


class CompleteSourceClosure(unittest.TestCase):
    def sources(self):
        owner=Path(os.environ.get('OUF_CHATBOT_ONBOARDING_ROOT',str(ROOT.parent/'onboarding-review-work')))
        paths=json.loads((ROOT/'tools/chatbot_file_cohort/source_paths.json').read_text())
        return {name:((owner/path.split(':',1)[1]) if path.startswith('ouf-onboarding:') else ROOT/path).read_bytes()
                for name,path in paths.items()}

    def run_native(self,alter=None):
        sources=self.sources();loader=PATH.read_bytes();pins={'ouf-deploy':'a'*40,'ouf-onboarding':'b'*40}
        declaration=runtime.declaration('a'*40,sources,loader,pins)
        payload={'sources':{name:base64.b64encode(raw).decode() for name,raw in sources.items()},
                 'loader':base64.b64encode(loader).decode(),'pins':pins,'hash':runtime.digest(declaration),'alter':alter}
        script=r'''
import base64,json,sys,types
p=json.loads(sys.stdin.buffer.read(8388609));raw=base64.b64decode(p['loader']);loader=types.ModuleType('closed_loader')
exec(compile(raw,'qualified-full-action-loader','exec'),loader.__dict__)
sources={n:base64.b64decode(v) for n,v in p['sources'].items()}
if p['alter']=='hash':sources['tools.chatbot_file_cohort.delivery']+=b'\n# unqualified change\n'
if p['alter']=='preloaded':sys.modules['tools']=types.ModuleType('tools')
try:
 entry,manifest=loader.load_entry('a'*40,sources,raw,p['hash'],p['pins'])
 assert entry.HumanSession is sys.modules['tools.chatbot_file_cohort.human_session'].HumanSession
 assert entry.AggregateAction is sys.modules['tools.semantic_policy_token_owner.owner_installation'].AggregateAction
 assert entry.GatewayRuntime is sys.modules['tools.chatbot_file_cohort.gateway_runtime'].GatewayRuntime
 assert entry.public_failure_reason(entry.PlanDenied('ROLE_BASELINE_DRIFT'))=='ROLE_BASELINE_DRIFT'
 assert entry.public_failure_reason(entry.ImageCustodyDenied('NATIVE_IMAGE_IDENTITY_DRIFT'))=='NATIVE_IMAGE_IDENTITY_DRIFT'
 assert entry.public_failure_reason(ValueError('DO_NOT_PRINT_PRIVATE_VALUE'))=='ValueError'
 assert entry.public_failure_reason(RuntimeError('private value'))=='RuntimeError'
 print(json.dumps({'entry':entry.__name__,'modules':manifest['moduleCount'],'sameConcreteOwnerTypes':True}))
except Exception as e:
 print(json.dumps({'denied':str(e)}));raise SystemExit(1)
'''
        return subprocess.run([sys.executable,'-I','-B','-S','-c',script],input=json.dumps(payload).encode(),
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45)

    def test_actual_complete_isolated_no_site_import_with_shared_concrete_owner_types(self):
        result=self.run_native()
        self.assertEqual(result.returncode,0,result.stdout.decode()+result.stderr.decode())
        value=json.loads(result.stdout)
        self.assertEqual(value['modules'],len(runtime.MODULES))
        self.assertEqual(value['entry'],'tools.chatbot_file_cohort.delivery')
        self.assertTrue(value['sameConcreteOwnerTypes'])

    def test_changed_source_or_preloaded_namespace_is_denied_before_entry(self):
        for alter in ('hash','preloaded'):
            with self.subTest(alter=alter):
                result=self.run_native(alter)
                self.assertNotEqual(result.returncode,0,result.stdout.decode()+result.stderr.decode())
                self.assertIn('denied',json.loads(result.stdout))

    def test_missing_extra_and_foreign_import_are_closed(self):
        sources=self.sources()
        for alter in ('missing','extra','foreign'):
            changed=dict(sources)
            if alter=='missing':changed.pop('tools.chatbot_file_cohort.gateway_runtime')
            elif alter=='extra':changed['unreviewed_source']=b'pass'
            else:changed['tools.chatbot_file_cohort.delivery']+=b'\nimport unreviewed_dependency\n'
            with self.subTest(alter=alter),self.assertRaises(runtime.RuntimeDenied):runtime.compile_sources(changed)


if __name__=='__main__':unittest.main()
