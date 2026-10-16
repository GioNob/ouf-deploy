"""Closed-source bootstrap and tamper checks; no installation or target calls."""
import base64
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
executor=module('token_bootstrap','scripts/execute-chatbot-semantic-token-session-20261016.py')
resume_executor=module('resume_token_bootstrap','scripts/continue-chatbot-semantic-token-session-20261016.py')
runtime=module('token_runtime','tools/chatbot_file_cohort/runtime.py')

class Bootstrap(unittest.TestCase):
    def test_actual_repository_modules_import_in_isolated_sealed_process(self):
        script='''import json,sys
from pathlib import Path
root=Path(sys.argv[1]);loader=(root/'tools/chatbot_file_cohort/runtime.py').read_bytes()
ns={'__name__':'sealed_native_qualification'};exec(compile(loader,'<loader>','exec'),ns)
paths=json.loads((root/'tools/chatbot_file_cohort/source_paths.json').read_bytes())
# The two external owner modules are import-only placeholders in THIS test.
# Production bootstrap retains their independently pinned original bytes.
sources={name:b'pass\\n' if path.startswith('ouf-onboarding:') else (root/path).read_bytes()for name,path in paths.items()}
pins={'ouf-deploy':'a'*40,'ouf-onboarding':'b'*40}
d=ns['declaration']('a'*40,sources,loader,pins)
ns['load_entry']('a'*40,sources,loader,ns['digest'](d),pins)
from tools.chatbot_file_cohort.continued_owner import token_only_session_main
from tools.chatbot_file_cohort.review import issue_token_action
from tools.chatbot_file_cohort.human_session import HumanSession
assert callable(token_only_session_main) and callable(issue_token_action)
assert callable(HumanSession.prepare_interrupted_login)
print('SEALED_TOKEN_ENTRY_IMPORTED_NO_ACTIONS')
'''
        result=subprocess.run([sys.executable,'-I','-B','-S','-c',script,str(ROOT)],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(result.stdout,b'SEALED_TOKEN_ENTRY_IMPORTED_NO_ACTIONS\n')

    def bundle(self):
        loader=(ROOT/'tools/chatbot_file_cohort/runtime.py').read_bytes()
        sources={name:b'pass\n'for name in runtime.MODULES}
        locations={
            'iam_binding_candidate':'tools/semantic_policy_token_owner/iam_binding_candidate.py',
            'migration_root_custody':'tools/semantic_policy_token_owner/migration_root_custody.py',
            **{name:name.replace('.','/')+'.py'for name in executor.OVERLAYS if name.startswith('tools.')}}
        sources.update({name:(ROOT/path).read_bytes()for name,path in locations.items()})
        value={'schema':'ouf.chatbot-file-cohort-closed-source-bundle.v1',
            'loader':base64.b64encode(loader).decode(),
            'sources':{name:base64.b64encode(raw).decode()for name,raw in sources.items()},
            'declaration':{'loaderHash':hashlib.sha256(loader).hexdigest(),
                'sourceHashes':{name:hashlib.sha256(raw).hexdigest()for name,raw in sources.items()}}}
        return value
    def test_all_six_overlays_fit_retained_closed_import_contract(self):
        loader,sources=executor.decode_sources(self.bundle())
        compiled=runtime.compile_sources(sources)
        self.assertEqual(set(compiled),runtime.MODULES)
        pins={'ouf-deploy':'a'*40,'ouf-onboarding':'b'*40}
        declaration=runtime.declaration('a'*40,sources,loader,pins)
        self.assertEqual(declaration['sourcePins'],pins)
    def test_changed_loader_body_or_source_body_denies_before_import(self):
        for what in ('loader','source','missing'):
            value=self.bundle()
            if what=='loader':value['loader']=base64.b64encode(b'pass\n').decode()
            if what=='source':value['sources']['iam_binding_candidate']=base64.b64encode(b'pass\n').decode()
            if what=='missing':value['sources'].pop('iam_binding_candidate')
            with self.assertRaises(executor.ReadDenied):executor.decode_sources(value)
    def test_executable_overlay_cannot_import_outside_reviewed_closure(self):
        _,sources=executor.decode_sources(self.bundle())
        sources['tools.chatbot_file_cohort.continued_owner']+=b'\nimport unreviewed_runtime_dependency\n'
        with self.assertRaises(runtime.RuntimeDenied):runtime.compile_sources(sources)

    def test_continuation_overlay_includes_real_human_state_machine_in_closed_sources(self):
        bundle=self.bundle();name='tools.chatbot_file_cohort.human_session'
        body=(ROOT/'tools/chatbot_file_cohort/human_session.py').read_bytes()
        bundle['sources'][name]=base64.b64encode(body).decode()
        bundle['declaration']['sourceHashes'][name]=hashlib.sha256(body).hexdigest()
        loader,sources=resume_executor.decode_sources(bundle)
        self.assertEqual(set(resume_executor.OVERLAYS),set(executor.OVERLAYS)|{name})
        runtime.compile_sources(sources)

if __name__=='__main__':unittest.main()
