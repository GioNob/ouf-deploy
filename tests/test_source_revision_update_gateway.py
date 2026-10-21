"""Actual pinned Gateway renderer/projector/schema bytes, no target transport."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.source_revision_update import gateway as g
from tools.source_revision_update.owner import UpdateDenied


class ProductionCompiler(unittest.TestCase):
    def setUp(self):
        owner = Path(os.environ['OUF_REVISION_GATEWAY_ROOT'])
        self.sources = {name:(owner/name).read_bytes() for name in g.WANTED}
        self.temp = tempfile.TemporaryDirectory(dir='/root'); self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name); self.directory.chmod(0o700)
        for name,raw in self.sources.items():
            path = self.directory/name; path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(raw); path.chmod(0o600)
        self.compiled = json.loads(Path(os.environ['OUF_REVISION_COMPILED_FIXTURE']).read_bytes())
        self.projection = json.loads((owner/'tests/fixtures/installation-projection-lab.json').read_bytes())
        projector = g.module(self.sources[g.WANTED[0]],'fixture_projector',self.directory/g.WANTED[0])
        runtime = projector.apply_projection(self.compiled,self.projection)
        identity = runtime['x-ouf-installation']
        constants = '\n'.join('local '+name+' = '+json.dumps(value) for name,value in {
            'ISSUER':identity['issuerUrl'],'AUDIENCE':identity['gatewayAudience'],
            'MCP_WORKLOAD':identity['mcpServiceIdentity'],'DELEGATION_KEY_ENV':'FIXTURE_DELEGATION_KEY'}.items())
        base = {'id':'execute','uri':'/internal/capabilities/v1/execute','methods':['POST'],'labels':{},
            'plugins':{'openid-connect':{},'limit-count':{},'request-validation':{},
            'serverless-pre-function':{'functions':[constants]}}}
        self.before = {'execute':base}
        for mode in ('review-prepare','review-read'):
            route = copy.deepcopy(base); route.update(id='mcp-managed-file-'+mode,
                uri='/internal/capabilities/v1/execute/managed.file/'+mode)
            route['plugins']['serverless-post-function'] = {'functions':['local OWNER_KEY_ENV = "FIXTURE_ONBOARDING_KEY"']}
            self.before[route['id']] = route
        self.before['trusted-human-onboarding-review'] = {'id':'trusted-human-onboarding-review',
            'uri':'/trusted-human/onboarding/*','upstream':{'nodes':{'ouf-onboarding:8080':1}}}

    def compile(self):
        return g.compile_routes(self.directory,self.sources,self.compiled,self.projection,self.before)

    def test_real_production_macro_adds_exactly_two_routes_and_keeps_human_boundary(self):
        before = copy.deepcopy(self.before); result = self.compile()
        self.assertEqual(self.before,before); self.assertTrue(result['existingRoutesPreserved'])
        self.assertEqual(len(result['afterRoutes']),len(before)+2)
        self.assertEqual({k:v for k,v in result['afterRoutes'].items() if k in before},before)
        for mode,route in result['additions'].items():
            self.assertEqual(route['id'],'mcp-source-revision-'+mode)
            self.assertEqual(route['upstream']['retries'],0)
            function = route['plugins']['serverless-post-function']['functions'][0]
            self.assertIn('ouf-source-revision-owner-v1.',function)
            self.assertIn('local OWNER_KEY_ENV = "FIXTURE_ONBOARDING_KEY"',function)
            self.assertEqual(route['plugins']['request-validation']['max_req_body_size'],65536)
        self.assertFalse(result['credentialValuesRead'])

    def test_installation_identity_drift_blocks_before_materialization(self):
        self.projection['gateway']['issuerUrl'] = 'https://unapproved.fixture.invalid/realms/changed'
        with self.assertRaisesRegex(UpdateDenied,'IDENTITY_CHANGED'): self.compile()

    def test_signing_reference_conflict_or_source_drift_blocks(self):
        route = self.before['mcp-managed-file-review-read']
        route['plugins']['serverless-post-function']['functions'] = ['local OWNER_KEY_ENV = "OTHER_KEY"']
        with self.assertRaisesRegex(UpdateDenied,'SIGNING_REFERENCES_CHANGED'): self.compile()
        (self.directory/g.WANTED[0]).write_bytes(b'changed')
        with self.assertRaisesRegex(UpdateDenied,'SOURCE_CHANGED'): self.compile()

    def test_exact_selector_collision_in_uris_is_also_rejected(self):
        self.before['collision'] = {'id':'collision','uris':['/internal/capabilities/v1/execute/source.revision/read']}
        with self.assertRaisesRegex(UpdateDenied,'SELECTOR_COLLISION'): self.compile()

    def test_archive_blob_custody_and_traversal_are_verified_before_execution(self):
        def archive(extra=False,changed=False):
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer,mode='w') as target:
                for name,raw in self.sources.items():
                    if changed and name == g.WANTED[0]: raw = b'changed'
                    row = tarfile.TarInfo(name); row.size = len(raw); target.addfile(row,io.BytesIO(raw))
                if extra:
                    row = tarfile.TarInfo('../escape'); row.size = 1; target.addfile(row,io.BytesIO(b'x'))
            return buffer.getvalue()
        inventory = {'truncated':False,'tree':[{'path':name,'mode':'100644',
            'sha':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()} for name,raw in self.sources.items()]}
        self.assertEqual(g.source_members(archive(),inventory),self.sources)
        for extra,changed in ((True,False),(False,True)):
            with self.assertRaises(UpdateDenied): g.source_members(archive(extra,changed),inventory)


if __name__ == '__main__': unittest.main()
