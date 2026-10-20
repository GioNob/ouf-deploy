"""Owner control component: synthetic process/HTTP under real role/CAS gates.

No backend acceptance, namespace transport, current target identity or authority
is inferred from these unit fixtures.
"""
import copy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),
             str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.ingestion_rollout_execution import owner_read as o
from tools.ingestion_rollout_execution import contract as c
from test_ingestion_rollout_gateway_transport import binding

def profile(file,program=None):
    active={'installationId':'ente-fixture','revision':7,'checksum':'c'*64,'generation':9}
    active['etag']='"7:'+active['checksum']+':9"'
    return {'schema':'ouf.ingestion-rollout-owner-local-namespace-http.v1',
        'runtimeBinding':{'containerId':'a'*64,'imageId':'sha256:'+'b'*64,'pid':42,'startedAt':'fixture-first-start',
                          **dict.fromkeys(('configHash','hostConfigHash','mountsHash','networkSettingsHash'),'d'*64)},
        'restartCount':3,'networkNamespace':{'device':1,'inode':2},'endpoint':{'host':'127.0.0.2','port':18080},
        'pythonExecutable':program or {'path':'/fixture/ente-python','sha256':'e'*64},
        'installationId':'ente-fixture','expectedActive':active,
        'expectedPayload':{'installationId':'ente-fixture','fixture':'retained-payload'},'projection':binding(file)}

class OwnerProfile(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)))
        self.addCleanup(self.temp.cleanup);self.file=Path(self.temp.name)/'projection'
        self.file.write_bytes(b'fixture retained projection');self.file.chmod(0o600);self.profile=profile(self.file)
    def test_explicit_ente_endpoint_runtime_restart_count_and_projection_are_bound(self):
        self.assertEqual(o.validate_profile(self.profile),self.profile)
        other=copy.deepcopy(self.profile);other['endpoint']={'host':'::1','port':28080}
        other['pythonExecutable']['path']='/different-ente/python'
        self.assertEqual(o.validate_profile(other),other);self.assertNotEqual(c.digest(self.profile),c.digest(other))
    def test_incomplete_runtime_weak_etag_remote_endpoint_or_implicit_port_blocks(self):
        mutations=[lambda p:p['runtimeBinding'].pop('mountsHash'),lambda p:p.pop('restartCount'),
                   lambda p:p['expectedActive'].update(etag='W/'+p['expectedActive']['etag']),
                   lambda p:p['expectedActive'].update(revision=True),
                   lambda p:p['endpoint'].update(host='192.0.2.1'),
                   lambda p:p['endpoint'].pop('port'),lambda p:p.update(extra=True)]
        for mutate in mutations:
            p=copy.deepcopy(self.profile);mutate(p)
            with self.assertRaises(c.Denied):o.validate_profile(p)
    def test_active_response_numeric_types_cannot_alias_booleans(self):
        value={'status':200,'body':{k:v for k,v in self.profile['expectedActive'].items()if k!='etag'},
               'etag':self.profile['expectedActive']['etag']}
        for field in('revision','generation'):
            changed=copy.deepcopy(value);changed['body'][field]=True
            with self.assertRaises(c.Denied):o.validate_active_result(changed)
    def test_closed_child_has_no_owner_write_or_projection_export_path(self):
        valid={'host':'127.0.0.2','port':18080,'path':'/api/trusted-human/v1/installations/ente-fixture/active',
               'bearer':'fixture.bearer.value','correlation':'a'*64}
        mutations=[{'path':'/api/trusted-human/v1/installations/ente-fixture/projection?revision=7'},
                   {'path':'/api/trusted-human/v1/installations/ente-fixture/revisions/7:activate'},
                   {'method':'POST'},{'host':'192.0.2.1'},{'port':False},{'bearer':'contains whitespace'},
                   {'path':'/api/trusted-human/v1/installations/../active'}]
        for change in mutations:
            r=subprocess.run([sys.executable,'-I','-B','-S','-c',o.CHILD_SOURCE,'0'],
                             input=c.encoded({**valid,**change}),capture_output=True,timeout=5,check=False)
            self.assertNotEqual(r.returncode,0);self.assertEqual(r.stdout,b'');self.assertEqual(r.stderr,b'')

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','real root role signatures and persistent CAS required')
class SignedOwnerControl(unittest.TestCase):
    def setUp(self):
        import test_ingestion_rollout_execution as core
        self.temp=tempfile.TemporaryDirectory(dir=os.environ['OUF_TEST_ROOT']);self.addCleanup(self.temp.cleanup)
        self.projection=Path(self.temp.name)/'projection';self.projection.write_bytes(b'fixture retained projection')
        self.projection.chmod(0o600)
        self.profile=profile(self.projection,o.governance.executable(os.environ.get('OUF_TEST_PYTHON',sys.executable)))
        original=core.review_fixture
        def fixture(context='/fixture/execution',key_path=None):
            review,packet,inputs=original(context,key_path)
            review['ownerControlProfile']=copy.deepcopy(self.profile);review['maximumOwnerGetAttempts']=o.MAX_GETS
            return review,packet,inputs
        with patch.object(core,'review_fixture',side_effect=fixture):core.SignedFiniteRunner.setUp(self)
        from tools.chatbot_file_cohort.human_session import HumanSession
        self.human=HumanSession.__new__(HumanSession)
        self.human.current=lambda:self.scope['humanBinding']
        self.pin=o.OwnerNamespacePin.__new__(o.OwnerNamespacePin);self.pin.profile=copy.deepcopy(self.profile)
        # The held fixture file FD is not a network namespace. No child is run
        # by these protocol tests; actual namespace qualification is separate.
        self.pin.fd=os.open(self.projection,os.O_RDONLY);self.addCleanup(os.close,self.pin.fd)
        self.current_generation=True
        self.pin.check=lambda:c.require(self.current_generation,'SYNTHETIC_OWNER_GENERATION_CHANGED')
        self.native=o.NativeOwnerRead(self.action,self.runner.journal,self.review,self.human,self.pin)
        self.gets=[];self.drift=None
        def get(suffix):
            self.native.reserve();self.gets.append(suffix);active=self.profile['expectedActive']
            if suffix=='/active':
                value={'status':200,'body':{k:v for k,v in active.items()if k!='etag'},'etag':active['etag']}
                if self.drift=='etag':value['etag']='W/'+value['etag']
                if self.drift=='generation'and len(self.gets)>1:value['body']['generation']+=1
                return value
            payload=copy.deepcopy(self.profile['expectedPayload'])
            if self.drift=='payload':payload['foreign']=True
            return {'status':200,'etag':'','body':{'installationId':active['installationId'],'revision':active['revision'],
                'checksum':active['checksum'],'validationState':'VALIDATED','validationFindings':[],'payload':payload}}
        self.native.get=get
    def test_three_current_gets_preserve_owner_and_projection_without_authority(self):
        before=self.projection.read_bytes();proof=self.native.verify()
        self.assertEqual(self.gets,['/active','/revisions/7','/active'])
        self.assertEqual(self.runner.record()['nativeOwnerGetAttempts'],3);self.assertEqual(before,self.projection.read_bytes())
        self.assertEqual(proof['ownerMutations'],0);self.assertEqual(proof['projectionExports'],0)
        self.assertFalse(proof['runtimeAuthorityIssued']);self.assertNotIn('checksum',proof)
    def test_changed_owner_payload_etag_or_generation_blocks(self):
        for drift in('etag','payload','generation'):
            self.drift=drift;self.gets=[]
            with self.subTest(drift=drift),self.assertRaises(c.Denied):self.native.verify()
    def test_projection_replacement_and_runtime_drift_block(self):
        self.projection.write_bytes(b'changed projection')
        with self.assertRaises(c.Denied):self.native.verify()
        self.current_generation=False;self.gets=[]
        with self.assertRaises(c.Denied):self.native.verify()
        self.assertEqual(self.gets,[])
    def test_owner_get_budget_retained_after_exhaustion(self):
        row=self.runner.record();self.runner.journal.compare_and_save(row,{**row,'nativeOwnerGetAttempts':511,'version':row['version']+1})
        self.native.reserve();self.assertEqual(self.runner.record()['nativeOwnerGetAttempts'],512)
        for unused in range(2):
            with self.assertRaises(c.Denied):self.native.reserve()
        self.assertEqual(self.runner.record()['nativeOwnerGetAttempts'],512)
    def test_revoked_role_or_changed_profile_blocks_before_get(self):
        self.native.profile['endpoint']['port']+=1
        with self.assertRaises(c.Denied):self.native.verify()
        self.assertEqual(self.gets,[]);self.native.profile=copy.deepcopy(self.review['ownerControlProfile'])
        policy=__import__('json').loads(self.crypto.policy.read_bytes());policy['keys'][0]['state']='REVOKED'
        self.crypto.write(self.crypto.policy,c.encoded(policy))
        with self.assertRaises(Exception):self.native.verify()
        self.assertEqual(self.gets,[])
    def test_invalid_namespace_child_consumes_read_budget_without_retry(self):
        # Execute the sealed child against our deliberately non-namespace FD.
        # It must fail before HTTP and retain its reservation. HUMAN/process
        # observations remain synthetic; the real role gate is not mocked.
        row=self.runner.record()
        self.runner.journal.compare_and_save(row,{**row,'expiresMonotonic':time.monotonic()+240,'version':row['version']+1})
        self.native.token=lambda:'fixture.bearer.value'
        with self.assertRaises(c.Denied):o.NativeOwnerRead.get(self.native,'/active')
        self.assertEqual(self.runner.record()['nativeOwnerGetAttempts'],1)

if __name__=='__main__':unittest.main()
