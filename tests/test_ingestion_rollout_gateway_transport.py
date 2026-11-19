"""Actual file custody and closed child protocol; no target or runtime gate.

No native Docker/APISIX claim is made by these component tests. The sealed child
is executed only with rejected inputs here, before setns/network access.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_policy_token_owner'),
             str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.ingestion_rollout_execution import private_file as f
from tools.ingestion_rollout_execution import gateway_transport as g
from tools.ingestion_rollout_execution import contract as c

def binding(p):
    p=Path(p);s=p.stat();ancestors=[]
    for parent in reversed(p.parents):
        row=parent.stat()
        ancestors.append({'path':str(parent),'identity':[row.st_dev,row.st_ino,row.st_uid,row.st_gid,row.st_mode]})
    return {'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'metadata':f.metadata(s),
            'ancestors':ancestors}

class ProfileAndCustody(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)))
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.file=self.root/'selected-config';self.file.write_bytes(b'private fixture configuration');self.file.chmod(0o600)
        self.binding=binding(self.file)
    def profile(self,port=9280):
        return {'schema':'ouf.ingestion-rollout-gateway-transport.v1','endpoint':{'host':'127.0.0.2','port':port},
                'pythonExecutable':{'path':'/fixture/ente-python','sha256':'a'*64},
                'config':copy.deepcopy(self.binding),'adminKey':None}
    def test_read_uses_complete_explicit_custody_without_named_ente_exception(self):
        self.assertEqual(f.read(self.binding),b'private fixture configuration')
        profile=self.profile();self.assertEqual(g.validate_profile(profile),profile)
        other=copy.deepcopy(profile);other['endpoint']={'host':'::1','port':19380}
        other['pythonExecutable']['path']='/different-ente/qualified-python'
        self.assertEqual(g.validate_profile(other),other)
        self.assertNotEqual(c.digest(profile),c.digest(other))
    def test_replacement_inode_even_with_same_bytes_is_rejected(self):
        old=self.file.with_name('retained');self.file.rename(old)
        self.file.write_bytes(old.read_bytes());self.file.chmod(0o600)
        with self.assertRaises(c.Denied):f.read(self.binding)
    def test_changed_bytes_and_restored_mtime_are_rejected(self):
        before=self.file.stat();self.file.write_bytes(b'x'*before.st_size)
        os.utime(self.file,ns=(before.st_atime_ns,before.st_mtime_ns))
        with self.assertRaises(c.Denied):f.read(self.binding)
    def test_symlink_and_hardlink_are_rejected(self):
        target=self.file.with_name('original');self.file.rename(target);self.file.symlink_to(target)
        with self.assertRaises((c.Denied,OSError)):f.read(self.binding)
        self.file.unlink();self.file.hardlink_to(target)
        with self.assertRaises(c.Denied):f.read(self.binding)
    def test_parent_permission_drift_and_profile_omission_are_rejected(self):
        self.root.chmod(0o777)
        with self.assertRaises(c.Denied):f.read(self.binding)
        self.root.chmod(0o700)
        changed=copy.deepcopy(self.binding);changed['ancestors']=changed['ancestors'][1:]
        with self.assertRaises(c.Denied):f.read(changed)
    def test_world_or_group_writable_file_or_parent_profile_is_never_accepted(self):
        for target in('file','parent'):
            changed=copy.deepcopy(self.binding)
            if target=='file':changed['metadata'][4]|=0o020
            else:changed['ancestors'][-1]['identity'][4]|=0o020
            with self.subTest(target=target),self.assertRaises(c.Denied):f.validate(changed)
    def test_incomplete_extra_remote_or_implicit_transport_is_rejected(self):
        mutations=[
            lambda p:p.pop('endpoint'),
            lambda p:p.update(extra=True),
            lambda p:p['endpoint'].update(host='gateway.example.invalid'),
            lambda p:p['endpoint'].update(host='192.0.2.1'),
            lambda p:p['endpoint'].update(port=True),
            lambda p:p['endpoint'].update(port=0),
            lambda p:p['endpoint'].update(port=65536),
            lambda p:p['pythonExecutable'].update(path='../python'),
            lambda p:p['config'].pop('ancestors'),
        ]
        for i,mutate in enumerate(mutations):
            changed=self.profile();mutate(changed)
            with self.subTest(case=i),self.assertRaises(c.Denied):g.validate_profile(changed)
    def test_retry_after_retains_provider_floor_and_rejects_invalid_headers(self):
        self.assertEqual(g.retry_after_seconds('1000',now=0),1000.)
        self.assertEqual(g.retry_after_seconds('Thu, 01 Jan 1970 00:01:00 GMT',now=20),40.)
        self.assertEqual(g.retry_after_seconds('Thu, 01 Jan 1970 00:00:00 GMT',now=20),0.)
        for value in('-1','NaN','1.5','bad date','10\r\nInjected:x'):
            with self.subTest(value=value),self.assertRaises(c.Denied):g.retry_after_seconds(value,now=0)
    def test_closed_child_rejects_foreign_operation_and_endpoint_before_namespace(self):
        valid={'method':'GET','path':'/apisix/admin/routes','body':None,'key':'fixture-private-admin-key',
               'host':'127.0.0.2','port':19380}
        mutations=[{'method':'DELETE'},{'path':'/anything'},{'path':'/apisix/admin/routes/../secrets'},
                   {'host':'192.0.2.1'},{'port':True},{'port':65536},{'extra':True},
                   {'method':'PUT','body':None}]
        for change in mutations:
            request={**valid,**change}
            result=subprocess.run([sys.executable,'-I','-B','-S','-c',g.CHILD_SOURCE,'0'],
                input=c.encoded(request),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5,check=False)
            self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'');self.assertEqual(result.stderr,b'')


@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','real role-signature/private-journal fixture required')
class SignedRouteClaims(unittest.TestCase):
    """Real signatures and durable CAS; synthetic generation and route HTTP."""
    def setUp(self):
        sys.path.insert(0,str(ROOT/'tests'))
        import test_ingestion_rollout_execution as core
        from unittest.mock import patch
        self.temp=tempfile.TemporaryDirectory(dir=os.environ['OUF_TEST_ROOT']);self.addCleanup(self.temp.cleanup)
        config=Path(self.temp.name)/'ente-config';config.write_bytes(b'fixture');config.chmod(0o600)
        self.profile={'schema':'ouf.ingestion-rollout-gateway-transport.v1',
            'endpoint':{'host':'127.0.0.3','port':19381},'pythonExecutable':g.governance.executable(os.environ.get('OUF_TEST_PYTHON',sys.executable)),
            'config':binding(config),'adminKey':None}
        original=core.review_fixture
        def fixture(context='/fixture/execution',key_path=None):
            review,packet,inputs=original(context,key_path)
            selected={k:self.profile['config'][k]for k in ('path','sha256','metadata')}
            inputs['retainedGatewayConfig']=copy.deepcopy(selected);packet['retainedGatewayConfig']=copy.deepcopy(selected)
            packet['verifiedInputsHash']=c.digest(inputs)
            review=c.compile_review(packet,{'path':'/fixture/packet-plan','sha256':c.digest(packet)},inputs,
                                    review['humanBinding'],context)
            review['gatewayTransportProfile']=copy.deepcopy(self.profile);review['maximumGatewayGetAttempts']=512
            return review,packet,inputs
        with patch.object(core,'review_fixture',side_effect=fixture):core.SignedFiniteRunner.setUp(self)
        _,self.packet,_=fixture(str(self.context),str(self.key_path))
        while self.runner.record()['nextStage']<next(i for i,s in enumerate(self.review['stages'])
                                                     if s['name']=='VERIFY_REBOUND_ROUTE_MAP'):
            self.runner.step()
        from tools.chatbot_file_cohort.human_session import HumanSession
        self.human=HumanSession.__new__(HumanSession)
        current=patch.object(self.human,'current',return_value=self.scope['humanBinding']);current.start();self.addCleanup(current.stop)
        from tools.ingestion_rollout_execution.namespace import GatewayNamespacePin
        self.pin=GatewayNamespacePin.__new__(GatewayNamespacePin)
        self.pin.old_id=self.packet['expectedRuntimeBindings']['gateway']['containerId'];self.pin.created_id='f'*64
        self.pin.frame=copy.deepcopy(self.packet['frames']['gateway'])
        self.pin.process={'containerId':self.pin.created_id,'pid':os.getpid(),'startedAt':'synthetic-first-process'}
        self.pin.fd=os.open('/proc/self/ns/net',os.O_RDONLY);self.addCleanup(os.close,self.pin.fd)
        self.generation_current=True
        def check():
            c.require(self.generation_current,'SYNTHETIC_NEW_GATEWAY_GENERATION_CHANGED')
            return {}
        self.pin.check=check
        row=self.runner.record();effects=copy.deepcopy(row['effects'])
        for e in effects:
            if e['stage']=='gateway.CREATE_REPLACEMENT':e['nativeResource']={'containerId':self.pin.created_id}
            if e['stage']=='gateway.START_REPLACEMENT':e['nativeResource']=self.pin.process
        self.runner.journal.compare_and_save(row,{**row,'effects':effects,'version':row['version']+1})
        self.native=g.NativeGatewayTransport(self.action,self.runner.journal,self.review,self.packet,self.human,self.pin)
        self.map=copy.deepcopy(self.packet['routeDraft']['beforeRoutes']);self.puts=[];self.lose_response=False
        self.native.routes=lambda:copy.deepcopy(self.map)
        def request(method,resource,body=None):
            self.assertEqual(method,'PUT')
            self.assertTrue(self.runner.record()['effects'][-1]['nativeGatewayPutAttempted'])
            self.puts.append(resource);self.map[resource.rsplit('/',1)[1]]=copy.deepcopy(body)
            if self.lose_response:raise OSError('synthetic response lost after committed PUT')
            return 200,{}
        self.native._request=request
        previous_apply=self.ports.apply;previous_observe=self.ports.observe
        self.ports.apply=lambda s:self.native.put(s)if s['name'].startswith('PUT_ROUTE.')else previous_apply(s)
        self.ports.observe=lambda s:self.native.observe(s)if s['name'].startswith(('PUT_ROUTE.','READ_ROUTE.'))or s['name']=='VERIFY_REBOUND_ROUTE_MAP'else previous_observe(s)
    def test_exact_two_puts_full82_map_and80_unchanged(self):
        while self.runner.record()['nextStage']<next(i for i,s in enumerate(self.review['stages'])if s['name']=='VERIFY_FINAL'):
            self.runner.step()
        self.assertEqual(len(self.puts),2);self.assertEqual(self.map,self.packet['routeDraft']['afterRoutes'])
        self.assertEqual(sum(self.map[k]==v for k,v in self.packet['routeDraft']['beforeRoutes'].items()),80)
    def test_lost_put_response_is_reconciled_without_second_put(self):
        self.runner.step();self.lose_response=True
        with self.assertRaises(OSError):self.runner.step()
        with self.assertRaises(c.Paused):self.runner.step()
        result=self.runner.reconcile();self.assertFalse(result['effectReplayed']);self.assertEqual(len(self.puts),1)
    def test_unrelated_route_drift_blocks_before_put_and_keeps_claim(self):
        self.runner.step();self.map['0']['foreign']=True
        with self.assertRaises(c.Denied):self.runner.step()
        self.assertEqual(self.puts,[])
        self.map['0'].pop('foreign')
        with self.assertRaises(c.Paused):self.runner.reconcile()
        self.assertEqual(self.puts,[])
    def test_changed_generation_or_human_blocks_put(self):
        self.runner.step();self.generation_current=False
        with self.assertRaises(c.Denied):self.runner.step()
        self.assertEqual(self.puts,[])
        with self.assertRaises(c.Paused):self.runner.step()
    def test_gateway_read_budget_is_shared_persistent_and_cannot_reset(self):
        row=self.runner.record()
        self.runner.journal.compare_and_save(row,{**row,'nativeGatewayGetAttempts':511,'version':row['version']+1})
        self.native.reserve_get()
        self.assertEqual(self.runner.record()['nativeGatewayGetAttempts'],512)
        with self.assertRaises(c.Denied):self.native.reserve_get()
        self.assertEqual(self.runner.record()['nativeGatewayGetAttempts'],512)
    def test_changed_human_blocks_before_first_put(self):
        self.runner.step()
        self.human.current.return_value={**self.scope['humanBinding'],'subject':'other'}
        with self.assertRaises(c.Denied):self.runner.step()
        self.assertEqual(self.puts,[])
    def test_changed_profile_or_revoked_role_blocks_before_put(self):
        self.runner.step();self.native.profile['endpoint']['port']+=1
        with self.assertRaises(c.Denied):self.runner.step()
        self.assertEqual(self.puts,[])
        self.native.profile=copy.deepcopy(self.review['gatewayTransportProfile'])
        policy=json.loads(self.crypto.policy.read_bytes());policy['keys'][0]['state']='REVOKED'
        self.crypto.write(self.crypto.policy,c.encoded(policy))
        with self.assertRaises(Exception):self.runner.step()
        self.assertEqual(self.puts,[])

if __name__=='__main__':unittest.main()
