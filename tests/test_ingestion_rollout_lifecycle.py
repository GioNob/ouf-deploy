"""Real role signatures/private CAS; synthetic Engine responses, no target.

The existing Docker tests qualify comparison/namespace components. These tests
exercise native request reservation, durable CID ordering and no-replay recovery;
they do not qualify a full production Ports composition or actual Docker calls.
"""
import copy
import os
from pathlib import Path
import sys
import unittest
from urllib.parse import unquote
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),
             str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_ingestion_rollout_execution as core
from tools.ingestion_rollout_execution import contract as c

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','real root role-signature fixture required')
class LifecycleClaims(unittest.TestCase):
    def setUp(self):
        core.SignedFiniteRunner.setUp(self)
        key,self.human=core.SignedFiniteRunner.key_component(self)
        from engine_creation import Engine
        from tools.ingestion_rollout_execution.lifecycle import NativeLifecycle
        self.native_engine=Engine.__new__(Engine)
        self.native_engine.check_socket=lambda:None
        self.calls=[];self.rows={};self.ambiguous_create=False;self.fail_read_after_create=False
        self.observed_cid_before_read=False
        for module,pin in self.review_packet()['expectedRuntimeBindings'].items():
            self.rows[pin['containerId']]={'Id':pin['containerId'],'Name':'/'+module,'Image':pin['imageId'],
                'HostConfig':{'RestartPolicy':{'Name':'unless-stopped','MaximumRetryCount':0}},
                'State':{'Running':True,'Paused':False,'Pid':41,'StartedAt':'fixture-old-process'},
                'NetworkSettings':{'Networks':copy.deepcopy(self.packet['frames'][module]['requestTemplate']['NetworkingConfig']['EndpointsConfig'])}}
        self.native_engine.request=self.request
        self.native=NativeLifecycle(self.action,self.runner.journal,self.review,self.packet,
                                   self.human,self.native_engine,key)
        previous_apply=self.ports.apply;previous_observe=self.ports.observe
        self.ports.apply=lambda stage:self.native.apply(stage)if self.native.handles(stage)else previous_apply(stage)
        self.ports.observe=lambda stage:self.native.observe(stage)if self.native.handles(stage)else previous_observe(stage)
    def review_packet(self):
        _,self.packet,_=core.review_fixture(str(self.context),str(self.key_path))
        return self.packet
    def new_container(self,request,cid,name):
        from tools.ingestion_rollout_execution.replacement import _mounts
        frame=self.packet['frames']['ingestion']
        config={k:copy.deepcopy(v)for k,v in request.items()if k not in('HostConfig','NetworkingConfig')}
        from tools.ingestion_rollout_preparation.frames import environment
        env={**environment(self.packet['candidate']['imageConfig'].get('Env')or[]),**environment(config.get('Env')or[])}
        config['Env']=[k+'='+v for k,v in env.items()]
        if config.get('Hostname')=='':config['Hostname']=cid[:12]
        networks=copy.deepcopy(request['NetworkingConfig']['EndpointsConfig'])
        for endpoint in networks.values():
            endpoint['IPAddress']='';endpoint['GlobalIPv6Address']=''
        return {'Id':cid,'Name':'/'+name,'Image':request['Image'],'Config':config,
                'HostConfig':copy.deepcopy(request['HostConfig']),'Mounts':list(_mounts(frame).values()),
                'NetworkSettings':{'Networks':networks},'RestartCount':0,
                'State':{'Running':False,'Status':'created','Paused':False,'Pid':0,'StartedAt':'0001-01-01T00:00:00Z'}}
    def request(self,method,path,body=None):
        self.calls.append((method,path))
        if method=='GET':
            cid=path.split('/containers/',1)[1].split('/')[0]
            if cid=='f'*64:
                resource=self.native.resource('ingestion.CREATE_REPLACEMENT')
                self.observed_cid_before_read=resource=={'containerId':cid}
                if self.fail_read_after_create:raise OSError('fixture lost post-create read')
            return 200,copy.deepcopy(self.rows[cid])
        # Every synthetic daemon mutation must already have a durable marker.
        self.assertTrue(self.runner.record()['effects'][-1]['nativeRequestAttempted'])
        if '/containers/create?'in path:
            cid='f'*64;name=unquote(path.split('?name=')[1])
            self.rows[cid]=self.new_container(body,cid,name)
            if self.ambiguous_create:raise OSError('fixture lost create response')
            return 201,{'Id':cid}
        if '/networks/'in path:
            cid=body['Container'];network=path.split('/networks/')[1].split('/')[0]
            self.rows[cid]['NetworkSettings']['Networks']={
                k:v for k,v in self.rows[cid]['NetworkSettings']['Networks'].items()if v['NetworkID']!=network}
            return 200,{}
        cid=path.split('/containers/',1)[1].split('/')[0];row=self.rows[cid]
        if path.endswith('/update'):
            row['HostConfig']['RestartPolicy']=copy.deepcopy(body['RestartPolicy']);return 200,{}
        if '/stop?'in path:
            row['State'].update(Running=False,Pid=0);return 204,None
        if '/rename?'in path:
            row['Name']='/'+unquote(path.split('?name=')[1]);return 204,None
        if path.endswith('/start'):
            row['State'].update(Running=True,Status='running',Pid=12345,StartedAt='fixture-first-start')
            for e in row['NetworkSettings']['Networks'].values():
                e['IPAddress']=(e.get('IPAMConfig')or{}).get('IPv4Address','')
                e['GlobalIPv6Address']=(e.get('IPAMConfig')or{}).get('IPv6Address','')
            return 204,None
        raise AssertionError(path)
    def until(self,name):
        while self.runner.record()['nextStage']<self.native.indices[name]:
            self.runner.step()
    def posts(self,needle):
        return [p for m,p in self.calls if m=='POST'and needle in p]
    def test_ordered_mutations_preserve_predecessor_and_durable_first_generation(self):
        self.until('ingestion.CREATE_REPLACEMENT');self.runner.step()
        self.assertTrue(self.observed_cid_before_read)
        self.assertEqual(self.native.created('ingestion'),'f'*64)
        old=self.rows[self.packet['expectedRuntimeBindings']['ingestion']['containerId']]
        self.assertFalse(old['State']['Running']);self.assertEqual(old['State']['Pid'],0)
        self.assertFalse(old['NetworkSettings']['Networks']);self.assertIn('-retained-',old['Name'])
        self.runner.step()
        self.assertEqual(self.native.process('ingestion'),{'containerId':'f'*64,'pid':12345,'startedAt':'fixture-first-start'})
        self.assertEqual(len(self.posts('/start')),1)
        self.assertEqual(len(self.posts('/containers/create?')),1)
    def test_response_lost_without_durable_cid_cannot_discover_or_create_again(self):
        self.until('ingestion.CREATE_REPLACEMENT');self.ambiguous_create=True
        with self.assertRaises(OSError):self.runner.step()
        self.assertIsNone(self.native.resource('ingestion.CREATE_REPLACEMENT'))
        stage=self.review['stages'][self.runner.record()['nextStage']]
        with self.assertRaises(c.Denied):self.native.apply(stage)
        with self.assertRaises(c.Paused):self.runner.reconcile()
        self.assertEqual(len(self.posts('/containers/create?')),1)
        self.assertFalse(any('/containers/ingestion/'in p for _,p in self.calls))
    def test_durable_cid_survives_post_create_read_failure_and_reconciles_without_post(self):
        self.until('ingestion.CREATE_REPLACEMENT');self.fail_read_after_create=True
        with self.assertRaises(OSError):self.runner.step()
        self.assertEqual(self.native.created('ingestion'),'f'*64)
        self.fail_read_after_create=False;result=self.runner.reconcile()
        self.assertFalse(result['effectReplayed']);self.assertEqual(len(self.posts('/containers/create?')),1)
    def test_private_generated_key_read_is_fenced_and_not_emitted_as_proof(self):
        self.until('ingestion.DISABLE_OLD_RESTART')
        value=self.native.key.read_for_gateway()
        self.assertEqual(len(value),64);self.assertEqual(value,self.key_path.read_text())
        self.assertNotIn(value,c.encoded(self.runner.record()).decode())
        self.key_path.chmod(0o600)
        with self.assertRaises(c.Denied):self.native.key.read_for_gateway()
    def test_in_place_key_change_with_restored_mode_cannot_change_gateway_resolution(self):
        self.until('ingestion.DISABLE_OLD_RESTART')
        before=self.native.key.read_for_gateway()
        self.key_path.chmod(0o600);self.key_path.write_text('0'*64);self.key_path.chmod(0o400)
        self.assertNotEqual(before,'0'*64)
        self.assertEqual(self.native.key.observe(),('UNKNOWN',{}))
        with self.assertRaises(c.Denied):self.native.key.read_for_gateway()
    def test_revocation_blocks_native_post_and_keeps_the_claim(self):
        self.until('ingestion.DISABLE_OLD_RESTART')
        policy=__import__('json').loads(self.crypto.policy.read_bytes());policy['keys'][0]['state']='REVOKED'
        self.crypto.write(self.crypto.policy,c.encoded(policy))
        with self.assertRaises(Exception):self.runner.step()
        self.assertFalse(self.posts('/update'))
    def test_foreign_stage_or_changed_intent_cannot_dispatch(self):
        self.until('ingestion.DISABLE_OLD_RESTART')
        stage=copy.deepcopy(self.review['stages'][self.runner.record()['nextStage']])
        stage['intent']['restartPolicy']['Name']='always'
        with self.assertRaises(c.Denied):self.native.apply(stage)
        self.assertFalse(self.posts('/update'))

if __name__=='__main__':unittest.main()
