import copy
import ast
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('proposal',ROOT/'prepare.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Tests(unittest.TestCase):
    def setUp(self):
        self.case=json.loads((ROOT/'case.json').read_text())
        self.gid='a'*64;self.rid=self.case['historicalRegistryId']
        self.registry={'Id':self.rid,'Image':'sha256:'+'b'*64,
            'Config':{'Entrypoint':m.ENTRY,'Cmd':m.JAVA,'User':'10001:10001',
                      'Env':['OUF_SCHEMA_GOV_ENABLED=false','OUF_DISCOVERY_WORKER_ENABLED=false','SECRET=PRIVATE_FIXTURE']},
            'HostConfig':{'RestartPolicy':{'Name':'no','MaximumRetryCount':0},'CapDrop':['ALL'],
                          'SecurityOpt':['no-new-privileges:true']},
            'State':{'Status':'exited','Running':False,'Pid':0,'Paused':False,'Restarting':False,'Dead':False},
            'Mounts':[],'NetworkSettings':{'Networks':{}},'RestartCount':0}
        self.gateway=copy.deepcopy(self.registry)
        self.gateway.update(Id=self.gid)
        self.gateway['State'].update(Status='running',Running=True,Pid=12,StartedAt='2026-10-22T01:00:00Z')
        self.pin={'containerId':self.gid,'imageId':self.gateway['Image'],'pid':12,
                  'startedAt':self.gateway['State']['StartedAt'],
                  **{key:m.digest(self.gateway[field]) for field,key in [('Config','configHash'),
                    ('HostConfig','hostConfigHash'),('NetworkSettings','networkSettingsHash')]}}
        self.review={'executionReview':{'stages':[{}]*12,'engineBinding':{},
                      'runtimeGuardProfile':{'unchangedApplications':{'gateway':{'binding':self.pin}}}}}
        self.journal={'nextStage':12,'effects':[{'state':'APPLIED'}]*12}

    def compile(self):return m.compile_proposal(self.case,self.review,self.journal,self.registry)

    def capture(self,mutation=None,read_drift=False):
        owner=self
        class Engine(m.Engine):
            def get(self,path):
                owner.assertIn(path,self.paths);owner.assertLess(self.calls,4);self.calls+=1
                value=copy.deepcopy(owner.registry if owner.rid in path else owner.gateway)
                if mutation:mutation(self.calls,value)
                return json.dumps(value).encode()
        reads=[0]
        def read(path):
            reads[0]+=1
            value=self.review if path.endswith('review.json') else self.journal
            return value,b'changed' if read_drift and reads[0]>2 else path.encode()
        with patch.object(m,'Engine',Engine),patch.object(m,'private_json',read):return m.capture(self.case)

    def test_four_get_capture_is_blocked_proposal_without_secrets(self):
        proposal,gets=self.capture();self.assertEqual(gets,4)
        self.assertEqual(len(proposal['requiredGates']),proposal['unresolvedGateCount'])
        for key in ('runtimeAuthorityIssued','targetApplyAuthorized','nativeExecutorQualified','providerRecoveryProposed',
                    'newProviderLeaseProposed','newOAuthBudgetProposed','newHumanWindowProposed',
                    'oldStartOrSignalClaimReusable','oldAttestationReusableForNewPid','automaticReplayAllowed','budgetReset'):
            self.assertFalse(proposal[key])
        self.assertNotIn('PRIVATE_FIXTURE',json.dumps(proposal))
        self.assertNotIn('Env',json.dumps(proposal));self.assertFalse(proposal['rawContainerConfigurationStored'])

    def test_original_gate_and_file_only_producer_contracts(self):
        gate={}
        tree=ast.parse((ROOT/'tests/fixtures/gated_creation_plan.py').read_text())
        for node in tree.body:
            if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id in ('GATE','ENTRY') for t in node.targets):
                exec(compile(ast.Module(body=[node],type_ignores=[]),'original-gate-contract','exec'),gate)
        self.assertEqual(m.ENTRY,gate['ENTRY'])
        tree=ast.parse((ROOT/'tests/fixtures/file_only_profile.py').read_text())
        flags=next(ast.literal_eval(node.value) for node in tree.body if isinstance(node,ast.Assign)
                   and any(isinstance(t,ast.Name) and t.id=='FLAGS' for t in node.targets))
        env=dict(row.split('=',1) for row in self.registry['Config']['Env'])
        self.assertTrue(all(env[key]==value for key,value in flags.items()))

    def test_running_or_unknown_launch_cannot_be_adopted(self):
        for key,value in [('Running',True),('Pid',3),('Status','running'),('Paused',True)]:
            before=copy.deepcopy(self.registry['State']);self.registry['State'][key]=value
            with self.assertRaises(m.Stop):self.compile()
            self.registry['State']=before
        self.registry['Config']['Entrypoint']=m.JAVA
        with self.assertRaisesRegex(m.Stop,'GATED_LAUNCH'):self.compile()

    def test_file_only_flags_overrides_and_duplicate_keys_rejected(self):
        for addition in ('OUF_SCHEMA_GOV_ENABLED=true','JAVA_TOOL_OPTIONS=-DPRIVATE_FIXTURE',
                         'SPRING_APPLICATION_JSON=PRIVATE_FIXTURE','OUF_SEMANTIC_DISCOVERY_WORKER_ENABLED=false'):
            before=list(self.registry['Config']['Env']);self.registry['Config']['Env'].append(addition)
            with self.assertRaises(m.Stop):self.compile()
            self.registry['Config']['Env']=before

    def test_restart_policy_privilege_and_shared_namespace_rejected(self):
        for key,value in [('RestartPolicy',{'Name':'unless-stopped','MaximumRetryCount':0}),
                          ('Privileged',True),('NetworkMode','host'),('PidMode','container:unreviewed')]:
            before=copy.deepcopy(self.registry['HostConfig']);self.registry['HostConfig'][key]=value
            with self.assertRaisesRegex(m.Stop,'BOUNDED_GATED_HOST'):self.compile()
            self.registry['HostConfig']=before

    def test_current_context_and_resource_drift_stop(self):
        with self.assertRaisesRegex(m.Stop,'RETAINED_CONTEXT_CHANGED'):self.capture(read_drift=True)
        for target in (3,4):
            def mutation(call,value):
                if call==target:value['Config']['Env'].append('DRIFT=true')
            with self.assertRaises(m.Stop):self.capture(mutation)
        self.journal['effects'][0]['state']='CLAIMED'
        with self.assertRaisesRegex(m.Stop,'COMPLETED_PATCH'):self.capture()

    def test_closed_exact_get_paths_and_budget(self):
        engine=m.Engine({},[self.gid,self.rid])
        for path in ('/v1.44/containers/json','/v1.44/containers/'+self.rid+'/start',
                     '/v1.44/containers/name/json'):
            with self.assertRaises(m.Stop):engine.get(path)
        engine.calls=4
        with self.assertRaises(m.Stop):engine.get(next(iter(engine.paths)))

    def test_only_new_private_proposal_is_written_and_old_inputs_unchanged(self):
        # Workspace-owned root parent; no /tmp world-writable ancestor exception.
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            case=copy.deepcopy(self.case);case['privateParent']=directory
            proposal=self.compile();path,sha=m.publish(case,proposal)
            self.assertEqual(sha,m.digest(proposal))
            self.assertEqual(json.loads(Path(path).read_bytes()),proposal)
            self.assertEqual(stat.S_IMODE(Path(path).stat().st_mode),0o400)
            self.assertEqual(stat.S_IMODE(Path(path).parent.stat().st_mode),0o700)
            self.assertEqual(list(Path(directory).rglob('*.json')),[Path(path)])
            self.assertNotIn('PRIVATE_FIXTURE',Path(path).read_text())

if __name__=='__main__':unittest.main()
