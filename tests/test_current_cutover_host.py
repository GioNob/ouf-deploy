import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import types

s=importlib.util.spec_from_file_location('host',Path(__file__).resolve().parents[1]/'scripts/read-current-semantic-cutover-host.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)

class HostProjection(unittest.TestCase):
    def fixture(self):
        return {'Id':m.CID,'Image':m.backup.SEMANTIC_IMAGE,
                'State':{'Running':True,'Status':'running','Pid':1234,'StartedAt':'fixed','Health':{'changing':1}},
                'Config':{'Env':['OUF_SEM_DB_PASSWORD=private-fixture-value']},
                'HostConfig':{'Privileged':False,'NetworkMode':'ouf','Runtime':'runc','RestartPolicy':{'Name':'no'},'Memory':1000},
                'Mounts':[{'Source':'private-fixture-path','Destination':'/key'}],
                'NetworkSettings':{'Networks':{'ouf':{'NetworkID':'network','IPAddress':'172.18.0.6','MacAddress':'b2:96:a1:e2:c1:8d'}}}}
    def test_projection_discloses_no_environment_or_mount_source(self):
        v=self.fixture(); before=copy.deepcopy(v)
        report=m.project(v); encoded=json.dumps(report)
        self.assertEqual(v,before)
        self.assertNotIn('private-fixture-value',encoded)
        self.assertNotIn('private-fixture-path',encoded)
        self.assertTrue(report['legacyDatabasePasswordEnvironmentPresent'])
        self.assertFalse(report['fullRealizedOciProven'])
        self.assertFalse(report['protectedDeclarationCompared'])
    def test_health_counters_are_not_generation_drift(self):
        v=self.fixture(); changed=copy.deepcopy(v);changed['State']['Health']['changing']=99
        self.assertEqual(m.stable(v),m.stable(changed))
        changed['State']['Pid']=9999
        self.assertNotEqual(m.stable(v),m.stable(changed))
    def test_exact_installed_identity_running_and_bridge_required(self):
        for key,value in [('Id','other'),('Image','other')]:
            v=self.fixture();v[key]=value
            with self.assertRaises(RuntimeError):m.project(v)
        for key,value in [('Running',False),('Status','exited'),('Pid',0)]:
            v=self.fixture();v['State'][key]=value
            with self.assertRaises(RuntimeError):m.project(v)
        for key,value in [('Privileged',True),('NetworkMode','host'),('NetworkMode','container:peer')]:
            v=self.fixture();v['HostConfig'][key]=value
            with self.assertRaises(RuntimeError):m.project(v)
    def test_duplicate_environment_denied(self):
        v=self.fixture();v['Config']['Env'].append('OUF_SEM_DB_PASSWORD=duplicate')
        with self.assertRaises(RuntimeError):m.project(v)

    def test_current_r12_service_projection_does_not_expose_execstart(self):
        rows={'LoadState':'loaded','ActiveState':'active','SubState':'running','MainPID':'2446150',
              'NRestarts':'0','Restart':'no','Result':'success',
              'ExecStart':'/etc/ouf/deploy-snapshots/semantic-resilient-lease-recovery-r12-y048hyms/activate.py private-argument'}
        result=types.SimpleNamespace(returncode=0,stdout=('\n'.join(k+'='+v for k,v in rows.items())).encode())
        with patch.object(m.subprocess,'run',return_value=result) as run:
            report=m.service()
        self.assertIn('ouf-semantic-provider-lease-resilient-r12.service',run.call_args.args[0])
        self.assertTrue(report['serviceActiveAtObservation'])
        self.assertFalse(report['nativeLeaseMembershipProven'])
        self.assertNotIn('private-argument',json.dumps(report))
    def test_retired_or_foreign_service_execstart_is_not_current_readiness(self):
        rows={'LoadState':'loaded','ActiveState':'active','SubState':'running','MainPID':'1234',
              'NRestarts':'0','Restart':'no','Result':'success',
              'ExecStart':'/etc/ouf/deploy-snapshots/semantic-finite-lease-recovery-r10-nw9ue4d5/activate.py'}
        result=types.SimpleNamespace(returncode=0,stdout=('\n'.join(k+'='+v for k,v in rows.items())).encode())
        with patch.object(m.subprocess,'run',return_value=result):
            self.assertFalse(m.service()['serviceActiveAtObservation'])

if __name__=='__main__':unittest.main()

