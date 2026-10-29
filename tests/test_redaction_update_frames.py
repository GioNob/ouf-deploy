"""Pure executor-frame negatives; complements actual Docker lifecycle fixtures."""
import copy,importlib.util,types,unittest
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
f=module('frame_plan_fixture',BASE/'tests/test_acquisition_redaction_image_plan.py')
c=module('frame_authority',BASE/'tools/acquisition_redaction_update/authority.py')
ports=module('frame_ports',BASE/'tools/acquisition_redaction_update/ports.py')
class Frames(unittest.TestCase):
    def frame(self,kind='legacy'):
        inputs,receipts,images=f.fixture();original=inputs['currentObservations']['ingestion-read']
        if kind=='legacy':original['Config']['MacAddress']=original['NetworkSettings']['Networks']['ci-net']['MacAddress']
        elif kind=='null':original['Config']['MacAddress']=None
        elif kind=='empty':original['Config']['MacAddress']=''
        plan=f.m.compile_plan(inputs,receipts,images,f.p,f.mac);actual=copy.deepcopy(original);actual['State'].update(Running=False,Pid=0);actual['NetworkSettings']['Networks']={};actual['HostConfig']['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
        if kind=='legacy':del actual['Config']['MacAddress']
        history=[{'state':'APPLIED','proof':{'oldStopped':True,'oldDetached':True}}for _ in c.STAGES]
        ctx=types.SimpleNamespace(core=c,root=Path('/synthetic-only'),p=f.p,mac=f.mac,inputs=inputs,evidence=lambda *args:None)
        review={'nativePlan':{'proposal':plan},'stages':list(c.STAGES)};p=ports.NativePorts(ctx,review,None)
        p.execution=types.SimpleNamespace(record=lambda:{'effects':history});p.container=lambda cid:copy.deepcopy(actual);p.network=lambda role:{'Containers':{}}
        return p,actual,history
    def test_all_reviewed_mac_profiles_follow_exact_executor_detach_frame(self):
        for kind in('legacy','absent','null','empty'):
            p,_,_=self.frame(kind);p.old_guard('ingestion','RENAME_OLD_INGESTION_READ')
    def test_legacy_detach_does_not_accept_null_empty_or_new_value(self):
        for value in(None,'','02:42:ab:cd:ef:01',False):
            p,actual,_=self.frame();actual['Config']['MacAddress']=value
            with self.assertRaises(c.Stop):p.old_guard('ingestion','RENAME_OLD_INGESTION_READ')
    def test_endpoint_only_defaults_are_not_interchangeable_after_detach(self):
        for kind in('absent','null','empty'):
            for target in('absent','null','empty','legacy'):
                if kind==target:continue
                p,actual,_=self.frame(kind);actual['Config'].pop('MacAddress',None)
                if target!='absent':actual['Config']['MacAddress']={'null':None,'empty':'','legacy':'02:42:00:00:00:05'}[target]
                with self.assertRaises(c.Stop):p.old_guard('ingestion','RENAME_OLD_INGESTION_READ')
    def test_identity_generation_config_mount_host_and_running_drift_rejected(self):
        mutations=[lambda v:v.update(Id='0'*64),lambda v:v.update(Image='sha256:'+'0'*64),lambda v:v['State'].update(StartedAt='other'),lambda v:v['State'].update(Running=True,Pid=10),lambda v:v['Mounts'].append({'Destination':'/extra'}),lambda v:v['Config'].update(Env=['EXTRA=1']),lambda v:v['Config'].update(Hostname='other'),lambda v:v['HostConfig'].update(Memory=1),lambda v:v['NetworkSettings'].update(Networks={'extra':{}})]
        for change in mutations:
            p,actual,_=self.frame();change(actual)
            with self.assertRaises(c.Stop):p.old_guard('ingestion','RENAME_OLD_INGESTION_READ')
    def test_no_mac_transition_without_proven_stop_and_detach_prefix(self):
        for index in(c.STAGES.index('STOP_OLD_INGESTION_READ'),c.STAGES.index('DETACH_OLD_INGESTION_READ')):
            p,_,history=self.frame();history[index]['state']='CLAIMED'
            with self.assertRaises(c.Stop):p.old_guard('ingestion','RENAME_OLD_INGESTION_READ')
    def test_closed_write_dispatch_rejects_worker_mcp_and_cross_role_effects(self):
        p,_,_=self.frame();stage='STOP_OLD_INGESTION_READ';i=c.STAGES.index(stage)
        p.execution=types.SimpleNamespace(record=lambda:{'nextStage':i,'effects':[{}for _ in range(i)]+[{'state':'CLAIMED'}]})
        expected=p.proposal('ingestion')['oldBinding']['containerId'];p.assert_write('/v1.44/containers/'+expected+'/stop?t=10',None)
        for role in('mcp','ingestion','udp-read'):
            foreign=p.plan['existingApplications'][role]['containerId']
            with self.assertRaises(c.Stop):p.assert_write('/v1.44/containers/'+foreign+'/stop?t=10',None)
if __name__=='__main__':unittest.main()
