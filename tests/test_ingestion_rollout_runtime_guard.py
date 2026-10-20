"""Pure stage-aware old/unchanged runtime predicates; not Docker qualification."""
import copy
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),
             str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from engine_creation import Engine
from tools.ingestion_rollout_execution import runtime_guard as g,contract as c
from test_ingestion_rollout_execution import review_fixture

class OldGeneration(unittest.TestCase):
    def setUp(self):
        review,packet,inputs=review_fixture();before={}
        for module in('ingestion','gateway'):
            frame=packet['frames'][module];endpoints=frame['requestTemplate']['NetworkingConfig']['EndpointsConfig']
            endpoints['second_fixture_network']={'NetworkID':('2'if module=='ingestion'else'6')*64,
                'Aliases':['fixture-secondary'],'IPAMConfig':{'IPv4Address':'192.0.2.19'},'MacAddress':'02:00:00:00:00:19'}
            networks=copy.deepcopy(endpoints)
            for endpoint in networks.values():
                endpoint.update(EndpointID='fixture-endpoint',IPAddress=endpoint.get('IPAMConfig',{}).get('IPv4Address',''),
                    Gateway='192.0.2.1',GlobalIPv6Address='',IPv6Gateway='',IPPrefixLen=24,GlobalIPv6PrefixLen=0)
            pin=packet['expectedRuntimeBindings'][module]
            before[module]={'Id':pin['containerId'],'Image':pin['imageId'],'Name':'/'+frame['name'],
                'Config':{'Env':['PRIVATE_FIXTURE=value'],'MacAddress':next(iter(networks.values()))['MacAddress']},
                'HostConfig':{'RestartPolicy':copy.deepcopy(frame['restoreRestartPolicy']),'Memory':123},
                'Mounts':copy.deepcopy(frame['oldMounts']),'RestartCount':3,
                'State':{'Running':True,'Paused':False,'Restarting':False,'Pid':41,'StartedAt':'fixture-old-process'},
                'NetworkSettings':{'Networks':networks,'SandboxID':'old-sandbox','SandboxKey':'old-key',
                                   'Ports':{'8080/tcp':[{'HostIp':'127.0.0.1','HostPort':'18080'}]}}}
        inputs['expectedRuntimeBindings']={m:Engine.runtime_binding(v)for m,v in before.items()}
        packet['expectedRuntimeBindings']=inputs['expectedRuntimeBindings'];packet['verifiedInputsHash']=c.digest(inputs)
        self.packet=packet;self.review=c.compile_review(packet,{'path':'/fixture/packet','sha256':c.digest(packet)},inputs,
            review['humanBinding'],'/fixture/execution')
        self.profile={'schema':'ouf.ingestion-rollout-runtime-guard.v1','beforeContainers':before,
            'unchangedApplications':{}}
        self.unchanged={}
        for index,name in enumerate(('onboarding','mcp','udp'),3):
            actual=copy.deepcopy(before['ingestion']);actual['Id']=str(index)*64
            self.profile['unchangedApplications'][name]={'binding':Engine.runtime_binding(actual),'restartCount':actual['RestartCount']}
            self.unchanged[name]=actual
        g.validate_profile(self.profile,self.packet)
    def row(self,name,attempted=False):
        n=next(i for i,s in enumerate(self.review['stages'])if s['name']==name)
        effects=[{'stage':s['name'],'intentHash':s['intentHash'],'state':'APPLIED'if i<n else'CLAIMED',
                  'nativeRequestAttempted':attempted if i==n else True}
                 for i,s in enumerate(self.review['stages'][:n+1])]
        return {'nextStage':n,'effects':effects}
    def old(self,stopped=False,detached=False,renamed=False):
        actual=copy.deepcopy(self.profile['beforeContainers']['ingestion'])
        actual['HostConfig']['RestartPolicy']=copy.deepcopy(g.NO_RESTART)
        if stopped:
            actual['State'].update(Running=False,Pid=0);actual['Config']['MacAddress']=''
            actual['NetworkSettings'].update(SandboxID='',SandboxKey='',Ports={})
            for endpoint in actual['NetworkSettings']['Networks'].values():
                for key in g.RELEASED_STRINGS:
                    if key in endpoint:endpoint[key]=''
                for key in g.RELEASED_INTS:
                    if key in endpoint:endpoint[key]=0
        if detached:actual['NetworkSettings']['Networks']={}
        if renamed:actual['Name']='/'+next(s for s in self.review['stages']if s['name']=='ingestion.RENAME_OLD')['intent']['retainedName']
        return actual
    def check(self,actual,row):return g.predecessor('ingestion',actual,self.profile,self.packet,self.review,row)
    def test_exact_two_replaced_three_unchanged_apps_and_distinct_ids(self):
        for name,pin in self.profile['unchangedApplications'].items():g.unchanged(self.unchanged[name],pin)
        changed=copy.deepcopy(self.profile);changed['unchangedApplications'].pop('mcp')
        with self.assertRaises(c.Denied):g.validate_profile(changed,self.packet)
        changed=copy.deepcopy(self.profile);changed['unchangedApplications']['mcp']=changed['unchangedApplications']['udp']
        with self.assertRaises(c.Denied):g.validate_profile(changed,self.packet)
    def test_host_restart_change_requires_owned_attempt_marker(self):
        actual=self.old()
        with self.assertRaises(c.Denied):self.check(actual,self.row('ingestion.DISABLE_OLD_RESTART'))
        self.check(actual,self.row('ingestion.DISABLE_OLD_RESTART',True))
        actual['HostConfig']['Memory']+=1
        with self.assertRaises(c.Denied):self.check(actual,self.row('ingestion.DISABLE_OLD_RESTART',True))
    def test_stop_and_allocation_release_require_attempt_then_no_new_process(self):
        actual=self.old(stopped=True)
        with self.assertRaises(c.Denied):self.check(actual,self.row('ingestion.STOP_OLD'))
        self.assertTrue(self.check(actual,self.row('ingestion.STOP_OLD',True))['stopped'])
        actual['State'].update(Running=True,Pid=42)
        with self.assertRaises(c.Denied):self.check(actual,self.row('ingestion.STOP_OLD',True))
    def test_each_network_release_requires_its_own_exact_claim(self):
        actual=self.old(stopped=True);name=sorted(actual['NetworkSettings']['Networks'])[0]
        network=actual['NetworkSettings']['Networks'][name]['NetworkID'];actual['NetworkSettings']['Networks'].pop(name)
        stage='ingestion.DETACH_'+network
        with self.assertRaises(c.Denied):self.check(actual,self.row(stage))
        self.assertEqual(self.check(actual,self.row(stage,True))['remainingNetworks'],1)
    def test_foreign_mac_ip_alias_or_port_binding_is_never_unallocation(self):
        for mutate in(
            lambda a:next(iter(a['NetworkSettings']['Networks'].values())).update(MacAddress='02:00:00:ff:ff:ff'),
            lambda a:next(iter(a['NetworkSettings']['Networks'].values())).update(IPAddress='192.0.2.222'),
            lambda a:next(iter(a['NetworkSettings']['Networks'].values())).update(Aliases=['foreign']),
            lambda a:a['NetworkSettings'].update(Ports={'8080/tcp':[{'HostIp':'0.0.0.0','HostPort':'28080'}]})):
            actual=self.old(stopped=True);mutate(actual)
            with self.assertRaises(c.Denied):self.check(actual,self.row('ingestion.STOP_OLD',True))
    def test_detached_renamed_predecessor_is_retained_until_end(self):
        actual=self.old(stopped=True,detached=True,renamed=True)
        with self.assertRaises(c.Denied):self.check(actual,self.row('ingestion.RENAME_OLD'))
        self.check(actual,self.row('ingestion.RENAME_OLD',True))
        self.check(actual,self.row('VERIFY_RESTORED_FINAL'))
        actual['Config']['Env']=['FOREIGN=1']
        with self.assertRaises(c.Denied):self.check(actual,self.row('VERIFY_RESTORED_FINAL'))
    def test_unrelated_unchanged_application_restart_or_config_drift_blocks(self):
        actual=copy.deepcopy(self.unchanged['udp']);actual['RestartCount']+=1
        with self.assertRaises(c.Denied):g.unchanged(actual,self.profile['unchangedApplications']['udp'])
        actual=copy.deepcopy(self.unchanged['udp']);actual['Config']['Env'].append('FOREIGN=1')
        with self.assertRaises(c.Denied):g.unchanged(actual,self.profile['unchangedApplications']['udp'])

if __name__=='__main__':unittest.main()
