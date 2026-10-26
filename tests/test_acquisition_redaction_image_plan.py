"""Pure two-READ replacement plans: unchanged runtime settings and explicit MAC profiles."""
import copy,importlib.util,json,os,tempfile,unittest
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=module('redaction_image_plan',BASE/'scripts/prepare-acquisition-redaction-image-plan-20261026.py')
p=module('redaction_helper',BASE/'tools/acquisition_read_native/plan_helper.py')
mac=module('redaction_mac',BASE/'tools/acquisition_read_native/retained_mac.py')
CASE=json.loads((BASE/'releases/acquisition-redaction-artifact-case-20261026.json').read_text())

def fixture(images=None):
    if images is None:
        images={r:{'Id':'sha256:'+c*64,'Config':{'User':d['user'],'Entrypoint':d['entrypoint'],'Cmd':None,'Env':['FIXTURE=private-canary'],'Labels':{}}}
                for(r,d),c in zip(CASE['artifacts'].items(),('a','b'))}
    actual={};pins={}
    roles=('gateway','postgres','ingestion','udp','ingestion-read','udp-read','mcp')
    for i,role in enumerate(roles,1):
        read=role.removesuffix('-read');config=copy.deepcopy(images[read]['Config'])if role.endswith('-read')else{'User':'1000:1000','Entrypoint':['synthetic-original'],'Env':[],'Cmd':None,'Labels':{}}
        config['Hostname']=role;config.setdefault('Env',[])
        pin={'pid':100+i,'startTicks':7,'namespaces':{'net':[1,2],'mnt':[3,4]}}
        actual[role]={'Id':format(i,'064x'),'Image':'sha256:'+'c'*64,'Name':'/ouf-'+role,'Config':config,
          'HostConfig':{'NetworkMode':'ci-net','RestartPolicy':{'Name':'unless-stopped','MaximumRetryCount':0},'ReadonlyRootfs':True,
                        'AutoRemove':False,'Memory':0,'OomKillDisable':None,'CapAdd':None,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges:true'],
                        'Mounts':[],'Binds':None,'PortBindings':{},'PublishAllPorts':False},
          'Mounts':[],'State':{'Pid':pin['pid'],'StartedAt':'ci-start','Running':True,'Paused':False,'Restarting':False},
          'NetworkSettings':{'Networks':{'ci-net':{'NetworkID':'f'*64,'MacAddress':'02:42:00:00:00:'+format(i,'02x'),
                                'IPAddress':'10.72.0.'+str(i),'GlobalIPv6Address':'','Aliases':['ouf-'+role],'IPAMConfig':None}}}}
        pins[role]=pin
    inputs={'schema':'ouf.acquisition-redaction-update-inputs.v1','bootId':'ci-boot','currentObservations':actual,'currentProcessPins':pins,
            'engineInfo':{'ServerVersion':'29.8.1','Driver':'overlay2','DriverStatus':[]},'engineBinding':{'fixture':True},
            'candidateSourceCommits':{r:d['sourceCommit']for r,d in CASE['artifacts'].items()},
            'counts':{'bytes':72997,'engineGets':10,'privateMetadataReads':4},'retainedMcpCounts':{'engineGets':116,'engineWrites':8}}
    receipts={r:{'descriptor':d}for r,d in CASE['artifacts'].items()}
    return inputs,receipts,images

class PlanTests(unittest.TestCase):
    def test_only_two_read_replacements_preserve_env_args_host_policy_and_endpoint(self):
        inputs,receipts,images=fixture();before=copy.deepcopy(inputs)
        plan=m.compile_plan(inputs,receipts,images,p,mac)
        self.assertEqual(set(plan['readReplacements']),{'ingestion','udp'});self.assertEqual(inputs,before)
        for role,replacement in plan['readReplacements'].items():
            old=inputs['currentObservations'][role+'-read'];request=replacement['request']
            self.assertEqual(request['Env'],old['Config']['Env']);self.assertEqual(request['Cmd'],old['Config'].get('Cmd'))
            host=copy.deepcopy(old['HostConfig']);host['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
            self.assertEqual(request['HostConfig'],host);self.assertEqual(request['HostConfig']['Memory'],0)
            endpoint=request['NetworkingConfig']['EndpointsConfig']['ci-net']
            self.assertEqual(endpoint['MacAddress'],old['NetworkSettings']['Networks']['ci-net']['MacAddress'])
            self.assertEqual(endpoint['IPAMConfig']['IPv4Address'],old['NetworkSettings']['Networks']['ci-net']['IPAddress'])
            self.assertEqual(replacement['legacyConfigMacDetachPolicy']['configurationMacState'],'ABSENT')
        self.assertTrue(plan['mcpUnchanged']);self.assertFalse(plan['runtimeAuthorityIssued'])
    def test_legacy_present_uses_exact_legacy_absence_transition_without_general_normalization(self):
        inputs,receipts,images=fixture();old=inputs['currentObservations']['ingestion-read']
        old['Config']['MacAddress']=old['NetworkSettings']['Networks']['ci-net']['MacAddress']
        plan=m.compile_plan(inputs,receipts,images,p,mac);r=plan['readReplacements']['ingestion']
        self.assertNotIn('MacAddress',r['request'])
        self.assertEqual(r['legacyConfigMacDetachPolicy'],mac.policy(old));self.assertIn('MacAddress',old['Config'])
    def test_endpoint_only_null_and_empty_are_explicit_exact_config_profiles(self):
        for value,state in((None,'NULL'),('','EMPTY_STRING')):
            inputs,receipts,images=fixture();inputs['currentObservations']['ingestion-read']['Config']['MacAddress']=value
            policy=m.compile_plan(inputs,receipts,images,p,mac)['readReplacements']['ingestion']['legacyConfigMacDetachPolicy']
            self.assertEqual(policy['configurationMacState'],state);self.assertEqual(policy['originalConfigHash'],policy['detachedConfigHash'])
    def test_malformed_or_nonmatching_mac_never_becomes_endpoint_only(self):
        for value in(False,0,'broken','01:00:00:00:00:01','00:00:00:00:00:00','02:42:aa:bb:cc:dd'):
            inputs,receipts,images=fixture();inputs['currentObservations']['ingestion-read']['Config']['MacAddress']=value
            with self.assertRaises((m.Stop,p.Stop,mac.MacTransitionDenied)):m.compile_plan(inputs,receipts,images,p,mac)
    def test_resource_mount_and_launch_widening_are_rejected(self):
        for field,value in(('Memory',True),('Memory',-1),('ReadonlyRootfs',False),('Privileged',True),('CapAdd',['SYS_ADMIN'])):
            inputs,receipts,images=fixture();inputs['currentObservations']['udp-read']['HostConfig'][field]=value
            with self.assertRaises(m.Stop):m.compile_plan(inputs,receipts,images,p,mac)
        inputs,receipts,images=fixture();images['udp']['Config']['Env'].append('NEW_SCOPE=unreviewed')
        with self.assertRaises(m.Stop):m.compile_plan(inputs,receipts,images,p,mac)
    def test_source_capture_or_engine_drift_is_rejected(self):
        inputs,receipts,images=fixture();inputs['candidateSourceCommits']['udp']='0'*40
        with self.assertRaises(m.Stop):m.compile_plan(inputs,receipts,images,p,mac)
        inputs,receipts,images=fixture();inputs['engineInfo']['ServerVersion']='unqualified'
        with self.assertRaises(m.Stop):m.compile_plan(inputs,receipts,images,p,mac)

if __name__=='__main__':unittest.main(verbosity=2)
