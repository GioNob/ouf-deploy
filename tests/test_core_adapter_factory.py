import copy,sys,types,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_database_cutover')]
from core_adapter_factory import configure_core,OWNER,CORE,digest,PHASES
from database_gate import Psql
from engine_creation import Engine

class CoreFactory(unittest.TestCase):
    def fixture(self):
        cid='1'*64;nid='2'*64;eid='3'*64;name='fixture-bridge';ip='10.233.0.13';mac='02:00:00:00:00:13'
        original={'Id':cid,'Image':'sha256:'+'a'*64,'Config':{},'HostConfig':{'RestartPolicy':{'Name':'unless-stopped','MaximumRetryCount':0}},'Mounts':[],'State':{'Pid':100,'StartedAt':'fixture-only'},'NetworkSettings':{'Networks':{name:{'NetworkID':nid,'EndpointID':eid,'IPAddress':ip,'MacAddress':mac,'IPAMConfig':None}}}}
        pin=Engine.runtime_binding(original)
        request={'Image':'sha256:'+'b'*64,'HostConfig':{'NetworkMode':name,'RestartPolicy':{'Name':'no','MaximumRetryCount':0}},'NetworkingConfig':{'EndpointsConfig':{name:{'IPAMConfig':{'IPv4Address':ip},'MacAddress':mac}}}}
        intents={p:{'syntheticFixture':True} for p in PHASES}
        intents.update({'QUIESCE_PRODUCERS':{'producerBindings':[pin],'initialNetworkSettings':{cid:original['NetworkSettings']},'initialHostConfigs':{cid:original['HostConfig']},'quiescentRestartPolicy':{'Name':'no','MaximumRetryCount':0},'stopTimeoutSeconds':1},
                        'RELEASE_OLD_ENDPOINT':{'containerId':cid,'networkId':nid,'networkName':name,'networkConfigurationHash':'f'*64,'originalEndpointId':eid,'staticIpv4':ip,'macAddress':mac,'priorEvidencePhase':'QUIESCE_PRODUCERS'},
                        'FENCED_BACKUP':{'containerId':'d'*64,'user':'postgres','database':'semantic','databaseOid':21558,'directory':'/fixture/private','maxArchiveBytes':1048576},
                        'ADMIT_MIGRATION':{'containerId':'d'*64,'user':'postgres','database':'semantic','databaseOid':21558,'priorBackupEvidencePhase':'FENCED_BACKUP','priorPausedEvidencePhase':'STAGE_PAUSED_REPLACEMENT'},
                        'CREATE_REPLACEMENT':request,'STAGE_PAUSED_REPLACEMENT':{'creationRequestHash':digest(request),'priorEvidencePhase':'CREATE_REPLACEMENT'},
                        'START_REPLACEMENT':{'creationRequestHash':digest(request),'priorEvidencePhase':'STAGE_PAUSED_REPLACEMENT'}})
        calls=[];owners={p:types.SimpleNamespace(apply=lambda value:calls.append(value),observe=lambda value:('UNKNOWN',{})) for p in OWNER}
        t=types.SimpleNamespace(context='e'*64,read=lambda:{'creationRequestHash':digest(request)})
        return request,intents,owners,t,Psql.__new__(Psql),calls
    def test_constructs_seven_native_adapters_without_any_effect(self):
        request,intents,owners,t,admin,calls=self.fixture()
        a=configure_core(None,t,request,None,admin,intents,owners,lambda point:None)
        self.assertEqual(set(a),set(PHASES));self.assertEqual(len(CORE),7);self.assertEqual(calls,[])
    def test_missing_owner_phase_or_database_scope_mismatch_blocks_construction(self):
        for change in ('owner','database'):
            request,intents,owners,t,admin,calls=self.fixture()
            if change=='owner':del owners[next(iter(OWNER))]
            else:intents['ADMIT_MIGRATION']['databaseOid']+=1
            with self.assertRaises(ValueError):configure_core(None,t,request,None,admin,intents,owners,lambda point:None)
            self.assertEqual(calls,[])
    def test_mismatched_ip_mac_or_prior_generation_reference_blocks(self):
        for change in ('ip','mac','generation'):
            request,intents,owners,t,admin,calls=self.fixture()
            if change=='ip':intents['RELEASE_OLD_ENDPOINT']['staticIpv4']='10.233.0.99'
            if change=='mac':intents['RELEASE_OLD_ENDPOINT']['macAddress']='02:00:00:00:00:99'
            if change=='generation':intents['START_REPLACEMENT']['creationRequestHash']='f'*64
            with self.assertRaises(ValueError):configure_core(None,t,request,None,admin,intents,owners,lambda point:None)
            self.assertEqual(calls,[])

if __name__=='__main__':unittest.main()
