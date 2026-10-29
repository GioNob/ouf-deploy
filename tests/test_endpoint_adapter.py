import copy,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover')]
from endpoint_adapter import EndpointAdapter,NETWORK_FIELDS
from producer_adapter import ProducerAdapter
from engine_creation import Engine,digest,CreationDenied
from executor_composition_fixture import compose

class Endpoints(unittest.TestCase):
    def fixture(self,override=None):
        cid='1'*64;nid='2'*64;eid='3'*64;ip='10.233.0.13';mac='02:00:00:00:00:13';name='fixture-private-bridge'
        attachment={'NetworkID':nid,'EndpointID':eid,'IPAddress':ip,'MacAddress':mac,'IPAMConfig':{'IPv4Address':ip}}
        actual={'Id':cid,'Image':'sha256:'+'a'*64,'Config':{},'HostConfig':{'RestartPolicy':{'Name':'no','MaximumRetryCount':0}},'Mounts':[],'NetworkSettings':{'Networks':{name:attachment}},'RestartCount':0,'State':{'Running':True,'Paused':False,'Status':'running','Pid':100,'StartedAt':'2026-10-12T00:00:00Z','FinishedAt':'0001-01-01T00:00:00Z','Error':''}}
        network={'Id':nid,'Name':name,'Driver':'bridge','Containers':{cid:{'EndpointID':eid,'IPv4Address':ip+'/24','MacAddress':mac}}};posts=[]
        engine=Engine.__new__(Engine)
        def request(method,path,body=None):
            if method=='GET':return 200,copy.deepcopy(network if path.startswith('/v1.44/networks/') else actual)
            posts.append(path)
            if '/stop?' in path:
                actual['State'].update(Running=False,Status='exited',Pid=0,FinishedAt='2026-10-12T01:00:00Z')
                network['Containers'].pop(cid,None);attachment.update(EndpointID='',IPAddress='',MacAddress='')
                return 204,None
            actual['NetworkSettings']['Networks'].pop(name);network['Containers'].pop(cid,None);return 200,None
        engine.request=request;pin=engine.runtime_binding(actual)
        quiesce={'producerBindings':[pin],'initialNetworkSettings':{cid:copy.deepcopy(actual['NetworkSettings'])},'initialHostConfigs':{cid:copy.deepcopy(actual['HostConfig'])},'quiescentRestartPolicy':{'Name':'no','MaximumRetryCount':0},'stopTimeoutSeconds':1}
        intent={'containerId':cid,'networkId':nid,'networkName':name,'networkConfigurationHash':digest({k:network.get(k) for k in NETWORK_FIELDS}),'originalEndpointId':eid,'staticIpv4':ip,'macAddress':mac,'priorEvidencePhase':'QUIESCE_PRODUCERS'}
        if override:intent.update(override)
        e,store=compose(self,'RELEASE_OLD_ENDPOINT',intent,lambda t,s:EndpointAdapter(engine,t,intent,s),{'QUIESCE_PRODUCERS':(quiesce,lambda t,s:ProducerAdapter(engine,t,quiesce,s))})
        return e,engine,actual,network,posts,intent
    def test_crash_after_disconnect_reconciles_without_replay(self):
        e,engine,actual,network,posts,intent=self.fixture();e.run(3);adapter=e.adapters['RELEASE_OLD_ENDPOINT'];original=adapter.apply
        def crash(value):original(value);raise RuntimeError('fixture-crash-after-disconnect')
        adapter.apply=crash
        with self.assertRaises(RuntimeError):e.run(4)
        adapter.apply=lambda value:self.fail('DISCONNECT_REPLAYED')
        e.run(4);e.run(4);self.assertEqual(len(posts),2);self.assertEqual(actual['State']['Status'],'exited')
    def test_foreign_ip_mac_or_network_configuration_blocks_before_disconnect(self):
        for change in ('ip','mac','network'):
            e,engine,actual,network,posts,intent=self.fixture();e.run(3)
            if change=='network':network['Labels']={'changed':'true'}
            else:network['Containers']['4'*64]={'IPv4Address':intent['staticIpv4']+'/24' if change=='ip' else '10.233.0.14/24','MacAddress':intent['macAddress'] if change=='mac' else '02:00:00:00:00:14'}
            with self.assertRaises(CreationDenied):e.run(4)
            self.assertEqual(len(posts),1)
    def test_original_endpoint_binding_cannot_be_substituted(self):
        e,engine,actual,network,posts,intent=self.fixture({'originalEndpointId':'f'*64});e.run(3)
        # A source-bound intent can be wrong; it must still match the signed
        # initial network snapshot carried by the prior quiescence evidence.
        with self.assertRaisesRegex(CreationDenied,'SIGNED_INITIAL_ENDPOINT_BINDING_DRIFT'):e.run(4)
        self.assertEqual(len(posts),1)

if __name__=='__main__':unittest.main()
