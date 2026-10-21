"""Actual private bridge/static attachment release and controller death.
Only producer stop/endpoint disconnect are native; authority/lease/DB synthetic.
"""
import json,sys,uuid,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover')]
from native_runtime_executor import NativeRuntime
from engine_creation import digest,CreationDenied
from endpoint_adapter import EndpointAdapter,NETWORK_FIELDS
from producer_adapter import ProducerAdapter
from executor_composition_fixture import compose

class NativeEndpoint(NativeRuntime):
    def endpoint(self,legacy_dynamic=False):
        _,engine,_=self.fixture();name='ouf-endpoint-fixture-'+uuid.uuid4().hex[:12]
        status,result=engine.request('POST','/v1.44/networks/create',{'Name':name,'Driver':'bridge','Internal':True,'IPAM':{'Config':[{'Subnet':'10.233.0.0/24'}]}})
        self.assertEqual(status,201);nid=result['Id'];self.addCleanup(lambda:engine.request('DELETE','/v1.44/networks/'+nid))
        def create(ip):
            endpoint={} if ip is None else {'IPAMConfig':{'IPv4Address':ip}}
            request={'Image':self.image,'Cmd':['sleep','600'],'HostConfig':{'NetworkMode':name,'RestartPolicy':{'Name':'no','MaximumRetryCount':0}},'NetworkingConfig':{'EndpointsConfig':{name:endpoint}}}
            status,value=engine.request('POST','/v1.44/containers/create?name=ouf-endpoint-producer-'+uuid.uuid4().hex,request);self.assertEqual(status,201);cid=value['Id']
            self.addCleanup(lambda:engine.request('DELETE','/v1.44/containers/'+cid+'?force=true'))
            self.assertEqual(engine.request('POST','/v1.44/containers/'+cid+'/start')[0],204)
            return engine.request('GET','/v1.44/containers/'+cid+'/json')[1]
        initial=create(None if legacy_dynamic else '10.233.0.13');pin=engine.runtime_binding(initial);attach=initial['NetworkSettings']['Networks'][name]
        network=engine.request('GET','/v1.44/networks/'+nid)[1]
        quiesce={'producerBindings':[pin],'initialNetworkSettings':{pin['containerId']:initial['NetworkSettings']},'initialHostConfigs':{pin['containerId']:initial['HostConfig']},'quiescentRestartPolicy':{'Name':'no','MaximumRetryCount':0},'stopTimeoutSeconds':1}
        intent={'containerId':pin['containerId'],'networkId':nid,'networkName':name,'networkConfigurationHash':digest({k:network.get(k) for k in NETWORK_FIELDS}),'originalEndpointId':attach['EndpointID'],'staticIpv4':attach['IPAddress'],'macAddress':attach['MacAddress'],'priorEvidencePhase':'QUIESCE_PRODUCERS'}
        e,store=compose(self,'RELEASE_OLD_ENDPOINT',intent,lambda t,s:EndpointAdapter(engine,t,intent,s),{'QUIESCE_PRODUCERS':(quiesce,lambda t,s:ProducerAdapter(engine,t,quiesce,s))})
        return e,engine,intent,create
    def test_native_disconnect_controller_death_and_independent_peer_preserved(self):
        e,engine,intent,create=self.endpoint();independent=create('10.233.0.14');e.run(3)
        self.death_after(e,'RELEASE_OLD_ENDPOINT',4);e.run(4);e.run(4)
        old=engine.request('GET','/v1.44/containers/'+intent['containerId']+'/json')[1]
        self.assertEqual(old['State']['Status'],'exited');self.assertNotIn(intent['networkName'],old['NetworkSettings']['Networks'])
        current=engine.request('GET','/v1.44/containers/'+independent['Id']+'/json')[1]
        self.assertEqual(engine.runtime_binding(current),engine.runtime_binding(independent));self.assertTrue(current['State']['Running'])
    def test_native_ip_reallocation_blocks_disconnect(self):
        e,engine,intent,create=self.endpoint();e.run(3)
        # Explicit isolated-fixture competing transition: free the old retained
        # attachment and allocate its IP to another generation. The tested
        # controller must block rather than adopt this as its own release.
        self.assertEqual(engine.request('POST','/v1.44/networks/'+intent['networkId']+'/disconnect',{'Container':intent['containerId'],'Force':False})[0],200)
        foreign=create(intent['staticIpv4'])
        with self.assertRaises(CreationDenied):e.run(4)
        self.assertEqual(e.t.read()['state'],'IN_FLIGHT')
        self.assertTrue(engine.request('GET','/v1.44/containers/'+foreign['Id']+'/json')[1]['State']['Running'])
    def test_dynamically_allocated_legacy_endpoint_is_released_by_observed_binding(self):
        e,engine,intent,create=self.endpoint(legacy_dynamic=True);e.run(3)
        self.death_after(e,'RELEASE_OLD_ENDPOINT',4);e.run(4);e.run(4)
        old=engine.request('GET','/v1.44/containers/'+intent['containerId']+'/json')[1]
        self.assertNotIn(intent['networkName'],old['NetworkSettings']['Networks']);self.assertEqual(old['State']['Status'],'exited')

if __name__=='__main__':
    names=[n for n in NativeEndpoint.__dict__ if n.startswith('test_')]
    result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(NativeEndpoint(n) for n in names))
    if result.wasSuccessful():print('OUF_ENDPOINT_EXECUTOR_NATIVE='+json.dumps({'status':'PASS','tests':result.testsRun,'actualPrivateBridgeAndStaticIpv4':True,'actualControllerProcessDeath':True,'disconnectReplayDenied':True,'independentPeerGenerationPreserved':True,'foreignIpAllocationDenied':True,'authorityAndLeaseAndDatabaseSynthetic':True,'targetApplied':False,'targetInstallerQualified':False,'notReleaseAcceptance':True}))
    raise SystemExit(not result.wasSuccessful())
