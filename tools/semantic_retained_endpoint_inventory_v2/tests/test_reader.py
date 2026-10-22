import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('inventory_reader',ROOT/'reader.py')
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
producer_spec=importlib.util.spec_from_file_location('route_map_producer',ROOT/'tests/fixtures/route_map_producer.py')
producer=importlib.util.module_from_spec(producer_spec)
producer_spec.loader.exec_module(producer)

def map_rows(rows):
    return producer.route_map([{'value':dict(row,id='route-'+str(i))} for i,row in enumerate(rows)])

class Tests(unittest.TestCase):
    def setUp(self):
        self.case=json.loads((ROOT/'case.json').read_text())
        self.cid='a'*64
        self.gateway={'Id':self.cid,'Image':'sha256:fixture','Config':{'Env':['PRIVATE_FIXTURE']},
            'HostConfig':{},'Mounts':[],'RestartCount':0,
            'State':{'Pid':12,'StartedAt':'2026-10-21T01:00:00Z','Running':True},
            'NetworkSettings':{'Networks':{'fixture':{'NetworkID':'net1','IPAddress':'192.0.2.1'}}}}
        self.pin={'containerId':self.cid,'imageId':self.gateway['Image'],'pid':12,
            'startedAt':self.gateway['State']['StartedAt'],
            **{key:m.digest(self.gateway[field]) for field,key in [('Config','configHash'),
              ('HostConfig','hostConfigHash'),('NetworkSettings','networkSettingsHash')]}}
        self.route={'uri':m.OPERATION,'methods':['GET'],'upstream':{'nodes':{'192.0.2.2:8080':1}}}
        routes=map_rows([self.route]+[{'uri':'/fixture/'+str(i)} for i in range(81)])
        self.packet={'routeDraft':{'beforeRoutes':routes,'afterRoutes':copy.deepcopy(routes)}}
        self.review={'executionReview':{'stages':[{}]*12,'packetBinding':{
            'path':self.case['contextPath']+'/packet.json','sha256':m.digest(self.packet)},
            'engineBinding':{},'runtimeGuardProfile':{'unchangedApplications':{'gateway':{'binding':self.pin}}}}}
        self.journal={'nextStage':12,'effects':[{'state':'APPLIED'}]*12}
        self.rows=[{'Id':'b'*64,'ImageID':'sha256:fixture','State':'running',
            'Names':['PRIVATE_FIXTURE'],'Command':'PRIVATE_FIXTURE',
            'NetworkSettings':{'Networks':{'fixture':{'NetworkID':'net1','IPAddress':'192.0.2.2'}}}}]

    def execute(self, mutation=None, read_drift=False):
        owner=self
        class Engine(m.Engine):
            def get(self,path):
                owner.assertIn(path,self.paths)
                owner.assertLess(self.calls,4)
                self.calls+=1
                value=copy.deepcopy(owner.rows if path==self.inventory_path else owner.gateway)
                if mutation: mutation(self.calls,value)
                return json.dumps(value).encode()
        reads=[0]
        def read(path):
            reads[0]+=1
            name=Path(path).stem
            value={'review':owner.review,'recovery':owner.journal,'packet':owner.packet}[name]
            return value,b'changed' if read_drift and reads[0]>3 else name.encode()
        with patch.object(m,'Engine',Engine),patch.object(m,'private_json',read):
            return m.run(self.case)

    def test_full_four_get_path_and_safe_output(self):
        result=self.execute()
        self.assertEqual(result['engineGets'],4)
        row=result['retainedSemanticNodeComparisons'][0]['candidates'][0]
        self.assertEqual(row['containerId'],'b'*64)
        self.assertTrue(row['sharesObservedGatewayNetwork'])
        for key in ('currentRegistryIdentityEstablished','rootCauseEstablished','liveGatewayRouteMapRead',
                    'serviceReadinessEstablished','activationResubmitted','automaticReplayAllowed'):
            self.assertFalse(result[key])
        for value in ('192.0.2.','PRIVATE_FIXTURE','Env','Command','Names'):
            self.assertNotIn(value,json.dumps(result))

    def test_no_candidate_and_external_network_are_not_health_proofs(self):
        self.rows=[]
        result=self.execute()['retainedSemanticNodeComparisons'][0]
        self.assertEqual(result['candidates'],[])
        self.assertTrue(result['noCandidateDoesNotProveUnreachable'])
        self.setUp()
        self.rows[0]['NetworkSettings']['Networks']['fixture']['NetworkID']='net2'
        result=self.execute()['retainedSemanticNodeComparisons'][0]['candidates'][0]
        self.assertFalse(result['sharesObservedGatewayNetwork'])

    def test_dns_never_resolved(self):
        result=m.compare([('private.invalid',8080)],{},self.gateway)[0]
        self.assertFalse(result['literalAddress'])
        self.assertFalse(result['dnsResolutionPerformed'])

    def test_exact_route_ambiguity_and_indirection_stop(self):
        for rows in ({},map_rows([self.route,self.route]),map_rows([dict(self.route,uri=m.OPERATION+'other')]),
                     map_rows([dict(self.route,upstream_id='private')]),map_rows([dict(self.route,service_id='private')])):
            with self.assertRaises(m.Stop):m.retained_nodes(rows)
        with self.assertRaises(m.Stop):
            m.retained_nodes(map_rows([dict(self.route,upstream={'discovery_type':'dns','nodes':{'private:80':1}})]))

    def test_ipv6_list_nodes_and_no_credentials_in_node(self):
        self.assertEqual(m.retained_nodes(map_rows([dict(self.route,upstream={'nodes':{'[2001:db8::2]:8080':1}})])),
                         [('2001:db8::2',8080)])
        self.assertEqual(m.retained_nodes(map_rows([dict(self.route,upstream={'nodes':[
            {'host':'192.0.2.2','port':8080,'weight':1}]})])),[('192.0.2.2',8080)])
        for node in ('user:secret@192.0.2.2:80','192.0.2.2:80/path','192.0.2.2:70000'):
            with self.assertRaises(m.Stop):
                m.retained_nodes(map_rows([dict(self.route,upstream={'nodes':{node:1}})]))

    def test_actual_producer_map_contract_and_82_route_packet(self):
        routes=self.packet['routeDraft']['beforeRoutes']
        self.assertIs(type(routes),dict)
        self.assertEqual(len(routes),82)
        self.assertEqual(producer.route_map([{'value':{'value':v}} for v in routes.values()]),routes)
        self.assertEqual(m.retained_nodes(routes),[('192.0.2.2',8080)])
        self.assertTrue(self.execute()['complete'])

    def test_lists_envelopes_wrong_ids_and_oversized_maps_rejected(self):
        for routes in ([self.route],{'list':[self.route]}, {'wrong':dict(self.route,id='other')},
                       map_rows([self.route]+[{'uri':'/fixture/'+str(i)} for i in range(255)])|{'extra':{'id':'extra'}}):
            with self.assertRaises(m.Stop):m.retained_nodes(routes)
        with self.assertRaises(ValueError):
            producer.route_map([{'id':'same'},{'id':'same'}])

    def test_invalid_map_stops_before_any_engine_construction(self):
        self.packet['routeDraft']['beforeRoutes']=[self.route]
        self.review['executionReview']['packetBinding']['sha256']=m.digest(self.packet)
        with patch.object(m,'Engine',side_effect=AssertionError('Engine must not be constructed')):
            def read(path):
                name=Path(path).stem
                return {'review':self.review,'recovery':self.journal,'packet':self.packet}[name],b'fixture'
            with patch.object(m,'private_json',read):
                with self.assertRaisesRegex(m.Stop,'BOUNDED_RETAINED_ROUTE_MAP_REQUIRED'):m.run(self.case)

    def test_inventory_and_gateway_drift_stop(self):
        def inventory_drift(call,value):
            if call==3:value[0]['State']='exited'
        def gateway_drift(call,value):
            if call==4:value['State']['Pid']=13
        def config_drift(call,value):
            if call==1:value['Config']={}
        for mutation in (inventory_drift,gateway_drift,config_drift):
            with self.assertRaises(m.Stop):self.execute(mutation)

    def test_packet_journal_and_metadata_drift_stop(self):
        with self.assertRaisesRegex(m.Stop,'RETAINED_CONTEXT_CHANGED'):self.execute(read_drift=True)
        self.review['executionReview']['packetBinding']['sha256']='0'*64
        with self.assertRaisesRegex(m.Stop,'EXACT_RETAINED_PACKET'):self.execute()
        self.setUp()
        self.journal['effects'][0]['state']='CLAIMED'
        with self.assertRaisesRegex(m.Stop,'COMPLETED_PATCH'):self.execute()

    def test_inventory_limits_duplicates_and_closed_transport(self):
        for rows in ([self.rows[0]]*257,[self.rows[0]]*2):
            self.rows=rows
            with self.assertRaises(m.Stop):self.execute()
            self.setUp()
        engine=m.Engine({},self.cid)
        with self.assertRaises(m.Stop):engine.get('/v1.44/containers/json?all=true')
        engine.calls=4
        with self.assertRaises(m.Stop):engine.get(engine.inventory_path)

if __name__=='__main__':unittest.main()
