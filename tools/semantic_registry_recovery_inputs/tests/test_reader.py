import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('recovery_inputs',ROOT/'reader.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
old_spec=importlib.util.spec_from_file_location('producer_contract_tests',ROOT.parent/'semantic_retained_endpoint_inventory_v2/tests/test_reader.py')
old=importlib.util.module_from_spec(old_spec);old_spec.loader.exec_module(old)

class Tests(unittest.TestCase):
    def setUp(self):
        f=old.Tests();f.setUp()
        self.case=json.loads((ROOT/'case.json').read_text())
        self.gateway=f.gateway;self.review=f.review;self.packet=f.packet;self.journal=f.journal;self.rows=f.rows
        self.registry=copy.deepcopy(self.gateway)
        self.registry.update(Id=self.case['historicalRegistryId'],Image='sha256:historical',RestartCount=0)
        self.registry['State'].update(Status='exited',Running=False,Pid=0,ExitCode=143,OOMKilled=False)
        self.registry['Config']['Labels']={'org.opencontainers.image.source':'PRIVATE_FIXTURE_SOURCE'}
        self.registry['NetworkSettings']['Networks']={'fixture':{'IPAMConfig':{'IPv4Address':'192.0.2.2'}}}
        self.rows[0].update(ImageID='sha256:historical',Labels={'org.opencontainers.image.source':'PRIVATE_FIXTURE_SOURCE'})
        self.guard={'ActiveState':'active','SubState':'exited','Result':'success'}

    def execute(self,mutation=None,boot_drift=False,guard_drift=False):
        owner=self
        class Engine(m.Engine):
            def get(self,path):
                owner.assertIn(path,self.paths);owner.assertLess(self.calls,6);self.calls+=1
                if path==self.inventory_path:value=owner.rows
                elif owner.case['historicalRegistryId'] in path:value=owner.registry
                else:value=owner.gateway
                value=copy.deepcopy(value)
                if mutation:mutation(self.calls,value)
                return json.dumps(value).encode()
        def read(path):
            if path=='/etc/ouf/deploy-snapshots/fixture-boot.json':return {},b'changed' if boot_drift else b'boot'
            name=Path(path).stem
            return {'review':owner.review,'recovery':owner.journal,'packet':owner.packet}[name],name.encode()
        guards=[self.guard,dict(self.guard,ActiveState='failed') if guard_drift else self.guard]
        with patch.object(m,'Engine',Engine),patch.object(m,'private_json',read),patch.object(m,'loaded_guard',side_effect=guards),\
             patch.object(m,'boot_inputs',return_value=({'journals':{},'journalObservationIsRuntimeAuthority':False},
                   {'/etc/ouf/deploy-snapshots/fixture-boot.json':b'boot'})):
            return m.run(self.case)

    def test_complete_six_get_flow_maps_82_routes_and_redacts(self):
        result=self.execute()
        self.assertEqual(result['engineGets'],6);self.assertEqual(result['guardShows'],2)
        h=result['historicalRegistry']
        self.assertEqual(h['retainedNodeMatchesConfiguredAddress'],[True])
        self.assertEqual(h['imageFamilyCandidates'][0]['containerId'],'b'*64)
        self.assertTrue(h['sourceLabelComparisonAvailable']);self.assertTrue(h['otherRegistryImagesNotExcluded'])
        for key in ('currentRegistryIdentityEstablished','rootCauseEstablished','liveGatewayRouteMapRead',
                    'serviceReadinessEstablished','activationResubmitted','automaticReplayAllowed','budgetReset'):
            self.assertFalse(result[key])
        for secret in ('PRIVATE_FIXTURE','192.0.2.','sourceLabel\"','Env','Command'):
            self.assertNotIn(secret,json.dumps(result))

    def test_absent_matching_family_is_not_global_absence(self):
        self.rows[0].update(ImageID='sha256:different',Labels={})
        result=self.execute()['historicalRegistry']
        self.assertEqual(result['imageFamilyCandidates'],[])
        self.assertTrue(result['otherRegistryImagesNotExcluded'])

    def test_new_image_same_source_and_missing_source_are_distinct(self):
        self.rows[0]['ImageID']='sha256:different'
        result=self.execute()['historicalRegistry']['imageFamilyCandidates'][0]
        self.assertFalse(result['sameHistoricalImage']);self.assertTrue(result['sameHistoricalSourceLabel'])
        self.registry['Config']['Labels']={}
        self.assertFalse(self.execute()['historicalRegistry']['sourceLabelComparisonAvailable'])

    def test_lifecycle_fields_cannot_expose_arbitrary_inspect_values(self):
        for key,value in [('Status','PRIVATE_FIXTURE'),('Running','PRIVATE_FIXTURE'),('ExitCode','PRIVATE_FIXTURE'),('Pid',True)]:
            before=copy.deepcopy(self.registry['State'])
            self.registry['State'][key]=value
            with self.assertRaisesRegex(m.Stop,'BOUNDED_HISTORICAL_LIFECYCLE'):self.execute()
            self.registry['State']=before

    def test_drift_each_resource_and_boot_stops(self):
        for target in (4,5,6):
            def mutate(call,value):
                if call==target:
                    if type(value) is list:value[0]['State']='exited'
                    else:value['Config']['Env']=['changed']
            with self.assertRaises(m.Stop):self.execute(mutation=mutate)
        with self.assertRaisesRegex(m.Stop,'BOOT_METADATA_CHANGED'):self.execute(boot_drift=True)
        with self.assertRaisesRegex(m.Stop,'LOADED_GUARD_STATE_CHANGED'):self.execute(guard_drift=True)

    def test_family_bound_and_closed_transport(self):
        self.rows=[dict(self.rows[0],Id=format(i,'064x'),NetworkSettings={'Networks':{}}) for i in range(33)]
        with self.assertRaisesRegex(m.Stop,'BOUNDED_IMAGE_FAMILY'):self.execute()
        engine=m.Engine({},'a'*64,'b'*64)
        for path in ('/v1.44/containers/name/json','/v1.44/containers/a/start','/v1.44/containers/a/logs'):
            with self.assertRaises(m.Stop):engine.get(path)
        engine.calls=6
        with self.assertRaises(m.Stop):engine.get(engine.inventory_path)

    def boot_fixture(self):
        base='/etc/ouf/deploy-snapshots/fixture/'
        owner={'kernel':{'tableName':'fixture'},'commonLockFile':'/run/fixture.lock','journalFile':base+'owner.json'}
        boot={'kernel':owner['kernel'],'lockFile':owner['commonLockFile'],'journalFile':base+'boot.json'}
        profile={'schema':'ouf.semantic-coordinated-boot-profile.v1',
                 'coordinatedConfiguration':base+'owner-config.json','bootConfiguration':base+'boot-config.json'}
        data={profile['coordinatedConfiguration']:owner,profile['bootConfiguration']:boot,
              owner['journalFile']:{'state':'BLOCKED','startAuthorized':False,'leaseAuthorized':False,
                                    'leaseAddresses':[[],[]],'privateKey':'PRIVATE_FIXTURE'},
              boot['journalFile']:{'state':'RUNTIME_EMPTY','startAuthorized':False}}
        for key in ('coordinatedConfiguration','bootConfiguration'):
            profile[key+'Hash']=m.hashlib.sha256(m.encoded(data[profile[key]])).hexdigest()
        data[self.case['bootProfilePath']]=profile
        case=copy.deepcopy(self.case);case['bootProfileSha256']=m.hashlib.sha256(m.encoded(profile)).hexdigest()
        return case,data,profile,owner,boot

    def boot_run(self,case,data):
        with patch.object(m,'private_json',side_effect=lambda p:(data[p],m.encoded(data[p]))):return m.boot_inputs(case)

    def test_exact_sealed_boot_chain_and_safe_journal_projection(self):
        case,data,profile,owner,boot=self.boot_fixture()
        result,saved=self.boot_run(case,data)
        self.assertEqual(len(saved),5)
        self.assertEqual(result['journals']['coordinatedOwner']['state'],'BLOCKED')
        self.assertEqual(result['journals']['coordinatedOwner']['leaseAddressCounts'],[0,0])
        self.assertFalse(result['journalObservationIsRuntimeAuthority'])
        self.assertFalse(result['providerRegistryAssociationEstablished'])
        self.assertNotIn('PRIVATE_FIXTURE',json.dumps(result))

    def test_boot_hash_pair_and_path_mismatch_fail_closed(self):
        case,data,profile,owner,boot=self.boot_fixture()
        case['bootProfileSha256']='0'*64
        with self.assertRaisesRegex(m.Stop,'EXACT_BOOT_PROFILE'):self.boot_run(case,data)
        case,data,profile,owner,boot=self.boot_fixture()
        boot['lockFile']='/run/other'
        with self.assertRaisesRegex(m.Stop,'BOOT_CONFIGURATION_HASH'):self.boot_run(case,data)
        case,data,profile,owner,boot=self.boot_fixture()
        profile['coordinatedConfiguration']='/outside/scope'
        case['bootProfileSha256']=m.hashlib.sha256(m.encoded(profile)).hexdigest()
        with self.assertRaisesRegex(m.Stop,'BOOT_METADATA_SCOPE'):self.boot_run(case,data)

    def test_journal_unsupported_states_and_lease_limits(self):
        case,data,profile,owner,boot=self.boot_fixture()
        data[owner['journalFile']]['state']='PRIVATE_FIXTURE'
        self.assertEqual(self.boot_run(case,data)[0]['journals']['coordinatedOwner']['state'],'UNRECOGNIZED_STATE_REDACTED')
        data[owner['journalFile']]['leaseAddresses']=[[]]*17
        with self.assertRaisesRegex(m.Stop,'BOUNDED_LEASE_METADATA'):self.boot_run(case,data)

    def guard_reply(self,path=None,digest=None):
        return ('ActiveState=active\nSubState=exited\nResult=success\nExecStart={ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 '+
                str(Path(self.case['bootProfilePath']).parent/'source/scripts/run_semantic_coordinated_boot_guard.py')+' '
                '--configuration '+(path or self.case['bootProfilePath'])+' --configuration-sha256 '+
                (digest or self.case['bootProfileSha256'])+' ; }\n').encode()

    def test_guard_show_contract_only_and_loaded_binding(self):
        fake=types.SimpleNamespace(st_uid=0,st_mode=0o100755)
        def metadata(path):return fake if str(path)=='/usr/bin/systemctl' else types.SimpleNamespace(st_uid=0,st_mode=0o40755)
        calls=[]
        def run(args,**kwargs):
            calls.append(args)
            self.assertEqual(args[1:4],['show','--no-pager','--property=ExecStart,ActiveState,SubState,Result'])
            self.assertEqual(kwargs['stdin'],subprocess.DEVNULL)
            return types.SimpleNamespace(returncode=0,stdout=self.guard_reply(),stderr=b'')
        with patch.object(Path,'lstat',metadata),patch.object(m.subprocess,'run',run):
            self.assertEqual(m.loaded_guard(self.case),self.guard)
        self.assertEqual(len(calls),1)

    def test_guard_drift_timeout_and_duplicate_properties(self):
        def metadata(path):return types.SimpleNamespace(st_uid=0,st_mode=0o100755 if str(path)=='/usr/bin/systemctl' else 0o40755)
        with patch.object(Path,'lstat',metadata):
            for raw in (self.guard_reply(digest='0'*64),self.guard_reply()+b'Result=success\n'):
                with patch.object(m.subprocess,'run',return_value=types.SimpleNamespace(returncode=0,stdout=raw,stderr=b'')):
                    with self.assertRaises(m.Stop):m.loaded_guard(self.case)
            with patch.object(m.subprocess,'run',side_effect=subprocess.TimeoutExpired('show',6)):
                with self.assertRaises(subprocess.TimeoutExpired):m.loaded_guard(self.case)

if __name__=='__main__':unittest.main()
