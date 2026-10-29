import copy
import importlib.util
import json
from pathlib import Path
import unittest

s=importlib.util.spec_from_file_location('creation',Path(__file__).resolve().parents[1]/'tools/semantic_application_cutover/creation_plan.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)


class CreationPlan(unittest.TestCase):
    def fixture(self):
        original={'Id':'a'*64,'Image':'sha256:'+'b'*64,
          'State':{'Pid':1234,'StartedAt':'fixed','Running':True},
          'Config':{'User':'10001:10001','Env':['OUF_SEM_DB_PASSWORD=fixture-secret'],
                    'Labels':{'fixture':'retained'},'Entrypoint':['java'],'Cmd':['-jar','/app.jar']},
          'HostConfig':{'Privileged':False,'Runtime':'runc','NetworkMode':'ouf-fixture',
              'ContainerIDFile':'','Binds':['/retained:/retained:ro'],
              'RestartPolicy':{'Name':'unless-stopped','MaximumRetryCount':0},
              'Memory':0,'MemorySwap':0,'NanoCpus':0,'PidsLimit':None,
              'ReadonlyRootfs':True,'SecurityOpt':['no-new-privileges'],
              'CapDrop':['ALL'],'LogConfig':{'Type':'json-file','Config':{'max-size':'1m'}},
              'PortBindings':{},'Ulimits':[{'Name':'nofile','Soft':4096,'Hard':4096}]},
          'Mounts':[{'Source':'/retained','Destination':'/retained','RW':False}],
          'NetworkSettings':{'Networks':{'ouf-fixture':{'NetworkID':'c'*64,
              'IPAddress':'172.30.77.6','MacAddress':'02:42:ac:1e:4d:06',
              'Aliases':['ouf-semantic','a'*64, 'a'*12],'GlobalIPv6Address':''}}}}
        mounts=[{'source':'/inputs/'+key,'target':'/run/'+key,'readOnly':True,
            'uid':10001,'gid':10001,'mode':0o400} for key in ('auth','discovery','trust')]
        secret={'sourceDirectory':'/inputs/database','targetDirectory':'/run/database',
            'readOnly':True,'directoryUid':10001,'directoryGid':10001,'directoryMode':0o500,
            'file':{'name':'OUF_SEM_DB_PASSWORD','uid':10001,'gid':10001,'mode':0o400}}
        adds=[r['source']+':'+r['target']+':ro' for r in mounts]+['/inputs/database:/run/database:ro']
        proposed=copy.deepcopy(original['HostConfig']);proposed['Binds']+=adds
        proposed['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
        config=copy.deepcopy(original['Config']);config['Env']=['SPRING_CONFIG_IMPORT=configtree:/run/database/']
        d={'schema':'ouf.discovery.private-file-secret-runtime-declaration.v1',
           'candidateImageId':'sha256:'+'d'*64,'candidateConfig':config,'proposedHostConfig':proposed,
           'retainedNativeCreationFrame':original,'roleOwnedReadOnlyMounts':mounts,
           'databaseSecretProjection':secret,'hostDelta':{'appendedReadOnlyBinds':adds},
           'productionApplyReady':False,'applicationCutoverAuthorized':False,'completeReplacementOciProven':False}
        h={'status':'CURRENT_CUTOVER_HOST_METADATA_CAPTURED','semantic':{
            'containerId':original['Id'],'imageId':original['Image'],'generation':original['State'],
            'installedConfigHash':m.digest(original['Config']),
            'installedHostConfigHash':m.digest(original['HostConfig']),
            'installedMountsHash':m.digest(original['Mounts']),
            'networkSettingsHash':m.digest(original['NetworkSettings'])},
           'resources':{'MemAvailableBytes':11216740352,'rootFilesystemFreeBytes':466539782144}}
        return d,h

    def compile(self,d,h,**kw):return m.compile_creation(d,m.digest(d),h,**kw)

    def test_lossless_private_creation_and_explicit_resources_without_authority_promotion(self):
        d,h=self.fixture();before=copy.deepcopy(d)
        request,public=self.compile(d,h)
        self.assertEqual(d,before)
        for field,value in d['candidateConfig'].items():self.assertEqual(request[field],value)
        for field,value in d['proposedHostConfig'].items():
            if field not in ('Memory','MemorySwap','NanoCpus','PidsLimit'):
                self.assertEqual(request['HostConfig'][field],value)
        self.assertEqual(request['HostConfig']['Memory'],2147483648)
        self.assertEqual(request['HostConfig']['MemorySwap'],2147483648)
        self.assertEqual(request['HostConfig']['NanoCpus'],2000000000)
        self.assertEqual(request['HostConfig']['PidsLimit'],512)
        self.assertNotIn('fixture-secret',json.dumps(public))
        self.assertNotIn('/inputs/',json.dumps(public))
        self.assertEqual(public['status'],'PLAN_ONLY_NOT_AUTHORITY')
        for field in ('productionApplyReady','applicationCutoverAuthorized','completeRealizedOciProven',
                      'r12MayBeReplayed','databaseRestoreAuthorized'):self.assertFalse(public[field])
    def test_source_seal_and_current_configuration_generation_drift_rejected(self):
        d,h=self.fixture()
        with self.assertRaisesRegex(ValueError,'SEALED_DECLARATION_HASH_REQUIRED'):
            m.compile_creation(d,'0'*64,h)
        for field in ('containerId','imageId','installedConfigHash','installedHostConfigHash',
                      'installedMountsHash','networkSettingsHash'):
            d,h=self.fixture();h['semantic'][field]='changed'
            with self.subTest(field=field),self.assertRaises(ValueError):self.compile(d,h)
        d,h=self.fixture();h['semantic']['generation']=dict(h['semantic']['generation'],Pid=999)
        with self.assertRaises(ValueError):self.compile(d,h)
    def test_undeclared_host_privilege_ports_mount_and_restart_changes_rejected(self):
        for field,value in [('Privileged',True),('CapDrop',[]),('PortBindings',{'8080/tcp':[{}]}),
                            ('Runtime','foreign'),('NetworkMode','host'),('ReadonlyRootfs',False),
                            ('RestartPolicy',{'Name':'always'})]:
            d,h=self.fixture();d['proposedHostConfig'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.compile(d,h)
        d,h=self.fixture();d['proposedHostConfig']['Binds'][-1]=d['proposedHostConfig']['Binds'][-1][:-2]+'rw'
        with self.assertRaises(ValueError):self.compile(d,h)
    def test_secret_env_optional_import_duplicate_and_projection_custody_rejected(self):
        for value in ['OUF_SEM_DB_PASSWORD=leak','SPRING_DATASOURCE_PASSWORD=leak',
                      'SPRING_CONFIG_IMPORT=optional:configtree:/run/database/']:
            d,h=self.fixture();d['candidateConfig']['Env'].append(value)
            with self.subTest(value=value),self.assertRaises(ValueError):self.compile(d,h)
        d,h=self.fixture();d['databaseSecretProjection']['file']['mode']=0o644
        with self.assertRaises(ValueError):self.compile(d,h)
    def test_finite_memory_cpu_pid_swap_and_control_reserve_admission(self):
        for field,value in [('memoryBytes',0),('memoryBytes',True),('memorySwapBytes',-1),
                            ('nanoCpus',9000000000),('pidsLimit',0),('controlReserveBytes',0)]:
            d,h=self.fixture();r=dict(m.DEFAULT_RESOURCES);r[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.compile(d,h,resources=r)
        for field,value in [('MemAvailableBytes',3000000000),('rootFilesystemFreeBytes',1000)]:
            d,h=self.fixture();h['resources'][field]=value
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'HOST_RESOURCE_HEADROOM_UNPROVEN'):
                self.compile(d,h)
    def test_network_identity_mac_projection_and_generated_aliases(self):
        d,h=self.fixture();d['candidateConfig']['MacAddress']='02:42:ac:1e:4d:06'
        request,public=self.compile(d,h)
        self.assertNotIn('MacAddress',request)
        endpoint=request['NetworkingConfig']['EndpointsConfig']['ouf-fixture']
        self.assertEqual(endpoint['IPAMConfig']['IPv4Address'],'172.30.77.6')
        self.assertEqual(endpoint['MacAddress'],'02:42:ac:1e:4d:06')
        self.assertEqual(endpoint['Aliases'],['ouf-semantic'])
        self.assertIn('EXCLUSIVE_OLD_ENDPOINT_RELEASE_NO_CONCURRENT_IP_MAC_REUSE',public['requiredBeforeEffects'])
        d,h=self.fixture();d['candidateConfig']['MacAddress']='02:00:00:00:00:99'
        with self.assertRaises(ValueError):self.compile(d,h)
    def test_mutable_custody_mount_shadow_and_wrong_user_cannot_be_planned(self):
        d,h=self.fixture();d['candidateConfig']['User']='0:0'
        with self.assertRaises(ValueError):self.compile(d,h)
        d,h=self.fixture();d['roleOwnedReadOnlyMounts'][0]['mode']=0o644
        with self.assertRaises(ValueError):self.compile(d,h)
        d,h=self.fixture();d['roleOwnedReadOnlyMounts'][0]['target']='/run'
        with self.assertRaises(ValueError):self.compile(d,h)
    def test_prior_apply_or_oci_flags_do_not_become_creation_authority(self):
        for field in ('productionApplyReady','applicationCutoverAuthorized','completeReplacementOciProven'):
            d,h=self.fixture();d[field]=True
            with self.subTest(field=field),self.assertRaises(ValueError):self.compile(d,h)


if __name__=='__main__':unittest.main()
