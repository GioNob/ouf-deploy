"""Deterministic collector tests; native target reads are explicit fixtures."""
import copy,json,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
TOKEN=ROOT if (ROOT/'tools/semantic_policy_token_owner/owner_installation.py').exists() else ROOT.parent/'token-owner-installer-work'
COHORT=ROOT if (ROOT/'tools/chatbot_file_cohort/preparation.py').exists() else ROOT.parent/'cohort-delivery-work'
sys.path[:0]=[str(COHORT),str(TOKEN),str(ROOT),str(ROOT/'tests'),str(TOKEN/'tools/semantic_policy_token_owner'),
    str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_database_cutover'),
    str(ROOT/'tools/semantic_frame_compiler'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import file_only_preparation as prep
from file_only_frame_inputs import compile_inputs,ENGINE,BASELINE_SHA256
from test_file_only_frame_compiler import FourMountCompiler
from compile_file_only_frame_policy import compile_policy
from file_only_profile import FileOnlyProfile,PHASES
from transition_journal import digest

class Preparation(unittest.TestCase):
    def inputs(self):
        _,launch,context,args=FourMountCompiler().fixture()
        request=copy.deepcopy(args['execution_profile'].request);tree=args['execution_profile'].configtree
        request.update(WorkingDir='/app',Cmd=[])
        request['HostConfig'].update(ReadonlyRootfs=False,CapDrop=['ALL'],SecurityOpt=['no-new-privileges:true'],
            Memory=536870912,MemorySwap=536870912,PidsLimit=256,NanoCpus=1000000000)
        return request,tree,launch['sources'][0],args['renewable_token'],args['proposal_receipt_key'],context

    def test_independent_baseline_compiles_complete_four_mount_policy(self):
        request,tree,key,token,proposal,context=self.inputs()
        raw=(ROOT/'tools/semantic_frame_compiler/containerd-overlayfs-southbound.json').read_bytes()
        template,launch=compile_inputs(raw,request,tree,token,key,proposal,ENGINE)
        result=compile_policy(template,launch,context,execution_profile=FileOnlyProfile(request,tree),
            renewable_token=token,delegation_key_metadata_hash='d'*64,proposal_receipt_key=proposal)
        self.assertEqual(len(result['manifest']['mounts']),4)
        self.assertEqual(result['expectedOci']['linux']['resources']['cpu'],{'period':100000,'quota':100000})
        self.assertEqual(result['expectedOci']['linux']['seccomp'],json.loads(raw)['template']['expectedOci']['linux']['seccomp'])
        self.assertEqual(result['startup']['args'],request['Entrypoint'])
        self.assertNotIn('$OUF_',str(result));self.assertFalse(result.get('acceptanceGranted',False))

    def test_baseline_bytes_engine_kernel_and_resource_drift_rejected(self):
        raw=(ROOT/'tools/semantic_frame_compiler/containerd-overlayfs-southbound.json').read_bytes()
        for kind in ('baseline','engine','cpu','sysctl','writable'):
            with self.subTest(kind=kind):
                request,tree,key,token,proposal,_=self.inputs();data=raw;engine=copy.deepcopy(ENGINE)
                if kind=='baseline':data+=b' '
                if kind=='engine':engine['serverVersion']='29.8.2'
                if kind=='cpu':request['HostConfig']['NanoCpus']=123456789
                if kind=='sysctl':request['HostConfig']['Sysctls']={'net.ipv4.ip_forward':'1'}
                if kind=='writable':request['HostConfig']['ReadonlyRootfs']=True
                with self.assertRaises(ValueError):compile_inputs(data,request,tree,token,key,proposal,engine)

    def test_exact_retained_selection_is_not_newest_search(self):
        selected=prep.default_selection()
        self.assertEqual(set(selected),{'installationReview','declaration','creationRequest','coordinationIntake'})
        self.assertEqual(selected['installationReview']['sha256'],prep.INSTALLATION_REVIEW_HASH)
        self.assertTrue(selected['coordinationIntake']['path'].endswith(selected['coordinationIntake']['sha256']+'/intake.json'))

    def database(self,superuser=True,history=None):
        migrations=[{'version':'1','type':'SQL','script':'V1__init.sql','checksum':123,'success':True}]
        calls=[]
        class Channel:
            def __init__(self,cid,user,database,name):self.user,self.database=user,database;calls.append((cid,user,database,name))
            def query(self,sql,timeout):
                if 'rolsuper' in sql:return {'user':self.user,'database':self.database,'superuser':superuser}
                if 'json_agg' in sql:return migrations if history is None else history
                return {'name':'semantic','oid':1234,'allowConnections':True,'prepared':0}
            def close(self):pass
        pg={'Id':'b'*64,'Name':'/ouf-postgres','Config':{'Hostname':'pg','Env':['POSTGRES_USER=bootstrap']},
            'NetworkSettings':{'Networks':{'ouf-backend':{'Aliases':['pg'],'IPAddress':'10.42.0.3'}}}}
        request={'Env':['OUF_SEM_DB_URL=jdbc:postgresql://pg:5432/semantic','OUF_SEM_DB_USER=semantic_app']}
        return Channel,calls,pg,request,migrations

    def test_preflight_proves_distinct_admin_before_any_cutover_effect(self):
        Channel,calls,pg,request,migrations=self.database()
        with patch.object(prep,'Psql',Channel):result=prep.registry_database(pg,request,migrations)
        self.assertEqual((result['user'],result['adminUser']),('semantic_app','bootstrap'))
        self.assertEqual([(c[1],c[2]) for c in calls],[('semantic_app','semantic'),('bootstrap','postgres')])
        Channel,calls,pg,request,migrations=self.database(superuser=False)
        with patch.object(prep,'Psql',Channel),self.assertRaisesRegex(ValueError,'PRIVILEGED_REGISTRY_FENCE_OWNER'):
            prep.registry_database(pg,request,migrations)

    def test_migration_checksum_or_database_peer_drift_rejected(self):
        Channel,calls,pg,request,migrations=self.database(history=[])
        with patch.object(prep,'Psql',Channel),self.assertRaisesRegex(ValueError,'MIGRATION_PREFIX'):
            prep.registry_database(pg,request,migrations)
        self.assertEqual(len(calls),1)
        request['Env'][0]='OUF_SEM_DB_URL=jdbc:postgresql://different:5432/semantic'
        with patch.object(prep,'Psql',Channel),self.assertRaisesRegex(ValueError,'SELECTED_POSTGRES'):
            prep.registry_database(pg,request,migrations)

    def producer(self,letter):
        return {'Id':letter*64,'Image':'sha256:'+'f'*64,'State':{'Pid':12,'StartedAt':'2026-10-14T01:00:00Z'},
            'Config':{'Env':[]},'HostConfig':{'RestartPolicy':{'Name':'unless-stopped','MaximumRetryCount':0}},'Mounts':[],
            'NetworkSettings':{'Networks':{'ouf-backend':{'NetworkID':'9'*64,'EndpointID':letter*64,
                'IPAddress':'10.42.0.2','MacAddress':'02:42:0a:2a:00:02'}}}}

    def test_all_eleven_intents_bind_same_package_and_retire_five_generations(self):
        request,tree,key,token,proposal,context=self.inputs();producers=[self.producer(c) for c in 'abcdef']
        cohort={'replacements':[{'oldRuntimeBinding':{'containerId':p['Id']}} for p in producers[1:5]]}
        paths={'backup':'/fixture/action/registry/backup'}
        db={'adminUser':'bootstrap','database':'semantic','databaseOid':1234}
        recipe={'sourceClosureHash':'1'*64,'qualifiedPackageHash':'2'*64,'imageConfigurationHash':'3'*64}
        network={'Name':'ouf-backend','Id':'9'*64}
        intents=prep.phase_intents(request,producers,network,db,{'Id':'8'*64},{'retained':True},recipe,{'db':'fixture'},paths,cohort)
        self.assertEqual(tuple(intents),PHASES)
        release=intents['RELEASE_PRODUCERS'];self.assertEqual(release['retiredContainerIds'],[p['Id'] for p in producers[:5]])
        self.assertEqual(release['releaseProducerIds'],[producers[5]['Id']])
        self.assertEqual(intents['FENCED_BACKUP']['user'],'bootstrap')
        self.assertEqual(intents['ATTEST_NEW_OCI_PEER']['nodeRecipeHash'],digest(recipe))
        self.assertEqual(release['cohortReviewHash'],digest(cohort))

    def test_creation_binds_new_token_file_without_disabling_iam(self):
        request,tree,key,token,proposal,context=self.inputs();old=self.producer('a')
        request['Env']+=['OUF_AUTHORIZATION_REGISTRY_TOKEN_FILE='+token['target']+'/old.jwt',
            'OUF_CONSULTATION_KEY='+key['target'],'OUF_IAM_ENABLED=true']
        request['NetworkingConfig']={'EndpointsConfig':{'ouf-backend':{'NetworkID':'9'*64,
            'MacAddress':'02:42:0a:2a:00:02','IPAMConfig':{'IPv4Address':'10.42.0.2'}}}}
        audit={'imageId':request['Image'],'imageConfig':{'User':'10001:10001','Entrypoint':request['Entrypoint'],
            'Cmd':[],'Volumes':{},'Env':['PATH=/usr/bin:/bin'],'WorkingDir':'/app'}}
        result=prep.creation(request,{'retainedNativeCreationFrame':old},old,audit,tree,token,key,proposal,
            {'issuer':'gateway','audience':'semantic','workload':'ouf-semantic'})
        env=prep.environment(result['Env'])
        self.assertEqual(env['OUF_AUTHORIZATION_REGISTRY_TOKEN_FILE'],token['target']+'/'+token['fileName'])
        self.assertEqual(env['OUF_IAM_ENABLED'],'true')
        self.assertEqual(len(result['HostConfig']['Binds']),4)
        self.assertEqual(result['Cmd'],audit['imageConfig']['Entrypoint'])
        request['Env'][-1]='OUF_IAM_ENABLED=false'
        with self.assertRaisesRegex(ValueError,'IAM_CANNOT_BE_DISABLED'):
            prep.creation(request,{'retainedNativeCreationFrame':old},old,audit,tree,token,key,proposal,
                {'issuer':'gateway','audience':'semantic','workload':'ouf-semantic'})

if __name__=='__main__':unittest.main()
