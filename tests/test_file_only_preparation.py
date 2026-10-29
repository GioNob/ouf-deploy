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
    def retained_candidate(self,image_config=None):
        """Target-observed names, source-derived values; no VPS secret values."""
        request,tree,key,token,proposal,context=self.inputs();old=self.producer('a')
        env={'JAVA_HOME':'/opt/java/openjdk','JAVA_VERSION':'fixture-old',
            'LANG':'en_US.UTF-8','LANGUAGE':'en_US:en','LC_ALL':'en_US.UTF-8','PATH':'/usr/bin:/bin',
            'OUF_AUTHORIZATION_MAX_STALENESS_SECONDS':'120','OUF_AUTHORIZATION_REFRESH_SECONDS':'30',
            'OUF_AUTHORIZATION_REGISTRY_TOKEN_FILE':token['target']+'/old.jwt',
            'OUF_AUTHORIZATION_REGISTRY_URL':'https://api.ouf-lab.it/authorization',
            'OUF_IAM_ACTOR_TYPE_CLAIM':'actor_type','OUF_IAM_AUDIENCE':'ouf-api-gateway',
            'OUF_IAM_ENABLED':'true','OUF_IAM_ISSUER':'https://auth.ouf-lab.it/realms/ouf',
            'OUF_SEMANTIC_DELEGATION_KEY_FILE':key['target'],'OUF_SEMANTIC_DELEGATION_WORKLOAD':'ouf-mcp-server',
            'OUF_SEM_DB_URL':'jdbc:postgresql://ouf-postgres:5432/ouf_semantic','OUF_SEM_DB_USER':'ouf_semantic'}
        native={**env,'OUF_SEM_DB_PASSWORD':'DISPOSABLE_NOT_A_TARGET_PASSWORD'}
        old['Config']['Env']=[k+'='+v for k,v in native.items()]
        # Independent historical literal from compose-semantic-replacement-draft.py.
        env.update({'JAVA_TOOL_OPTIONS':'-Djavax.net.ssl.trustStore=/run/ouf-discovery-trust/java-truststore.p12 '
            '-Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword=changeit',
            'SPRING_CONFIG_IMPORT':'configtree:'+tree['target']+'/',
            'OUF_SCHEMA_GOV_ENABLED':'true','OUF_SCHEMA_GOV_GATEWAY_AUTH_ENABLED':'true',
            'OUF_SCHEMA_GOV_GATEWAY_BASE_URL':'https://ouf-semantic-southbound-v2:10443',
            'OUF_SCHEMA_GOV_SEARCH_PATH':'/internal/providers/schema-gov/search',
            'OUF_SCHEMA_GOV_FETCH_PATH':'/internal/providers/schema-gov/fetch',
            'OUF_SCHEMA_GOV_TOKEN_ENDPOINT':env['OUF_IAM_ISSUER']+'/protocol/openid-connect/token',
            'OUF_SCHEMA_GOV_CLIENT_ID':'ouf-semantic','OUF_SCHEMA_GOV_CLIENT_SECRET_FILE':'/run/secrets/schema-gov-client-secret',
            'OUF_SCHEMA_GOV_WORKLOAD_SCOPE':'gateway.southbound.invoke',
            'OUF_SEMANTIC_DISCOVERY_DELEGATION_KEY_FILE':'/run/secrets/semantic-discovery-owner.key',
            'OUF_SEMANTIC_DISCOVERY_DELEGATION_WORKLOAD':'ouf-mcp-server'})
        request['Env']=[k+'='+v for k,v in env.items()]
        request['NetworkingConfig']={'EndpointsConfig':{'ouf-backend':{'NetworkID':'9'*64,
            'MacAddress':'02:42:0a:2a:00:02','IPAMConfig':{'IPv4Address':'10.42.0.2'}}}}
        config=image_config or {'User':'10001:10001','Entrypoint':request['Entrypoint'],
            'Cmd':[],'Volumes':{},'Env':['PATH=/usr/bin:/bin'],'WorkingDir':'/app'}
        audit={'imageId':request['Image'],'imageConfig':config}
        return request,old,audit,tree,token,key,proposal

    def test_observed_historical_environment_converts_only_exact_unapplied_discovery_trust(self):
        request,old,audit,tree,token,key,proposal=self.retained_candidate()
        before=copy.deepcopy((request,old,audit));self.assertEqual(len(request['Env']),31)
        self.assertEqual(len(old['Config']['Env']),19)
        result=prep.creation(request,{'retainedNativeCreationFrame':old},old,audit,tree,token,key,proposal,
            {'issuer':'gateway','audience':'semantic','workload':'ouf-semantic'})
        env=prep.environment(result['Env'])
        self.assertNotIn('JAVA_TOOL_OPTIONS',env);self.assertNotIn('OUF_SEM_DB_PASSWORD',env)
        self.assertEqual(env['OUF_SCHEMA_GOV_ENABLED'],'false')
        self.assertEqual(env['OUF_DISCOVERY_WORKER_ENABLED'],'false')
        self.assertEqual(env['OUF_IAM_ISSUER'],'https://auth.ouf-lab.it/realms/ouf')
        self.assertEqual(env['OUF_IAM_ENABLED'],'true');self.assertEqual(len(result['HostConfig']['Binds']),4)
        self.assertFalse(any('/run/ouf-discovery-trust' in b for b in result['HostConfig']['Binds']))
        self.assertEqual((request,old,audit),before)
        FileOnlyProfile(result,tree)

    def test_other_or_applied_jvm_options_are_never_silently_removed(self):
        for option in ('','-Djavax.net.ssl.trustStore=/another/store',
            prep.RETIRED_DISCOVERY_JVM_TRUST+' -Douf.semantic.discovery-worker.enabled=true'):
            request,old,*_=self.retained_candidate();env=prep.environment(request['Env'])
            env['JAVA_TOOL_OPTIONS']=option;request['Env']=[k+'='+v for k,v in env.items()]
            with self.subTest(option=option),self.assertRaisesRegex(ValueError,'UNREVIEWED_OR_APPLIED'):
                prep.retained_file_environment(request,old)
        request,old,*_=self.retained_candidate()
        old['Config']['Env'].append('JAVA_TOOL_OPTIONS='+prep.RETIRED_DISCOVERY_JVM_TRUST)
        with self.assertRaisesRegex(ValueError,'UNREVIEWED_OR_APPLIED'):prep.retained_file_environment(request,old)
        for key in ('JDK_JAVA_OPTIONS','_JAVA_OPTIONS','SPRING_APPLICATION_JSON','OUF_SEMANTIC_DISCOVERY_WORKER_ENABLED'):
            request,old,*_=self.retained_candidate();request['Env'].append(key+'=true')
            with self.subTest(key=key),self.assertRaises(ValueError):prep.retained_file_environment(request,old)

    def gated_frame(self):
        request,old,audit,tree,token,key,proposal=self.retained_candidate()
        result=prep.creation(request,{'retainedNativeCreationFrame':old},old,audit,tree,token,key,proposal,
            {'issuer':'gateway','audience':'semantic','workload':'ouf-semantic'})
        token={k:v for k,v in token.items() if k not in ('directoryDevice','directoryInode')}
        token['directoryCustodyScopeHash']='7'*64
        raw=(ROOT/'tools/semantic_frame_compiler/containerd-overlayfs-southbound.json').read_bytes()
        template,launch=compile_inputs(raw,result,tree,token,key,proposal,ENGINE)
        *_,context=self.inputs()
        args={'execution_profile':FileOnlyProfile(result,tree),'renewable_token':token,
            'delegation_key_metadata_hash':'d'*64,'proposal_receipt_key':proposal}
        return template,launch,context,args,result

    def test_complete_creation_to_frame_preserves_exact_deferred_runtime_gate(self):
        template,launch,context,args,request=self.gated_frame();before=copy.deepcopy((template,launch,request))
        result=compile_policy(template,launch,context,**args)
        expected=request['Entrypoint']+request['Cmd']
        self.assertEqual(result['startup']['args'],expected)
        self.assertEqual(result['expectedOci']['process']['args'],expected)
        self.assertIn('$OUF_APPLICATION_GATE',expected[2])
        self.assertEqual(result['expectedOci']['hostname'],context['containerId'][:12])
        self.assertNotIn('$OUF_',result['expectedOci']['root']['path'])
        self.assertEqual(result['schema'],'ouf.semantic-configured-file-only-four-mount-frame-policy.v2-proposal')
        self.assertEqual((template,launch,request),before)

    def test_runtime_gate_does_not_exempt_unresolved_fields_or_modified_commands(self):
        for field in ('env','directory','annotation','args','ociArgs'):
            template,launch,context,args,request=self.gated_frame()
            if field=='env':
                row='OUF_UNUSED=$OUF_UNREVIEWED'
                request['Env'].append(row);launch['startup']['env'].append(row)
                template['expectedOci']['process']['env'].append(row)
                args['execution_profile']=FileOnlyProfile(request,args['execution_profile'].configtree)
            if field=='directory':
                token=args['renewable_token'];token['source']='/fixture/$OUF_APPLICATION_GATE'
                launch['manifest']['mounts'][3]['source']=token['source']
                for mount in template['expectedOci']['mounts']:
                    if mount['destination']==token['target']:mount['source']=token['source']
            if field=='annotation':template['expectedOci']['annotations']={'value':'$OUF_APPLICATION_GATE'}
            if field=='args':
                launch['startup']['args'][2]+='; echo $OUF_UNREVIEWED'
                template['expectedOci']['process']['args']=copy.deepcopy(launch['startup']['args'])
            if field=='ociArgs':template['expectedOci']['process']['args'][2]+='; echo changed'
            with self.subTest(field=field),self.assertRaises(ValueError):compile_policy(template,launch,context,**args)

    def inputs(self):
        _,launch,context,args=FourMountCompiler().fixture()
        request=copy.deepcopy(args['execution_profile'].request);tree=args['execution_profile'].configtree
        request.update(WorkingDir='/app',Cmd=[])
        request['HostConfig'].update(ReadonlyRootfs=False,CapDrop=['ALL'],SecurityOpt=['no-new-privileges:true'],
            Memory=536870912,MemorySwap=536870912,PidsLimit=256,NanoCpus=1000000000)
        return request,tree,launch['sources'][0],args['renewable_token'],args['proposal_receipt_key'],context

    def test_independent_baseline_compiles_complete_four_mount_policy(self):
        request,tree,key,token,proposal,context=self.inputs()
        # This Engine-specific compiler requires the audited image PATH; the
        # generic four-mount fixture deliberately does not carry image inputs.
        request['Env'].insert(0,'PATH=/usr/bin:/bin')
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

    def test_semantic_schema_marker_is_preserved_in_expected_history(self):
        marker={'version':None,'type':'SCHEMA','script':'"ouf_sem"','checksum':None,'success':True}
        sql={'version':'1','type':'SQL','script':'V1__init.sql','checksum':123,'success':True}
        Channel,calls,pg,request,migrations=self.database(history=[marker,sql])
        original=copy.deepcopy(migrations)
        with patch.object(prep,'Psql',Channel):result=prep.registry_database(pg,request,migrations)
        self.assertEqual(result['before'],[marker,sql]);self.assertEqual(result['expected'],[marker,sql])
        self.assertEqual(migrations,original)
        self.assertNotEqual(digest(result['expected']),digest(migrations))
        for altered in ({**marker,'script':'"wrong_schema"'},{**marker,'success':False},{**sql,'checksum':321}):
            history=[altered,sql] if altered.get('type')=='SCHEMA' else [marker,altered]
            Channel,calls,pg,request,migrations=self.database(history=history)
            with patch.object(prep,'Psql',Channel),self.assertRaisesRegex(ValueError,'MIGRATION_PREFIX'):
                prep.registry_database(pg,request,migrations)

    def inspection_pair(self):
        cli=self.producer('a');cli['Name']='/ouf-semantic'
        cli['NetworkSettings']['Networks']['ouf-backend'].update(Aliases=None,DNSNames=['ouf-semantic','a'*12])
        api=copy.deepcopy(cli);api['NetworkSettings']['Networks']['ouf-backend']['Aliases']=['a'*12]
        return cli,api

    def test_exact_target_channel_profile_keeps_both_complete_bindings(self):
        cli,api=self.inspection_pair();before_cli=copy.deepcopy(cli);before_api=copy.deepcopy(api)
        prep.verify_retained_inspection(cli,api,cli)
        self.assertEqual(cli,before_cli);self.assertEqual(api,before_api)
        self.assertNotEqual(prep.Engine.runtime_binding(cli)['networkSettingsHash'],prep.Engine.runtime_binding(api)['networkSettingsHash'])

    def test_channel_profile_denies_other_network_or_configuration_differences(self):
        for field in ('config','host','mounts','ipv4','mac','endpoint','dns','aliases','historicalAliases'):
            cli,api=self.inspection_pair();old=copy.deepcopy(cli)
            endpoint=api['NetworkSettings']['Networks']['ouf-backend']
            if field=='config':api['Config']['Env'].append('SECRET=private-value')
            if field=='host':api['HostConfig']['RestartPolicy']['Name']='always'
            if field=='mounts':api['Mounts']=[{'Source':'/private/path'}]
            if field=='ipv4':endpoint['IPAddress']='10.42.0.9'
            if field=='mac':endpoint['MacAddress']='02:42:0a:2a:00:09'
            if field=='endpoint':endpoint['EndpointID']='b'*64
            if field=='dns':endpoint['DNSNames']=['new-name']
            if field=='aliases':endpoint['Aliases']=['unexplained-alias']
            if field=='historicalAliases':cli['NetworkSettings']['Networks']['ouf-backend']['Aliases']=['ouf-semantic']
            with self.subTest(field=field),self.assertRaises(ValueError):prep.verify_retained_inspection(old,api,cli)

    def test_paired_reader_uses_exact_host_and_rejects_either_unstable_channel(self):
        for unstable in (None,'cli','api'):
            cli,api=self.inspection_pair();calls=[];api_calls=[]
            class Engine:
                path='/var/run/pinned.sock'
                def check_socket(self):pass
                def request(self,method,path):
                    api_calls.append((method,path));value=copy.deepcopy(api)
                    if unstable=='api' and len(api_calls)==2:value['State']['Pid']=999
                    return 200,value
            class Reader:
                def __init__(self,*args):pass
                def run(self,command,args,limit):
                    calls.append((command,args,limit));value=copy.deepcopy(cli)
                    if unstable=='cli' and len(calls)==2:value['State']['Pid']=999
                    return json.dumps([value]).encode()
            with patch.object(prep,'native_commands'),patch.object(prep,'NodeObservation',Reader),\
                 patch.dict(prep.os.environ,{'DOCKER_CONFIG':'/private/empty-cli-config'}):
                if unstable:
                    with self.assertRaisesRegex(ValueError,'CHANNEL_UNSTABLE'):prep.paired_retained_inspection(Engine(),cli,{'path':'/usr/bin/docker','sha256':'d'*64},object())
                else:
                    observed,native=prep.paired_retained_inspection(Engine(),cli,{'path':'/usr/bin/docker','sha256':'d'*64},object())
                    self.assertEqual(observed,api);self.assertEqual(native,cli)
            self.assertEqual(calls[0][1],['--host','unix:///var/run/pinned.sock','--config','/private/empty-cli-config','inspect','--type=container','a'*64])
            self.assertTrue(all(method=='GET' for method,path in api_calls))

    def producer(self,letter):
        return {'Id':letter*64,'Image':'sha256:'+'f'*64,'State':{'Pid':12,'StartedAt':'2026-10-14T01:00:00Z','Running':True},
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
        request['HostConfig']['OomKillDisable']=None
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
        self.assertIs(result['HostConfig']['OomKillDisable'],False)
        self.assertIsNone(request['HostConfig']['OomKillDisable'])
        self.assertEqual(result['Cmd'],audit['imageConfig']['Entrypoint'])
        request['Env'][-1]='OUF_IAM_ENABLED=false'
        with self.assertRaisesRegex(ValueError,'IAM_CANNOT_BE_DISABLED'):
            prep.creation(request,{'retainedNativeCreationFrame':old},old,audit,tree,token,key,proposal,
                {'issuer':'gateway','audience':'semantic','workload':'ouf-semantic'})

if __name__=='__main__':unittest.main()
