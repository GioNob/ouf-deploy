"""Full finite native sequence on disposable Docker29/APISIX/JVM/PG17.

HUMAN journal and dual-role signatures are real fixture mechanisms; the bearer
and GET-only Owner are synthetic. This qualifies the executor, never current
target HUMAN/Onboarding authority, functional F5/F6 or release acceptance.
"""
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
import zipfile
import shutil
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),
             str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_ingestion_db_preflight_native as legacy
import test_cutover_authority_native as crypto
from test_ingestion_rollout_gateway_transport import binding
from tools.ingestion_readiness_patch_execution import contract as c,native_review,runtime_bindings as rb
from tools.ingestion_readiness_patch_execution.native import NativePorts
from tools.ingestion_readiness_patch_execution.runner import Runner
from tools.ingestion_rollout_execution.gateway_transport import CHILD_SOURCE # fixture setup PUTs only
from tools.ingestion_readiness_patch_execution.readiness import CHILD_SOURCE as READY_CHILD
from tools.ingestion_readiness_patch_execution.namespace import identity
from tools.ingestion_rollout_preparation import frames
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort import human_session as human_module
from tools.chatbot_file_cohort.gateway import route_map
import iam_governance_intake as governance
from engine_creation import Engine,CreationDenied

def cli(arguments,seconds=90):
    result=subprocess.run(['docker',*arguments],capture_output=True,timeout=seconds)
    if result.returncode:raise RuntimeError('DISPOSABLE_FIXTURE_DOCKER_COMMAND_FAILED')
    return result.stdout

@unittest.skipUnless(os.environ.get('OUF_ISOLATED_NATIVE_PLATFORM')=='1','explicit disposable platform required')
class NativePlatform(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pg=type('_DisposablePostgres',(legacy.NativeDatabase,),{})
        cls.addClassCleanup(cls.pg.doClassCleanups);cls.pg.setUpClass()
        engine=cls.pg.selected['engine'];cls.engine=Engine(engine['socketPath'],tuple(engine['socketBinding']))
        folder=cls.pg.root/'candidate';folder.mkdir(mode=0o700)
        with zipfile.ZipFile(os.environ['OUF_CANDIDATE_ZIP']) as package:
            expected={'image.tar.gz','metadata.json','image-inspect.json','trivy-image.json','SHA256SUMS'}
            if set(package.namelist())!=expected:raise AssertionError('EXACT_CANDIDATE_ARTIFACT_CONTENTS_REQUIRED')
            for name in sorted(expected):
                if package.getinfo(name).file_size>200_000_000:raise AssertionError('BOUNDED_CANDIDATE_ARTIFACT_REQUIRED')
                with package.open(name) as source, open(folder/name,'xb') as target:shutil.copyfileobj(source,target,1048576)
        meta=json.loads((folder/'metadata.json').read_bytes())
        if meta['imageArchiveSha256']!=hashlib.sha256((folder/'image.tar.gz').read_bytes()).hexdigest():
            raise AssertionError('CANDIDATE_ARCHIVE_CHANGED')
        if meta['sourceCommit']!='4165b9e149be467d5d7c6bed35e4e1af4e249db1':
            raise AssertionError('EXACT_CANDIDATE_SOURCE_REQUIRED')
        cls.archive=folder/'image.tar.gz';cls.image=meta['imageId']
        inspect=json.loads((folder/'image-inspect.json').read_bytes())[0];cls.image_config=inspect['Config']
        cls.candidate={'sourceCommit':meta['sourceCommit'],'configurationImageId':cls.image,
            'nativeImageId':cls.image,'imageConfig':cls.image_config,
            'rootfs':{'type':'layers','diff_ids':inspect['RootFS']['Layers']}}
        cli(['load','-i',str(cls.archive)],180)
        for name in('OUF_FIXTURE_APISIX_IMAGE','OUF_FIXTURE_ETCD_IMAGE','OUF_FIXTURE_OWNER_IMAGE'):
            cli(['pull',os.environ[name]],180)
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=os.environ['OUF_TEST_ROOT']);self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700);self.label='ouf-native-'+uuid.uuid4().hex[:10]
        self.names=[];self.second=self.label+'-second';cli(['network','create',self.second])
        self.addCleanup(self.cleanup);self.first=self.pg.network
        self.addCleanup(self.report_progress)
        self.program=governance.executable(os.environ.get('OUF_TEST_PYTHON','/usr/bin/python3'))
        self.key_path=self.root/'dedicated-key';self.owner_data=self.root/'owner.json'
        self.human,self.bearer=self.fixture_human()
        self.payload={'installationId':self.label,'secrets':{'references':{'ingestionReadOwnerKey':str(self.key_path)}}}
        active={'installationId':self.label,'revision':7,'checksum':c.digest(self.payload),'generation':1}
        active['etag']='"7:'+active['checksum']+':1"';self.active=active
        self.owner_data.write_bytes(c.encoded({'active':active,'payload':self.payload,'bearer':self.bearer}));self.owner_data.chmod(0o400)
        owner=self.launch(self.label+'-owner',os.environ['OUF_FIXTURE_OWNER_IMAGE'],
            ['python','-I','-B','-S','/fixture/owner.py','/fixture/owner.json','18080'],
            binds=[str(ROOT/'tests/fixtures/ingestion-rollout/owner_server.py')+':/fixture/owner.py:ro',
                   str(self.owner_data)+':/fixture/owner.json:ro'])
        udp=self.launch(self.label+'-udp','postgres:17-alpine',['sleep','900'])
        etcd=self.launch(self.label+'-etcd',os.environ['OUF_FIXTURE_ETCD_IMAGE'],
            ['--listen-client-urls=http://0.0.0.0:2379','--advertise-client-urls=http://'+self.label+'-etcd:2379'],
            entrypoint='/usr/local/bin/etcd')
        before=self.root/'config-before.yaml';before.write_text(self.gateway_config(self.label+'-etcd'));before.chmod(0o444)
        staged=self.root/'config-staged.yaml';staged.write_bytes(frames.expose_owner_environment(before.read_bytes()));staged.chmod(0o444)
        gateway=self.launch(self.label+'-gateway',os.environ['OUF_FIXTURE_APISIX_IMAGE'],[],
            binds=[str(before)+':'+frames.CONFIG_DESTINATION+':ro'],second=True)
        ingestion=self.launch(self.label+'-ingestion',self.image,
            ['--spring.main.banner-mode=off','--logging.level.root=ERROR',
             '--spring.flyway.enabled=false','--ouf.ingestion.startup.schema-mode=VALIDATE_ONLY'],second=True,
            environment={'OUF_ING_DB_URL':'jdbc:postgresql://'+self.pg.pg+':5432/'+self.pg.db,
                'OUF_ING_DB_USER':self.pg.user,'OUF_ING_DB_PASSWORD':'ci-only-runtime','SPRING_FLYWAY_ENABLED':'false'})
        self.wait_ready(ingestion)
        for attempt in range(60):
            try:
                reply=self.admin(gateway,'GET','/apisix/admin/routes')
                if reply['status']==200:break
            except (AssertionError,ValueError):pass
            if attempt==59:raise AssertionError('DISPOSABLE_APISIX_ADMIN_NOT_READY')
            time.sleep(.5)
        routes={rid:{'id':rid,'uri':'/fixture/'+str(i),'plugins':{'serverless-pre-function':{
            'phase':'rewrite','functions':['return function(conf,ctx) ngx.say("fixture-before"); return ngx.exit(200) end']}}}
            for i,rid in enumerate(['mcp-ingestion-status','mcp-ingestion-history',*[str(j)for j in range(80)]])}
        for rid,value in routes.items():self.assertIn(self.admin(gateway,'PUT','/apisix/admin/routes/'+rid,value)['status'],(200,201))
        routes=route_map(self.admin(gateway,'GET','/apisix/admin/routes')['body']['list'])
        after=copy.deepcopy(routes)
        for name in('mcp-ingestion-status','mcp-ingestion-history'):
            after[name]['plugins']['serverless-pre-function']['functions']=['return function(conf,ctx) ngx.say("fixture-after"); return ngx.exit(200) end']
        before_containers={'ingestion':self.inspect(ingestion),'gateway':self.inspect(gateway)}
        draft={'candidate':{'sourceCommit':self.candidate['sourceCommit']},'ingestion':{
            'bootstrapCmd':before_containers['ingestion']['Config']['Cmd'],
            'ownerReadEnvironmentAdditions':{'OUF_ING_GATEWAY_READ_ENABLED':'true',
                'OUF_ING_GATEWAY_READ_ISSUER':'https://fixture.invalid','OUF_ING_GATEWAY_READ_AUDIENCE':'fixture-audience',
                'OUF_ING_GATEWAY_READ_WORKLOAD':'ouf-mcp-server','OUF_ING_GATEWAY_READ_KEY_FILE':'/run/secrets/fixture-owner-key'},
            'startupEnvironmentAddition':{'SPRING_FLYWAY_ENABLED':'false'},
            'readOnlyBindAddition':{'Type':'bind','Source':str(self.key_path),'Destination':'/run/secrets/fixture-owner-key','RW':False}}}
        # Contract flags must be the final two command-line options.
        draft['ingestion']['bootstrapCmd']=['--spring.main.banner-mode=off','--logging.level.root=ERROR',
            '--spring.flyway.enabled=false','--ouf.ingestion.startup.schema-mode=VALIDATE_ONLY']
        complete={m:frames.frame(m,v,self.image if m=='ingestion'else v['Image'],self.image_config,draft,
                   str(staged)if m=='gateway'else None)for m,v in before_containers.items()}
        self.before=before_containers
        self.names.extend(v['Id']for v in before_containers.values())
        candidate=copy.deepcopy(self.candidate);selected_archive=binding(self.archive)
        candidate['nativeArchiveBinding']={k:selected_archive[k]for k in('path','sha256','metadata')}
        selected_old,selected_new=binding(before),binding(staged)
        inputs={'candidate':candidate,'expectedRuntimeBindings':{m:rb.observed(v,rb.SORTED)for m,v in before_containers.items()},
            'gatewayConfigBefore':{k:selected_old[k]for k in('path','sha256','metadata')},
            'retainedGatewayConfig':{k:selected_new[k]for k in('path','sha256','metadata')},
            'dedicatedOwnerKey':{'path':str(self.key_path),'state':'MISSING_AT_EXISTING_CUSTODIED_PARENT'},
            'retainedClaims':{'fixture-only':'retained-owner-and-publication'}}
        owner_plan={'bindingPlan':{'candidatePayload':self.payload}}
        packet={'schema':'ouf.ingestion-rollout-private-packet.v3','kind':'PRIVATE_TEMPLATES_NOT_EXECUTABLE_AUTHORITY',
            **inputs,'ownerPlanSha256':c.digest(owner_plan),'verifiedInputsHash':c.digest(inputs),'frames':complete,
            'routeDraft':{'beforeRoutes':routes,'afterRoutes':after,'retainedOtherRoutes':80,'maximumPutRequests':2},
            'runtimeAuthorityIssued':False,'runtimeExecutorQualified':False,'databaseAdmissionProven':False,
            'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,'newLoginAllowed':False}
        self.packet=packet;self.after_routes=after
        projection=self.root/'projection';projection.write_bytes(b'unchanged fixture projection');projection.chmod(0o600)
        applications={'onboarding':self.inspect(owner),'mcp':self.inspect(self.pg.app),'udp':self.inspect(udp)}
        pg=self.inspect(self.pg.selected['postgres']['containerId']);engine=self.pg.selected['engine']
        empty=self.root/'empty-docker-config';empty.mkdir(mode=0o700)
        from tools.ingestion_readiness_patch_execution.database_read import empty_config_directory
        docker=governance.executable(self.pg.docker)
        owner_binding=rb.observed(applications['onboarding'],rb.SORTED)
        db={'schema':'ouf.ingestion-rollout-native-database-read.v1','engineBinding':engine,
            'postgresRuntimeBinding':rb.observed(pg,rb.NATIVE),'runtimeBindingProfile':rb.NATIVE,'postgresRestartCount':pg['RestartCount'],
            'identity':{'database':self.pg.db,'user':self.pg.user,'databaseOid':self.pg.selected['databaseOid'],'postgresPort':5432},
            'dockerExecutable':docker,'dockerConfigDirectory':str(empty),'dockerConfigIdentity':empty_config_directory(str(empty)),
            'containerPrograms':{'env':'/usr/bin/env','timeout':'/usr/bin/timeout','psql':'/usr/local/bin/psql'},'unixSocketDirectory':'/var/run/postgresql'}
        gateway_profile=lambda selected:{'schema':'ouf.ingestion-rollout-gateway-transport.v1',
            'endpoint':{'host':'127.0.0.1','port':9180},'pythonExecutable':self.program,'config':selected,'adminKey':None}
        profiles={'schema':'ouf.ingestion-rollout-native-local-profile-set.v1','engineBinding':engine,
            'runtimeGuardProfile':{'schema':'ouf.ingestion-rollout-runtime-guard.v1','beforeContainers':before_containers,
                'unchangedApplications':{m:{'binding':rb.observed(v,rb.SORTED),'bindingProfile':rb.SORTED,
                                          'restartCount':v['RestartCount']}for m,v in applications.items()}},
            'ownerControlProfile':{'schema':'ouf.ingestion-rollout-owner-local-namespace-http.v1',
                'runtimeBinding':owner_binding,'runtimeBindingProfile':rb.SORTED,'restartCount':applications['onboarding']['RestartCount'],
                'networkNamespace':self.namespace(applications['onboarding']),'endpoint':{'host':'127.0.0.1','port':18080},
                'pythonExecutable':self.program,'installationId':self.label,'expectedActive':active,'expectedPayload':self.payload,
                'projection':binding(projection)},'databaseControlProfile':db,
            'imageImportProfile':{'schema':'ouf.ingestion-rollout-native-image-load.v1',
                **{k:db[k]for k in('engineBinding','dockerExecutable','dockerConfigDirectory','dockerConfigIdentity')},'archive':selected_archive},
            'retainedGatewayTransportProfile':gateway_profile(selected_old),'retainedGatewayNamespace':self.namespace(before_containers['gateway']),
            'gatewayTransportProfile':gateway_profile(selected_new),
            'ingestionReadinessProfile':{'schema':'ouf.ingestion-rollout-ingestion-readiness-local-ns.v1',
                'endpoint':{'host':'127.0.0.1','port':8080},'pythonExecutable':self.program}}
        self.context=self.root/'execution';self.context.mkdir(mode=0o700)
        owner_plan.update(engine=copy.deepcopy(engine),currentApplications={**copy.deepcopy(packet['expectedRuntimeBindings']),
            **{m:rb.observed(v,rb.SORTED)for m,v in applications.items()}})
        owner_plan['bindingPlan']['candidatePayloadChecksum']=active['checksum']
        packet['ownerPlanSha256']=c.digest(owner_plan)
        actual=before_containers['ingestion'];request=copy.deepcopy(actual['Config'])
        request.pop('MacAddress',None);request['Hostname']='';request['Image']=self.image
        request['Labels']={**(request.get('Labels')or{}),'org.opencontainers.image.revision':self.candidate['sourceCommit']}
        host=copy.deepcopy(actual['HostConfig']);restore=copy.deepcopy(host['RestartPolicy'])
        host['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
        request.update(HostConfig=host,NetworkingConfig={'EndpointsConfig':frames.endpoints(actual)})
        frame={'schema':'ouf.ingestion-local-docker-frame-template.v1','module':'ingestion','name':actual['Name'][1:],
            'requestTemplate':request,'oldMounts':copy.deepcopy(actual['Mounts']),'restoreRestartPolicy':restore,
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'resolveGatewaySecretAfterNativeAuthorityRequired':False}
        logical=c.digest({'operation':'INGESTION_READINESS_WORKLOAD_PATCH','oldContainerId':actual['Id'],'candidateImageId':self.image})
        stages=[]
        def add(name,kind,intent):stages.append({'name':name,'kind':kind,'intent':intent,'intentHash':c.digest(intent)})
        add('VERIFY_CURRENT_GATES','READ',{'fixtureOnly':True})
        add('IMPORT_INGESTION_IMAGE','EFFECT',{'nativeImageId':self.image})
        add('ingestion.DISABLE_OLD_RESTART','EFFECT',{'oldContainerId':actual['Id'],'restartPolicy':host['RestartPolicy']})
        add('ingestion.STOP_OLD','EFFECT',{'oldContainerId':actual['Id'],'timeoutSeconds':30})
        for i,endpoint in enumerate(request['NetworkingConfig']['EndpointsConfig'].values(),1):
            add('ingestion.DETACH_NETWORK.'+str(i),'EFFECT',{'oldContainerId':actual['Id'],'networkId':endpoint['NetworkID'],'force':False})
        add('ingestion.RENAME_OLD','EFFECT',{'oldContainerId':actual['Id'],'retainedName':frame['name']+'-retained-'+logical[:12]})
        add('ingestion.CREATE_REPLACEMENT','EFFECT',{'name':frame['name'],'requestTemplate':request})
        add('ingestion.START_REPLACEMENT','EFFECT',{'createdIdMustComeFromDurableCreateResponse':True})
        add('ingestion.READINESS','READ',{'fixtureOnly':True});add('VERIFY_FINAL','READ',{'fixtureOnly':True})
        add('ingestion.RESTORE_RESTART','EFFECT',{'createdIdMustComeFromDurableCreateResponse':True,'restartPolicy':restore})
        add('VERIFY_RESTORED_FINAL','READ',{'fixtureOnly':True})
        unchanged={**applications,'gateway':before_containers['gateway']}
        inspection={'Id':self.image,'Os':'linux','Architecture':'amd64','Config':self.image_config,
                    'RootFS':{'Type':'layers','Layers':self.candidate['rootfs']['diff_ids']}}
        bundle={'schema':'ouf.ingestion-readiness-patch-native-inputs.v1','kind':'PRIVATE_NATIVE_INPUTS_NOT_EXECUTABLE_AUTHORITY',
            'finiteIntentContract':{'logicalOperationRef':logical,'stages':stages,'maximumGatewayWrites':0,'maximumSecretCreations':0},
            'ingestionFrame':frame,'beforeIngestion':actual,'candidate':inspection,
            'candidateFileBindings':{'image.tar.gz':selected_archive},'parentReviewHash':'d'*64,
            'unchangedApplications':{m:{'binding':rb.observed(v,rb.NATIVE),'bindingProfile':rb.NATIVE,'restartCount':v['RestartCount']}
                                     for m,v in unchanged.items()},
            'engineBinding':engine,'ownerControlProfile':profiles['ownerControlProfile'],
            'databaseControlProfile':db,'imageImportProfile':profiles['imageImportProfile'],
            'ingestionReadinessProfile':profiles['ingestionReadinessProfile'],
            'unchangedGatewayTransportProfile':profiles['retainedGatewayTransportProfile'],'unchangedGatewayRoutes':routes,
            **{k:False for k in ('nativeRuntimeExecutorQualified','targetApplyAuthorized','runtimeAuthorityIssued',
                'automaticReplayAllowed','budgetReset','sourceActivationAllowed','releaseAcceptance')}}
        self.review,self.packet=native_review.compile_review(bundle,{'path':str(self.root/'native-inputs.json'),'sha256':c.digest(bundle)},
            self.human.current(),str(self.context))
        self.after_routes=routes;self.sign_scope()
        self.ports=NativePorts(self.action,Journal(self.context),self.review,self.packet,self.human);self.addCleanup(self.ports.close)
        self.runner=Runner(self.action,self.ports.journal,self.review,self.ports);self.runner.initialize()
    def cleanup(self):
        for name in reversed(self.names):subprocess.run(['docker','rm','-f',name],capture_output=True,timeout=25)
        subprocess.run(['docker','network','rm',self.second],capture_output=True,timeout=20)
    def report_progress(self):
        if not hasattr(self,'runner'):
            print('OUF_NATIVE_ROLLOUT_CHECKPOINT={"phase":"DISPOSABLE_SETUP"}',flush=True);return
        if not self.runner.journal.record.exists():
            print('OUF_NATIVE_ROLLOUT_CHECKPOINT={"phase":"SEALED_ENTRY_BEFORE_INITIALIZE"}',flush=True);return
        row=self.runner.record();index=row['nextStage']
        print('OUF_NATIVE_ROLLOUT_CHECKPOINT='+json.dumps({'nextStage':self.review['stages'][index]['name']if index<len(self.review['stages'])else'COMPLETE',
            'readState':row['readState'],'effects':len(row['effects']),
            'engineGets':row.get('nativeDirectEngineGets',0),'enginePosts':row.get('nativeDirectEnginePosts',0),
            'ownerGets':row.get('nativeOwnerGetAttempts',0),'sqlSessions':row.get('nativeDatabaseReadSessions',0),
            'runtimeAuthorityIssued':False,'notReleaseAcceptance':True},sort_keys=True),flush=True)
        if hasattr(self,'ports')and hasattr(self.ports,'database')and self.ports.database.last_report is not None:
            print('OUF_NATIVE_DATABASE_ADMISSION_PREDICATES='+json.dumps(self.ports.database.last_report,sort_keys=True),flush=True)
    def launch(self,name,image,arguments,*,binds=(),environment=None,second=False,entrypoint=None):
        self.names.append(name);args=['run','-d','--name',name,'--network',self.first,'--network-alias',name,
            '--restart','unless-stopped']
        if entrypoint is not None:args+=['--entrypoint',entrypoint]
        for item in binds:args+=['-v',item]
        for key,value in(environment or{}).items():args+=['-e',key+'='+value]
        args+=[image,*arguments];cid=cli(args).decode().strip()
        if second:cli(['network','connect','--alias',name+'-second',self.second,cid])
        return cid
    @classmethod
    def inspect(cls,cid):
        status,value=cls.engine.request('GET','/v1.44/containers/'+cid+'/json')
        if status!=200:raise AssertionError('FIXTURE_CONTAINER_NOT_PRESENT')
        return value
    def namespace(self,actual):return identity(os.stat('/proc/'+str(actual['State']['Pid'])+'/ns/net'))
    def child(self,cid,source,payload):
        fd=os.open('/proc/'+str(self.inspect(cid)['State']['Pid'])+'/ns/net',os.O_RDONLY|os.O_CLOEXEC)
        try:
            result=subprocess.run([self.program['path'],'-I','-B','-S','-c',source,str(fd)],input=c.encoded(payload),
                capture_output=True,pass_fds=(fd,),timeout=16,env={'LC_ALL':'C'})
            if result.returncode:raise AssertionError('DISPOSABLE_NAMESPACE_CHILD_NOT_READY')
            return json.loads(result.stdout)
        finally:os.close(fd)
    def admin(self,cid,method,path,body=None):
        return self.child(cid,CHILD_SOURCE,{'method':method,'path':path,'body':body,'key':'a'*64,'host':'127.0.0.1','port':9180})
    def wait_ready(self,cid):
        for attempt in range(90):
            try:
                value=self.child(cid,READY_CHILD,{'host':'127.0.0.1','port':8080})
                if value['status']==200 and json.loads(base64.b64decode(value['bodyBase64']))['status']=='UP':return
            except (AssertionError,ValueError,KeyError):pass
            if not self.inspect(cid)['State']['Running']:raise AssertionError('DISPOSABLE_JVM_EXITED_BEFORE_READY')
            time.sleep(.5)
        raise AssertionError('DISPOSABLE_JVM_READINESS_EXHAUSTED')
    def fixture_human(self):
        folder=self.root/'human';folder.mkdir(mode=0o700);now=int(time.time());expiry=now+1200
        selection={'issuer':'https://fixture.invalid','subject':'fixture-human','tenant':'fixture-tenant'}
        human=human_module.HumanSession(selection,folder,folder/'human-access.jwt',expiry)
        claims={'iss':selection['issuer'],'sub':selection['subject'],'tenant_id':selection['tenant'],'ouf_actor_type':'HUMAN',
            'azp':human_module.CLIENT,'acr':'fixture-only','aud':'ouf-api-gateway','scope':' '.join(human_module.SCOPES),'exp':expiry}
        token='fixture.'+base64.urlsafe_b64encode(c.encoded(claims)).decode().rstrip('=')+'.fixture'
        human.token_path.write_text(token);human.token_path.chmod(0o600)
        selected={'sessionId':uuid.uuid4().hex,'selectionHash':c.digest(selection),**selection,'clientId':human_module.CLIENT,
            'scopes':human_module.SCOPES,'tokenPath':str(human.token_path),'sessionDirectory':str(folder),
            'createdAt':now,'expiresAt':expiry,'retryProfile':human_module.PROFILE}
        human.journal.initialize({'schema':'ouf.chatbot-human-session.private.v1','binding':selected,'bootId':human._boot(),
            'monotonicDeadline':time.monotonic()+1200,'lastObservedAt':time.time(),'attempts':1,'state':'READY',
            'budgetReset':False,'accessExpiresAt':expiry,'publishedAccessToken':token,'version':0})
        return human,token
    def sign_scope(self):
        self.crypto=crypto.SignedCutover()
        with patch.object(crypto,'ROOT',self.root):self.crypto.setUp()
        self.addCleanup(self.crypto.doCleanups);q=self.crypto
        policy=json.loads(q.policy.read_bytes())
        for key in policy['keys']:key['expiresAt']=int(time.time())+1800
        q.write(q.policy,c.encoded(policy));q.verifier.policy_binding=q.binding(q.policy)
        raw=json.loads(q.authority);raw.update(issuedAt=int(time.time()),expiresAt=int(time.time())+900)
        raw[c.AUTHORITY_KEY]=c.scope(self.review);q.authority=c.encoded(raw)
        q.approval.update(expiresAt=int(time.time())+900,executionAuthorityHash=hashlib.sha256(q.authority).hexdigest())
        q.write(q.mandate,c.encoded(q.approval));q.approved=hashlib.sha256(q.mandate.read_bytes()).hexdigest()
        for role in q.grant['roles']:q.sign(role)
        gate=q.gate();gate.clock=time.time;gate.verifier.clock=time.time
        self.action=AggregateAction(gate,q.authority,q.expected['sourceClosureHash'])
    def gateway_config(self,etcd):
        # APISIX traditional mode, documented by the upstream deployment guide.
        return 'apisix:\n  node_listen: 9080\ndeployment:\n  role: traditional\n  role_traditional:\n    config_provider: etcd\n  admin:\n    admin_listen:\n      ip: 127.0.0.1\n      port: 9180\n    allow_admin:\n      - 127.0.0.1/32\n    admin_key:\n      - name: fixture\n        key: '+('a'*64)+'\n        role: admin\n  etcd:\n    host:\n      - http://'+etcd+':2379\n    prefix: /'+self.label+'\n    timeout: 5\nnginx_config:\n  envs:\n  - PATH\n'
    def advance_to(self,name):
        while self.review['stages'][self.runner.record()['nextStage']]['name']!=name:self.runner.step()
    def test_complete_real_native_sequence_preserves_routes_generations_and_claims(self):
        gateway=copy.deepcopy(self.inspect(self.before['gateway']['Id']))
        for _ in self.review['stages']:self.runner.step()
        self.assertTrue(self.runner.step()['complete'])
        self.ports.prepare();row=self.runner.record()
        self.assertEqual(row['nextStage'],len(self.review['stages']))
        self.assertEqual(row['nativeDirectEnginePosts'],self.review['maximumDirectEnginePosts'])
        self.assertFalse(any(e.get('nativeGatewayPutAttempted')for e in row['effects']))
        self.assertFalse(any(e.get('nativeAllocationAttempted')for e in row['effects']))
        new=self.ports.lifecycle.created('ingestion');self.names.append(new)
        self.assertNotEqual(new,self.before['ingestion']['Id']);actual=self.inspect(new)
        self.assertEqual(actual['HostConfig']['RestartPolicy'],self.packet['frames']['ingestion']['restoreRestartPolicy'])
        self.assertEqual(actual['RestartCount'],0)
        self.assertFalse(self.inspect(self.before['ingestion']['Id'])['State']['Running'])
        self.assertEqual(rb.observed(self.inspect(gateway['Id']),rb.NATIVE),rb.observed(gateway,rb.NATIVE))
        self.assertEqual(self.ports.routes(),self.after_routes)
        count=row['nativeDirectEnginePosts'];self.runner.step()
        self.assertEqual(self.runner.record()['nativeDirectEnginePosts'],count)
        print('OUF_READINESS_PATCH_PLATFORM_PROOF='+json.dumps({'complete':True,'stages':len(self.review['stages']),
            'enginePosts':count,'gatewayWrites':0,'secretCreations':0,'candidateSource':self.candidate['sourceCommit'],
            'syntheticHumanAndOwner':True,'runtimeAuthorityIssued':False,'notReleaseAcceptance':True}),flush=True)
    def test_lost_actual_create_response_retains_unknown_cid_without_discovery_or_replay(self):
        self.advance_to('ingestion.CREATE_REPLACEMENT');original=Engine.request;created=[]
        def lose(engine,method,path,body=None):
            result=original(engine,method,path,body)
            if method=='POST'and path.startswith('/v1.44/containers/create?'):
                created.append(result[1]['Id']);raise CreationDenied('FIXTURE_LOST_CREATE_REPLY')
            return result
        with patch.object(Engine,'request',lose):
            with self.assertRaises(CreationDenied):self.runner.step()
        row=self.runner.record();self.assertEqual(len(created),1);self.assertNotIn('nativeResource',row['effects'][-1])
        with self.assertRaises(c.Paused):self.runner.step()
        with self.assertRaises(c.Paused):self.runner.reconcile()
        self.assertNotIn('nativeResource',self.runner.record()['effects'][-1])
        self.assertEqual(self.inspect(created[0])['State']['Status'],'created')
    def test_expired_published_bearer_blocks_before_any_runtime_effect(self):
        row=self.human.journal.read();self.human.journal.compare_and_save(row,{**row,'accessExpiresAt':time.time()-1,'version':row['version']+1})
        with self.assertRaises(human_module.HumanSessionPaused):self.runner.step()
        row=self.runner.record();self.assertEqual(row['effects'],[]);self.assertFalse(self.key_path.exists())
        self.assertNotIn('nativeDirectEnginePosts',row)

if __name__=='__main__':unittest.main()

