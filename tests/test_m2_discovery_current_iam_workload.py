"""Real current parent crypto/custody; IAM/Engine and profile leaves modeled.

The actual bounded kcadm argument builder and full reader run against explicit
JSON fixtures. No live Keycloak, grant, real bearer or target admission is proved.
"""
import copy,hashlib,os,sys,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_discovery_current_cohort as cohort
from tools.m2_discovery_installation_profile import current_iam_workload as m

CLIENT='11111111-1111-4111-8111-111111111111'
SERVICE='22222222-2222-4222-8222-222222222222'
SCOPE='gateway.southbound.invoke'


class WorkloadIam(unittest.TestCase):
    setUp=cohort.Cohort.setUp
    native=cohort.Cohort.native
    write=cohort.Cohort.write
    binding=cohort.Cohort.binding
    sign=cohort.Cohort.sign
    authority=cohort.Cohort.authority
    runtime_fixture=cohort.Cohort.owner

    def prepared(self):
        runtime,_,_=self.runtime_fixture();docker=Path('/usr/bin/true').resolve()
        inputs={k:runtime.inputs[k] for k in ('sourceClosureHash','installationInputsHash','desiredProfileHash','cohortManifestHash')}
        actual={'Id':runtime.inputs['peers']['keycloak']['runtimeBinding']['containerId'],'Image':'sha256:'+'b'*64,
            'Config':{},'HostConfig':{},'Mounts':[],'NetworkSettings':{},'State':{
                'Pid':runtime.inputs['peers']['keycloak']['runtimeBinding']['pid'],'StartedAt':'fixture-only',
                'Running':True,'Paused':False,'Restarting':False},'RestartCount':0}
        runtime.inputs['peers']['keycloak']['runtimeBinding']=m.Engine.runtime_binding(actual)
        inputs.update(schema=m.SCHEMA,executionProfileHash='e'*64,dockerBinding={'path':str(docker),
            'sha256':hashlib.sha256(docker.read_bytes()).hexdigest()},keycloakRuntimeBinding=m.Engine.runtime_binding(actual),
            realm='ouf',clientUuid=CLIENT,serviceAccountUuid=SERVICE,expectedScopes=[SCOPE],expectedAudiences=['ouf-gateway'])
        extended=m.bind_iam_workload_inputs(runtime.inputs,inputs)
        review=copy.deepcopy(self.review);review['components']['cohortInstallation']['currentAdmission']=copy.deepcopy(
            review['components']['cohortInstallation']['currentAdmission']['requirements'])
        self.review=cohort.m.bind_runtime_review(review,extended);parent=self.authority(seconds=300)
        runtime.selected.images.parent=parent;runtime.selected.images.component=self.review['components']['cohortInstallation']
        runtime.selected.guard=lambda:parent.guard('cohortInstallation',runtime.selected.images.component)
        runtime=cohort.m.CurrentCohortRuntime(runtime.selected,extended);runtime.selected.images.engine.path='/run/reviewed.sock'
        path=self.root/'credential';path.write_bytes(b'fixture-existing-credential-123456');path.chmod(0o440)
        f={'source':str(path),'uid':0,'gid':os.getegid(),'mode':0o440,'maxBytes':4096,
            'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'metadataHash':m.digest(m.attributes(path.lstat()))}
        profile=object.__new__(m.DiscoveryProfile);profile.verify=lambda request:'e'*64
        profile.selection={'files':{'providerCredential':f},'references':{'OUF_IAM_ISSUER':'https://iam.fixture.invalid/realms/ouf',
            'OUF_SCHEMA_GOV_TOKEN_ENDPOINT':'https://iam.fixture.invalid/realms/ouf/protocol/openid-connect/token',
            'OUF_IAM_AUDIENCE':'ouf-gateway','OUF_SCHEMA_GOV_CLIENT_ID':'ouf-semantic','OUF_SCHEMA_GOV_WORKLOAD_SCOPE':SCOPE}}
        runtime.selected.installation.application.profile=profile;runtime.selected.installation.application.request={}
        selection={'keycloakContainer':actual['Id'],'realm':'ouf','docker':inputs['dockerBinding'],
            'issuer':profile.selection['references']['OUF_IAM_ISSUER'],'tenant':'tenant-fixture'}
        transport=object.__new__(m.OwnerTransport);transport.selection=selection
        auth=object.__new__(m.DiscoveryAuthorization);auth.transport=transport;auth.journal=object()
        child=object();raw=b'fixture-original-child';auth.action=SimpleNamespace(authority=child,raw=raw,authority_hash='f'*64)
        auth.plan={'selection':copy.deepcopy(selection)};auth.hash=m.digest(auth.plan);auth.scope={'fixture':True}
        auth.window=SimpleNamespace(selected=runtime.selected,gate=SimpleNamespace(child=child,raw=raw),child_hash='f'*64,
            assembly={'authorizationPlan':copy.deepcopy(auth.plan)},component={'authorization':copy.deepcopy(auth.scope)},
            lineage=Mock(side_effect=lambda:parent.guard('cohortInstallation',runtime.selected.images.component)))
        auth.window.guard=Mock(side_effect=AssertionError('RECURSIVE_PUBLICATION_CHECKPOINT_FORBIDDEN'))
        auth.owner_ids=tuple(map(id,(auth.window,auth.journal,transport,auth.action)))
        reader=m.CurrentWorkloadIam(runtime,auth,inputs)
        payload={'iss':selection['issuer'],'sub':SERVICE,'azp':'ouf-semantic','tenant_id':selection['tenant'],
            'ouf_actor_type':'SERVICE','aud':'ouf-gateway','scope':SCOPE,'iat':123,'jti':'volatile'}
        rows={'clients/'+CLIENT:{'id':CLIENT,'clientId':'ouf-semantic','enabled':True,'serviceAccountsEnabled':True,
                'publicClient':False,'clientAuthenticatorType':'client-secret','protocol':'openid-connect'},
            'clients/'+CLIENT+'/service-account-user':{'id':SERVICE,'enabled':True},
            'clients/'+CLIENT+'/default-client-scopes':[],
            'clients/'+CLIENT+'/optional-client-scopes':[{'id':'33333333-3333-4333-8333-333333333333','name':SCOPE,'protocol':'openid-connect'}],
            'clients/'+CLIENT+'/client-secret':{'type':'secret','value':path.read_text()},
            'clients/'+CLIENT+'/evaluate-scopes/generate-example-access-token':payload}
        return reader,parent,path,actual,rows

    def native_gets(self,reader,actual,rows,drift=None):
        calls=[];native_run=m.subprocess.run
        def run(args,**kwargs):
            if args[0]!=reader.inputs['dockerBinding']['path']:return native_run(args,**kwargs)
            calls.append((args,kwargs));path=args[args.index('get')+1]
            if drift:drift(path,len(calls),rows)
            return SimpleNamespace(returncode=0,stdout=m.encoded(rows[path]))
        class Engine:
            def __init__(self,*args):self.reads=0
            def get(self,cid):self.reads+=1;return copy.deepcopy(actual)
        return run,Engine,calls

    def test_full_two_pass_read_uses_only_bound_local_gets_and_keeps_secret_out_of_receipt(self):
        reader,_,path,actual,rows=self.prepared();run,Engine,calls=self.native_gets(reader,actual,rows)
        before=path.read_bytes()
        with patch.object(m.subprocess,'run',side_effect=run),patch.object(m,'CurrentIamEngine',Engine):proof=reader.observe()
        self.assertEqual((proof['iamMetadataGets'],proof['engineGets'],len(calls)),(12,2,12))
        self.assertTrue(proof['currentMountedCredentialMatchesKeycloak']);self.assertTrue(proof['examplePayloadIsConfigurationOnly'])
        for args,kwargs in calls:
            self.assertEqual(args[1:4],['--host','unix:///run/reviewed.sock','--config'])
            self.assertIn('get',args);self.assertNotIn(before.decode(),args)
            self.assertEqual(args[args.index('--server')+1],'http://localhost:8080');self.assertLessEqual(kwargs['timeout'],15)
            self.assertEqual(kwargs['env']['HOME'],args[4])
        self.assertNotIn(before,m.encoded(proof));self.assertEqual(path.read_bytes(),before)
        self.assertIs(proof['actualWorkloadBearerAdmissionProven'],False);self.assertIs(proof['fullCohortProven'],False)
        reader.authorization.window.guard.assert_not_called()

    def test_rotated_or_wrong_current_secret_is_preserved_and_denied(self):
        reader,_,path,actual,rows=self.prepared();rows['clients/'+CLIENT+'/client-secret']['value']='different-credential'
        run,Engine,calls=self.native_gets(reader,actual,rows);before=path.read_bytes()
        with patch.object(m.subprocess,'run',side_effect=run),patch.object(m,'CurrentIamEngine',Engine), \
             self.assertRaisesRegex(ValueError,'CREDENTIAL_DIFFER') as error:reader.observe()
        self.assertEqual(path.read_bytes(),before);self.assertNotIn(before.decode(),str(error.exception));self.assertEqual(len(calls),5)

    def test_disabled_and_integer_alias_service_flags_have_no_admission(self):
        reader,_,_,actual,rows=self.prepared();run,Engine,_=self.native_gets(reader,actual,rows)
        for enabled in (False,1):
            rows['clients/'+CLIENT]['enabled']=enabled
            with self.subTest(enabled=enabled),patch.object(m.subprocess,'run',side_effect=run),patch.object(m,'CurrentIamEngine',Engine), \
                 self.assertRaisesRegex(ValueError,'CONFIDENTIAL_WORKLOAD'):reader.observe()

    def test_example_identity_audience_or_scope_cannot_replace_reviewed_application(self):
        reader,_,_,actual,rows=self.prepared();value=rows['clients/'+CLIENT+'/evaluate-scopes/generate-example-access-token']
        run,Engine,_=self.native_gets(reader,actual,rows)
        for key,changed in [('tenant_id','other'),('ouf_actor_type','HUMAN'),('sub',CLIENT),('iss','https://elsewhere.invalid'),
                            ('aud',['ouf-gateway','unreviewed']),('scope',SCOPE+' extra.scope')]:
            old=value[key];value[key]=changed
            with self.subTest(key=key),patch.object(m.subprocess,'run',side_effect=run),patch.object(m,'CurrentIamEngine',Engine), \
                 self.assertRaisesRegex(ValueError,'EFFECTIVE_EXAMPLE_IDENTITY_OR_SCOPES'):reader.observe()
            value[key]=old

    def test_second_pass_or_retained_generation_drift_denies_without_repair(self):
        reader,_,_,actual,rows=self.prepared()
        def drift(path,count,values):
            if count==12:values[path]['tenant_id']='changed-after-first-pass'
        run,Engine,calls=self.native_gets(reader,actual,rows,drift)
        with patch.object(m.subprocess,'run',side_effect=run),patch.object(m,'CurrentIamEngine',Engine),self.assertRaises(ValueError):reader.observe()
        self.assertEqual(len(calls),12)
        actual['State']['Paused']=True;run,Engine,calls=self.native_gets(reader,actual,rows)
        with patch.object(m.subprocess,'run',side_effect=run),patch.object(m,'CurrentIamEngine',Engine), \
             self.assertRaisesRegex(ValueError,'KEYCLOAK_GENERATION_CHANGED'):reader.observe()
        self.assertEqual(calls,[])

    def test_parent_revocation_precedes_iam_read(self):
        reader,parent,_,actual,rows=self.prepared()
        (self.signatures/(parent.sha+'.FINAL_DEPLOYMENT_APPROVAL.json')).unlink()
        native=m.subprocess.run
        with patch.object(m.subprocess,'run',wraps=native) as command,self.assertRaises((OSError,ValueError)):reader.observe()
        self.assertFalse([c for c in command.call_args_list if c.args[0][0]==reader.inputs['dockerBinding']['path']])

    def test_binding_drift_and_unreviewed_gets_cannot_enter_iam(self):
        reader,*_=self.prepared();changed=copy.deepcopy(reader.inputs);changed['expectedScopes'].append('unreviewed')
        with self.assertRaisesRegex(ValueError,'CANNOT_BE_REPLACED'):m.bind_iam_workload_inputs(reader.runtime.inputs,changed)
        reader.gets=reader.response_bytes=0
        native=m.subprocess.run
        for path,query in [('clients/'+CLIENT+'/client-secret/rotated',[]),
                           ('clients/'+CLIENT+'/evaluate-scopes/generate-example-access-token',['-q','audience=forced'])]:
            with patch.object(m.subprocess,'run',wraps=native) as command,self.assertRaisesRegex(ValueError,'GET_ALLOWLIST'):
                reader.get(path,query,m.ObservationBudget(30),'/unused')
            self.assertFalse([c for c in command.call_args_list if c.args[0][0]==reader.inputs['dockerBinding']['path']])

    def test_credential_custody_change_is_denied_and_preserved(self):
        reader,_,path,actual,rows=self.prepared();path.chmod(0o400)
        run,Engine,_=self.native_gets(reader,actual,rows)
        with patch.object(m.subprocess,'run',side_effect=run),patch.object(m,'CurrentIamEngine',Engine), \
             self.assertRaisesRegex(ValueError,'CREDENTIAL_CUSTODY_CHANGED'):reader.observe()
        self.assertEqual(path.stat().st_mode&0o777,0o400)

if __name__=='__main__':unittest.main()
