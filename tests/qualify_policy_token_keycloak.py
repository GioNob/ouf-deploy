"""Actual disposable Keycloak protocol qualification; never an OUF VPS command."""
import dataclasses
import json
import os
import re
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import uuid
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
from test_iam_token_admission import certificate
from tools.semantic_policy_token_owner.iam_admission import IamProfile,PinnedIamOpener,OnlineIamAdmission,_Connection,_Deadline
from tools.semantic_policy_token_owner.producer import Binding,CredentialFile,HttpsGrant
from tools.semantic_lease_recovery.bounded_recovery import Permanent
from tools.semantic_policy_token_owner.iam_binding_candidate import compile_binding,encoded,sha
import tools.semantic_policy_token_owner.iam_binding_candidate as binding_module
sys.modules['iam_binding_candidate']=binding_module
import tools.semantic_policy_token_owner.iam_mapper_enrichment as enrichment
import tools.semantic_policy_token_owner.iam_mapper_semantics_review as mapper_review
import tools.semantic_policy_token_owner.iam_install_inputs_probe as install_probe

IMAGE='quay.io/keycloak/keycloak:26.0.8'
SECRET='DISPOSABLE_CI_CLIENT_SECRET'

def main():
    if os.environ.get('OUF_DISPOSABLE_KEYCLOAK')!='1' or os.environ.get('GITHUB_ACTIONS')!='true':raise SystemExit('DISPOSABLE_HOSTED_CI_ONLY')
    name='ouf-disposable-iam-'+uuid.uuid4().hex[:12];phase='PREPARE_FIXTURE';created=False
    report={'schema':'ouf.policy-token-real-keycloak-qualification.v1','productionCalls':0,'targetCredentialReads':0,'r12Touched':False,'notReleaseAcceptance':True,'imageTag':IMAGE}
    try:
        with tempfile.TemporaryDirectory(dir=ROOT,prefix='keycloak-iam-fixture-') as temp:
            root=Path(temp);root.chmod(0o700);ca,key=certificate(root);key.chmod(0o644)
            claim=lambda field,value:{'name':field,'protocol':'openid-connect','protocolMapper':'oidc-hardcoded-claim-mapper','config':{'claim.name':field,'claim.value':value,'jsonType.label':'String','access.token.claim':'true','introspection.token.claim':'true'}}
            client={'clientId':'fixture-client','enabled':True,'protocol':'openid-connect','publicClient':False,'secret':SECRET,'serviceAccountsEnabled':True,'standardFlowEnabled':False,'directAccessGrantsEnabled':False,'defaultClientScopes':['authorization.bundle.read'],'optionalClientScopes':[],
                    'protocolMappers':[claim('tenant_id','fixture-tenant'),claim('ouf_actor_type','SERVICE'),{'name':'fixture-audience','protocol':'openid-connect','protocolMapper':'oidc-audience-mapper','config':{'included.custom.audience':'fixture-audience','access.token.claim':'true','introspection.token.claim':'true'}}]}
            client['protocolMappers'] += [{'name':'fixture-'+kind,'protocol':'openid-connect','protocolMapper':kind,
                'config':{'access.token.claim':'true','introspection.token.claim':'true'}}
                for kind in ('oidc-acr-mapper','oidc-allowed-origins-mapper','oidc-sub-mapper')]
            realm={'realm':'fixture','enabled':True,'sslRequired':'all','accessTokenLifespan':300,'clientScopes':[{'name':'authorization.bundle.read','protocol':'openid-connect','attributes':{'include.in.token.scope':'true'}}],'clients':[client]}
            config=root/'fixture-realm.json';config.write_text(json.dumps(realm));config.chmod(0o644)
            phase='START_DISPOSABLE_ISSUER'
            cmd=['docker','run','-d','--name',name,'--memory','1g','--memory-swap','1g','--cpus','2','--pids-limit','512','--cap-drop','ALL','--security-opt','no-new-privileges',
                 '-p','127.0.0.1:18443:8443','-v',str(ca)+':/fixture/cert.pem:ro','-v',str(key)+':/fixture/key.pem:ro','-v',str(config)+':/opt/keycloak/data/import/fixture-realm.json:ro',
                 '-e','KC_BOOTSTRAP_ADMIN_USERNAME=ci-admin','-e','KC_BOOTSTRAP_ADMIN_PASSWORD=DISPOSABLE_CI_ADMIN_PASSWORD',IMAGE,'start','--http-enabled=true','--https-port=8443','--https-certificate-file=/fixture/cert.pem','--https-certificate-key-file=/fixture/key.pem','--hostname=https://iam.fixture.test:18443','--import-realm']
            result=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180)
            if result.returncode:raise ValueError('DISPOSABLE_ISSUER_START_FAILED')
            created=True;clock=lambda:(time.time(),time.monotonic());context=ssl.create_default_context(cafile=str(ca))
            def call(method,path,fields=None,bearer=None):
                connection=_Connection('iam.fixture.test',18443,'127.0.0.1',context,_Deadline(clock,5))
                headers={'Host':'iam.fixture.test:18443','Accept':'application/json'}
                if bearer:headers['Authorization']='Bearer '+bearer
                if fields is not None:
                    if method=='PUT':body=json.dumps(fields).encode();headers['Content-Type']='application/json'
                    else:body=urllib.parse.urlencode(fields).encode();headers['Content-Type']='application/x-www-form-urlencoded'
                else:body=None
                try:
                    connection.request(method,path,body,headers);response=connection.getresponse();raw=response.read(1048577)
                    if len(raw)>1048576:raise ValueError('DISPOSABLE_RESPONSE_BOUND_EXCEEDED')
                    return response.status,json.loads(raw) if raw else None
                finally:connection.close()
            phase='WAIT_ISSUER_READY';deadline=time.monotonic()+150
            while True:
                try:
                    status,metadata=call('GET','/realms/fixture/.well-known/openid-configuration')
                    if status==200:break
                except Exception:pass
                if time.monotonic()>=deadline:raise ValueError('DISPOSABLE_ISSUER_READINESS_EXHAUSTED')
                time.sleep(1)
            phase='READ_REGISTERED_SERVICE_ACCOUNT'
            status,value=call('POST','/realms/master/protocol/openid-connect/token',{'grant_type':'password','client_id':'admin-cli','username':'ci-admin','password':'DISPOSABLE_CI_ADMIN_PASSWORD'})
            if status!=200:raise ValueError('DISPOSABLE_REGISTRATION_READ_AUTH_UNPROVEN')
            admin=value['access_token'];status,clients=call('GET','/admin/realms/fixture/clients?clientId=fixture-client',bearer=admin)
            if status!=200 or len(clients)!=1:raise ValueError('EXACT_DISPOSABLE_CLIENT_REQUIRED')
            identifier=clients[0]['id'];status,account=call('GET','/admin/realms/fixture/clients/'+identifier+'/service-account-user',bearer=admin)
            if status!=200:raise ValueError('REGISTERED_SERVICE_SUBJECT_UNPROVEN')
            phase='COMPILE_REAL_REGISTERED_CLAIM_METADATA'
            status,default_scopes=call('GET','/admin/realms/fixture/clients/'+identifier+'/default-client-scopes',bearer=admin)
            if status!=200:raise ValueError('REGISTERED_DEFAULT_SCOPES_UNPROVEN')
            status,optional_scopes=call('GET','/admin/realms/fixture/clients/'+identifier+'/optional-client-scopes',bearer=admin)
            if status!=200:raise ValueError('REGISTERED_OPTIONAL_SCOPES_UNPROVEN')
            metadata_snapshot={'schema':'ouf.policy-token-existing-iam-metadata.v1',
                'issuerSelection':'https://iam.fixture.test:18443/realms/fixture','realm':'fixture',
                'client':{k:clients[0][k] for k in ('clientId','enabled','serviceAccountsEnabled','publicClient','protocol','clientAuthenticatorType','protocolMappers')},
                'serviceAccount':{k:account[k] for k in ('id','enabled')},
                'defaultScopes':default_scopes,'optionalScopes':optional_scopes,'requestedScopes':['authorization.bundle.read'],
                'credentialProvenanceAccepted':False,'actualTokenIntrospectionProven':False,
                'targetHttpsPeerBindingProven':False,'historicalAccountingReconciled':False,
                'runtimeAuthorityIssued':False,'notReleaseAcceptance':True}
            candidate,projection=compile_binding(metadata_snapshot,sha(encoded(metadata_snapshot)),
                {'issuer':metadata_snapshot['issuerSelection'],'tenant':'fixture-tenant','audience':'fixture-audience','actor':'SERVICE'})
            report.update(bindingStaticConstraintsComplete=projection['staticMapperConstraintsComplete'],
                bindingReviewReasons=projection['reviewReasons'],
                bindingTenantMapperMatched=projection['tenantStaticMapperMatchesReference'],
                bindingActorMapperMatched=projection['actorStaticMapperMatchesReference'],
                bindingAudienceMapperMatched=projection['audienceStaticMapperMatchesReference'])
            # A real issuer can include additional built-in/default mappers.
            # Unknown metadata must remain a review reason, not be whitelisted
            # merely to make this fixture appear accepted. Actual bearer checks
            # below are independent from this conservative metadata proposal.
            if not all(projection[k] for k in ('tenantStaticMapperMatchesReference',
                      'actorStaticMapperMatchesReference','audienceStaticMapperMatchesReference')) \
                    or candidate['productionApplyReady'] or candidate['runtimeAuthorityIssued']:
                raise ValueError('REGISTERED_CLAIM_COMPILATION_UNPROVEN')
            report['realAdminMetadataBindingCompilationPassed']=True
            phase='EXACT_DISPOSABLE_KCADM_METADATA_PROJECTION'
            # HTTP is not host-published and is used only by the administrative
            # CLI inside its disposable container, matching the retained route.
            # SERVICE grant/admission below still uses actual verified TLS only.
            cli='/opt/keycloak/bin/kcadm.sh';cli_config='/tmp/disposable-kcadm-observation.json'
            login=subprocess.run(['docker','exec',name,cli,'config','credentials','--config',cli_config,
                '--server','http://127.0.0.1:8080','--realm','master','--user','ci-admin',
                '--password','DISPOSABLE_CI_ADMIN_PASSWORD'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
            if login.returncode:
                # Fixed categories only; neither tokens nor raw auth errors are
                # published. Unknown failures block, without a retry/fallback.
                text=(login.stdout+login.stderr)[:16384].decode('utf-8','replace').lower()
                categories=[]
                for pattern,label in ((r'https required|ssl required','HTTPS_REQUIRED'),
                    (r'invalid_grant|invalid user credentials|invalid credentials','AUTHENTICATION_DENIED'),
                    (r'connection refused|connectexception','CONNECTION_REFUSED'),
                    (r'timed out|timeout','CONNECTION_TIMEOUT'),
                    (r'permission denied|accessdeniedexception','CONFIGURATION_WRITE_DENIED'),
                    (r'failed to create|could not save|unable to save','CONFIGURATION_PUBLICATION_FAILED'),
                    (r'unknown option|unmatched argument','CLI_ARGUMENT_UNSUPPORTED'),
                    (r'hostname|certificate|sslhandshake','TLS_PEER_DENIED')):
                    if re.search(pattern,text):categories.append(label)
                statuses=sorted(set(re.findall(r'\b(?:http[^\n]{0,48}|status[^\n]{0,24})\b([45][0-9]{2})\b',text)))
                report.update(kcadmLoginExitCode=login.returncode,
                    kcadmLoginDiagnosticCategories=categories or ['UNCLASSIFIED_AUTH_FAILURE'],
                    kcadmLoginHttpStatuses=statuses)
                raise ValueError('DISPOSABLE_KCADM_LOGIN_FAILED')
            def cli_get(resource,fields,query=None):
                argv=['docker','exec',name,cli,'get',resource,'--config',cli_config,
                      '--server','http://127.0.0.1:8080','-r','fixture','--fields',fields]
                if query:argv+=['-q',query]
                response=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30)
                if response.returncode or not 0<len(response.stdout)<=131072:raise ValueError('DISPOSABLE_KCADM_GET_FAILED')
                return json.loads(response.stdout)
            cli_clients=cli_get('clients','id,clientId,enabled,serviceAccountsEnabled,publicClient,clientAuthenticatorType,protocol,protocolMappers','clientId=fixture-client')
            if type(cli_clients) is not list or len(cli_clients)!=1:raise ValueError('DISPOSABLE_KCADM_CLIENT_NOT_UNIQUE')
            cli_snapshot={**metadata_snapshot,'client':cli_clients[0],
                'defaultScopes':cli_get('clients/'+identifier+'/default-client-scopes','id,name,protocol,protocolMappers'),
                'optionalScopes':cli_get('clients/'+identifier+'/optional-client-scopes','id,name,protocol,protocolMappers')}
            cli_candidate,cli_projection=compile_binding(cli_snapshot,sha(encoded(cli_snapshot)),
                {'issuer':metadata_snapshot['issuerSelection'],'tenant':'fixture-tenant','audience':'fixture-audience','actor':'SERVICE'})
            if cli_candidate['productionApplyReady'] or cli_candidate['runtimeAuthorityIssued']:raise ValueError('CLI_METADATA_FALSE_RUNTIME_ACCEPTANCE')
            report.update(actualKcadmProjectionCompiled=True,kcadmMapperSchemaFindings=cli_projection['mapperSchemaFindings'],
                kcadmUninterpretableMapperCount=cli_projection['uninterpretableMapperCount'],
                kcadmStaticConstraintsComplete=cli_projection['staticMapperConstraintsComplete'])
            phase='ACTUAL_KCADM_OWNER_MAPPER_ENRICHMENT'
            retained=root/('policy-token-iam-metadata-'+'a'*32+'.private.json')
            retained_raw=encoded(cli_snapshot);retained.write_bytes(retained_raw);retained.chmod(0o600)
            evidence={'privateEvidenceWrites':0};native_run=subprocess.run
            def configured_cli(argv,**kwargs):
                # The disposable fixture uses a private explicit CLI cache; all
                # GET/resource/--fields/no-fields behavior is the real source.
                if argv[:5]!=['/usr/bin/docker','exec',name,cli,'get']:raise ValueError('FIXTURE_KCADM_COMMAND_SCOPE_DRIFT')
                return native_run([*argv,'--config',cli_config],**kwargs)
            with patch.object(binding_module,'PARENT',root),patch.object(enrichment,'CONTAINER',name), \
                 patch.object(enrichment,'SERVER','http://127.0.0.1:8080'),patch.object(enrichment,'REALM','fixture'), \
                 patch.object(enrichment.subprocess,'run',side_effect=configured_cli):
                enrichment.execute(str(retained),sha(retained_raw),
                    {'issuer':metadata_snapshot['issuerSelection'],'tenant':'fixture-tenant','audience':'fixture-audience','actor':'SERVICE'},evidence)
            if retained.read_bytes()!=retained_raw or evidence['uninterpretableMapperCount']!=0 or not all(evidence[k] for k in (
                'tenantStaticMapperMatchesReference','actorStaticMapperMatchesReference','audienceStaticMapperMatchesReference')):
                raise ValueError('ACTUAL_KCADM_ENRICHMENT_UNPROVEN')
            report.update(actualKcadmOwnerMapperEnrichmentPassed=True,retainedProjectionPreserved=True,
                enrichedKcadmUninterpretableMapperCount=evidence['uninterpretableMapperCount'],
                enrichedKcadmReviewReasons=evidence['reviewReasons'])
            phase='REAL_REGISTERED_MAPPER_EFFECTS_REVIEW'
            enriched_raw=Path(evidence['enrichedMetadataPath']).read_bytes()
            reviewed,review_public=mapper_review.review(binding_module.decode(enriched_raw),sha(enriched_raw),
                {'issuer':metadata_snapshot['issuerSelection'],'tenant':'fixture-tenant','audience':'fixture-audience','actor':'SERVICE'})
            if not all(review_public[k] for k in ('staticMapperConstraintsComplete',
                    'serviceAccountClientIdMapperMatchesRegisteredClientSemantics',
                    'standardSubjectMapperMatchesServiceAccountSemantics')) \
                    or reviewed['productionApplyReady'] or reviewed['runtimeAuthorityIssued']:
                raise ValueError('REAL_REGISTERED_MAPPER_EFFECTS_UNPROVEN')
            report.update(actualRegisteredMapperEffectsReviewed=True,
                reviewedStaticMapperConstraintsComplete=review_public['staticMapperConstraintsComplete'],
                reviewedClientIdSessionNote=review_public['serviceAccountClientIdMapperMatchesRegisteredClientSemantics'],
                reviewedStandardSubject=review_public['standardSubjectMapperMatchesServiceAccountSemantics'],
                reviewedMapperReasons=review_public['reviewReasons'])
            # Expected subject comes from independent authenticated registration,
            # never from decoding/adopting the candidate token being validated.
            issuer='https://iam.fixture.test:18443/realms/fixture'
            profile=IamProfile(issuer,issuer+'/protocol/openid-connect/token',issuer+'/protocol/openid-connect/token/introspect','fixture-client',account['id'],'fixture-tenant','fixture-audience',('authorization.bundle.read',),('authorization.bundle.read','openid','profile','email','roles'),('127.0.0.1',))
            credential=root/'client-credential';credential.write_text(SECRET);credential.chmod(0o400)
            transport=PinnedIamOpener(profile,clock,context);admission=OnlineIamAdmission(profile,CredentialFile(credential),transport,clock)
            binding=Binding(profile.token_endpoint,profile.client_id,'authorization.bundle.read',str(root),'token.jwt',10001)
            phase='REAL_GRANT_AND_INTROSPECTION';admission.prepare(time.monotonic()+10)
            token=HttpsGrant(clock,opener=transport).request(binding,SECRET,time.monotonic()+10)['access_token']
            if admission.admit(token,time.monotonic()+300,time.monotonic()+10) is not True:raise ValueError('REAL_ISSUER_ADMISSION_FAILED')
            report['positiveRealIssuerAdmission']=True
            phase='WRONG_AUDIENCE_AND_TAMPER_DENIAL'
            wrong=dataclasses.replace(profile,audience='unapproved-audience')
            wrong_admission=OnlineIamAdmission(wrong,CredentialFile(credential),PinnedIamOpener(wrong,clock,context),clock)
            try:wrong_admission.admit(token,time.monotonic()+300,time.monotonic()+10)
            except Permanent:report['wrongAudienceDenied']=True
            else:raise ValueError('UNAPPROVED_AUDIENCE_ACCEPTED')
            try:admission.admit(token[:-8]+'INVALID',time.monotonic()+300,time.monotonic()+10)
            except Permanent:report['tamperedTokenDenied']=True
            else:raise ValueError('TAMPERED_TOKEN_ACCEPTED')
            phase='REAL_CLIENT_REVOCATION_DENIAL'
            status,current=call('GET','/admin/realms/fixture/clients/'+identifier,bearer=admin)
            if status!=200:raise ValueError('DISPOSABLE_CLIENT_STATE_UNAVAILABLE')
            current['enabled']=False;status,_=call('PUT','/admin/realms/fixture/clients/'+identifier,current,bearer=admin)
            if status!=204:raise ValueError('DISPOSABLE_CLIENT_DISABLE_UNPROVEN')
            try:admission.admit(token,time.monotonic()+300,time.monotonic()+10)
            except Permanent:report['currentDisabledClientDenied']=True
            else:raise ValueError('DISABLED_CLIENT_ACCEPTED')
            result=subprocess.run(['docker','inspect','--format','{{.Image}}',name],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=True)
            with patch.object(install_probe,'CONTAINER',name):
                artifact_observation=install_probe.artifact()
            if artifact_observation['imageId']!=result.stdout.decode().strip() or artifact_observation['targetProviderImplementationProven']:
                raise ValueError('DISPOSABLE_ARTIFACT_OBSERVATION_UNPROVEN')
            report['actualDockerArtifactMetadataObserved']=True
            report.update(imageId=result.stdout.decode().strip(),status='QUALIFIED_DISPOSABLE_KEYCLOAK_PROTOCOL',fixtureAdminAndRegistrationOnly=True,productionIssuerAccepted=False,targetInstallerReady=False)
    except Exception as e:
        code=str(e);report.update(status='QUALIFICATION_FAILED',failurePhase=phase,reason=code if code.isupper() and len(code)<=128 else 'DISPOSABLE_IAM_BOUNDARY_UNPROVEN')
    finally:
        if created:subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
    print('OUF_POLICY_TOKEN_REAL_KEYCLOAK='+json.dumps(report,sort_keys=True))
    Path('policy-token-real-keycloak-evidence.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    return 0 if report['status']=='QUALIFIED_DISPOSABLE_KEYCLOAK_PROTOCOL' else 1
if __name__=='__main__':raise SystemExit(main())
