"""Actual disposable Keycloak protocol qualification; never an OUF VPS command."""
import dataclasses
import base64
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
from tools.semantic_policy_token_owner.iam_admission import IamProfile,PinnedIamOpener,OnlineIamAdmission,_Connection,_Deadline
from tools.semantic_policy_token_owner.producer import Binding,CredentialFile,HttpsGrant
from tools.semantic_lease_recovery.bounded_recovery import Permanent
from tools.semantic_policy_token_owner.iam_binding_candidate import compile_binding,encoded,sha
import tools.semantic_policy_token_owner.iam_binding_candidate as binding_module
sys.modules['iam_binding_candidate']=binding_module
import tools.semantic_policy_token_owner.iam_mapper_enrichment as enrichment
import tools.semantic_policy_token_owner.iam_mapper_semantics_review as mapper_review
sys.modules['iam_mapper_semantics_review']=mapper_review
import tools.semantic_policy_token_owner.iam_introspection_audience_plan as caller_plan
import tools.semantic_policy_token_owner.iam_install_inputs_probe as install_probe
sys.path.insert(0,str(ROOT/'tools/semantic_application_cutover'))
sys.path.insert(0,str(ROOT/'tools/semantic_cohort_admission/cohort-draft'))
import tools
tools.__path__.append(str(ROOT/'tools/semantic_cohort_admission/cohort-draft/tools'))
sys.modules['iam_mapper_enrichment']=enrichment
import tools.semantic_policy_token_owner.iam_audience_transaction as iam_transaction
from test_cutover_authority_native import SignedCutover

IMAGE='quay.io/keycloak/keycloak@sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c'
TARGET_IMAGE_ID='sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c'
SECRET='DISPOSABLE_CI_CLIENT_SECRET'

def certificate(root):
    # Fixture-only native setup keeps the governed Python process -S. No
    # third-party certificate package/site hook enters the action runtime.
    ca=root/'ca.pem';key=root/'key.pem'
    result=subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-sha256','-nodes',
        '-keyout',str(key),'-out',str(ca),'-days','1','-subj','/CN=iam.fixture.test',
        '-addext','subjectAltName=DNS:iam.fixture.test','-addext','basicConstraints=critical,CA:TRUE'],
        stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20,
        env={'PATH':'/usr/bin:/bin','LC_ALL':'C','OPENSSL_CONF':'/dev/null'})
    if result.returncode!=0:raise ValueError('DISPOSABLE_TLS_CERTIFICATE_SETUP_FAILED')
    key.chmod(0o600);return ca,key

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
            #26.7.4 need not auto-register this mapper on a fresh client with
            #our explicit scope selection. The retained VPS has this exact
            #standard client_id effect; register it explicitly in the fixture.
            client['protocolMappers'].append({'name':'fixture-client-id-note','protocol':'openid-connect',
                'protocolMapper':'oidc-usersessionmodel-note-mapper','config':{'claim.name':'client_id',
                    'user.session.note':'client_id','jsonType.label':'String',
                    'access.token.claim':'true','introspection.token.claim':'true'}})
            #The governed fixture transaction adds the caller audience before
            #the positive bearer test, without disabling audience checks.
            realm={'realm':'fixture','enabled':True,'sslRequired':'all','accessTokenLifespan':300,'clientScopes':[{'name':'authorization.bundle.read','protocol':'openid-connect','attributes':{'include.in.token.scope':'true'}}],'clients':[client]}
            config=root/'fixture-realm.json';config.write_text(json.dumps(realm));config.chmod(0o644)
            phase='START_DISPOSABLE_ISSUER'
            cmd=['docker','run','-d','--name',name,'--memory','1g','--memory-swap','1g','--cpus','2','--pids-limit','512','--cap-drop','ALL','--security-opt','no-new-privileges',
                 '-p','127.0.0.1:18443:8443','-v',str(ca)+':/fixture/cert.pem:ro','-v',str(key)+':/fixture/key.pem:ro','-v',str(config)+':/opt/keycloak/data/import/fixture-realm.json:ro',
                 '-e','KC_BOOTSTRAP_ADMIN_USERNAME=ci-admin','-e','KC_BOOTSTRAP_ADMIN_PASSWORD=DISPOSABLE_CI_ADMIN_PASSWORD',
                 '-e','JAVA_OPTS_KC_HEAP=-Xms128m -Xmx512m',IMAGE,'start','--http-enabled=true','--https-port=8443','--https-certificate-file=/fixture/cert.pem','--https-certificate-key-file=/fixture/key.pem','--hostname=https://iam.fixture.test:18443','--import-realm']
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
            cli_prefix=['docker','exec','-e','KC_OPTS=-Xms16m -Xmx128m',name,cli]
            login=subprocess.run([*cli_prefix,'config','credentials','--config',cli_config,
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
                argv=[*cli_prefix,'get',resource,'--config',cli_config,
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
                return native_run([argv[0],argv[1],'-e','KC_OPTS=-Xms16m -Xmx128m',*argv[2:],'--config',cli_config],**kwargs)
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
            report.update(reviewedClientIdSessionNote=review_public['serviceAccountClientIdMapperMatchesRegisteredClientSemantics'],
                reviewedStandardSubject=review_public['standardSubjectMapperMatchesServiceAccountSemantics'],
                reviewedStaticMapperConstraintsComplete=review_public['staticMapperConstraintsComplete'],
                reviewedMapperReasons=review_public['reviewReasons'])
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
            phase='ACTUAL_SCOPED_IAM_MAPPER_TRANSACTION'
            frozen_metadata=binding_module.decode(enriched_raw)
            input_proposal={'schema':'ouf.policy-token-install-input-proposal.v1','bindingCandidate':reviewed,
                'bindingCandidateHash':sha(encoded(reviewed)), 'issuerArtifact':{
                    'declaredVersion':'26.7.4','imageId':TARGET_IMAGE_ID,'codeMountObserved':False},
                'runtimeAuthorityIssued':False,'productionApplyReady':False,'budgetReset':False}
            plan,_=caller_plan.compile_plan(frozen_metadata,sha(enriched_raw),input_proposal,sha(encoded(input_proposal)))
            signed=SignedCutover();signed.setUp()
            try:
                phase='ACTUAL_READ_ONLY_GOVERNANCE_INTAKE'
                import tools.semantic_policy_token_owner.iam_governance_intake as governance_intake
                native_run=subprocess.run
                def intake_cli(argv,**kwargs):
                    if argv[:2]==['/usr/bin/docker','exec']:
                        args=list(argv);args[args.index('ouf-keycloak')]=name
                        args[args.index('--server')+1]='http://127.0.0.1:8080';args[args.index('-r')+1]='fixture'
                        return native_run([*args[:2],'-e','KC_OPTS=-Xms16m -Xmx128m',*args[2:],'--config',cli_config],**kwargs)
                    return native_run(argv,**kwargs)
                policy_binding=signed.binding(signed.policy)
                public_profile={'schema':'ouf.semantic-existing-installation-authority-bindings.v1',
                    'authorities':signed.context,'policyBinding':policy_binding,
                    'keyRefs':{'installer':signed.grant['keyRef'],'attestor':'synthetic-fixture-attestor-key'},
                    'keyBindings':{r:{'path':str(signed.root/(r+'-NOT-OPENED.pem')),'sha256':'a'*64} for r in ('installer','attestor')}}
                public_profile['keyBindings']['installer']=signed.binding(signed.key)
                profile_path=signed.root/'public-profile.json';signed.write(profile_path,encoded(public_profile))
                review_path=signed.root/'review-plan.json';signed.write(review_path,encoded(plan))
                snapshot_path=signed.root/'metadata-snapshot.json';signed.write(snapshot_path,enriched_raw)
                closure={'sourceCommit':'c'*40,'sourceHashes':{n:sha((ROOT/'tools/semantic_policy_token_owner'/(n+'.py')).read_bytes())
                    for n in governance_intake.SOURCE_NAMES}}
                intake_report={'privateEvidenceWrites':0}
                with patch.object(binding_module,'PARENT',signed.root),patch.object(governance_intake,'PROFILE',signed.binding(profile_path)), \
                    patch.object(governance_intake,'POLICY',policy_binding),patch.object(governance_intake,'CONTEXT',signed.context), \
                    patch.object(governance_intake,'PLAN',review_path.name),patch.object(governance_intake,'PLAN_HASH',sha(encoded(plan))), \
                    patch.object(governance_intake,'SNAPSHOT',snapshot_path.name),patch.object(governance_intake,'SNAPSHOT_HASH',sha(enriched_raw)), \
                    patch.object(governance_intake.subprocess,'run',side_effect=intake_cli):
                    prepared=governance_intake.prepare(closure,intake_report)
                if prepared['runtimeAuthorityIssued'] or prepared['productionApplyReady'] or intake_report['privateEvidenceWrites']!=1:
                    raise ValueError('READ_ONLY_GOVERNANCE_INTAKE_SCOPE_UNPROVEN')
                report.update(actualGovernanceIntakeCompiled=True,actualGovernanceIntakeCurrentBaselineMatched=True,
                    fixtureGovernanceIntakeWrites=1,fixtureGovernancePrivateKeysRead=0)
                phase='ACTUAL_EXISTING_OWNER_SIGNED_ACTION'
                sys.modules['iam_governance_intake']=governance_intake
                sys.modules['iam_audience_transaction']=iam_transaction
                import tools.semantic_policy_token_owner.iam_owner_action as owner_action
                import tools.semantic_policy_token_owner.iam_action_runtime as action_runtime
                source_paths={p.stem:p for p in (ROOT/'tools/semantic_policy_token_owner').glob('*.py')}
                source_paths['cutover_authority']=ROOT/'tools/semantic_application_cutover/cutover_authority.py'
                source_paths.update({'tools.'+p.stem:p for p in (ROOT/'tools/semantic_cohort_admission/cohort-draft/tools').glob('*.py')})
                action_sources={n:source_paths[n].read_bytes() for n in action_runtime.MODULES}
                manifest=action_runtime.declaration('c'*40,action_sources,(ROOT/'tools/semantic_policy_token_owner/iam_action_runtime.py').read_bytes())
                native_run=subprocess.run
                def configured_mapper_cli(argv,**kwargs):
                    if argv[:2]==['/usr/bin/docker','exec']:
                        args=list(argv);args[args.index('ouf-keycloak')]=name
                        args[args.index('--server')+1]='http://127.0.0.1:8080'
                        args[args.index('-r')+1]='fixture'
                        args=[*args[:2],'-e','KC_OPTS=-Xms16m -Xmx128m',*args[2:],'--config',cli_config]
                        return native_run(args,**kwargs)
                    return native_run(argv,**kwargs)
                review_report={};action_report={'signaturesIssued':0,'installationKeyAccessAttempted':False}
                intake_path=Path(intake_report['privateEvidencePath'])
                with patch.object(binding_module,'PARENT',signed.root),patch.object(owner_action,'INTAKE',intake_path.name), \
                    patch.object(owner_action,'INTAKE_HASH',intake_report['privateEvidenceHash']), \
                    patch.object(governance_intake,'PROFILE',signed.binding(profile_path)),patch.object(governance_intake,'POLICY',policy_binding), \
                    patch.object(governance_intake,'CONTEXT',signed.context),patch.object(governance_intake,'PLAN',review_path.name), \
                    patch.object(governance_intake,'PLAN_HASH',sha(encoded(plan))),patch.object(governance_intake,'SNAPSHOT',snapshot_path.name), \
                    patch.object(governance_intake,'SNAPSHOT_HASH',sha(enriched_raw)),patch.object(iam_transaction.subprocess,'run',side_effect=configured_mapper_cli):
                    reviewed_action=owner_action.prepare(manifest,review_report)
                    now=int(time.time());decision={'approvalRef':'SYNTHETIC_EXISTING_OWNER_IAM_DECISION',
                        'approvedReviewHash':review_report['privateEvidenceHash'],'approvedSourceClosureHash':reviewed_action['sourceClosureHash'],
                        'approvedAt':now,'firstInvocationBefore':now+120,'decision':'APPROVE_ONE_EXACT_IAM_CALLER_AUDIENCE_MAPPER','state':'ACTIVE'}
                    applied=owner_action.apply(manifest,review_report['privateEvidenceHash'],decision,action_report)
                    authority_path=Path(action_report['privateEvidencePath'])/'authority.json'
                    authority_raw=authority_path.read_bytes();human_path=authority_path.parent/'human.json';human=json.loads(human_path.read_bytes())
                    expected={k:human[k] for k in ('intakeHash','sourceClosureHash','creationRequestHash','predecessorHistoryHash','predecessorIncidentRef')}
                    from cutover_authority import CutoverAuthority
                    from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
                    verifier=DetachedAuthenticator(policy_binding,str(authority_path.parent),prepared['executablesProposedNotAccepted']['openssl'])
                    gate=CutoverAuthority(verifier,signed.binding(human_path),sha(human_path.read_bytes()),signed.context,expected)
                    operation=iam_transaction.AudienceTransaction(plan,sha(encoded(plan)),frozen_metadata,gate,authority_raw)
                    reconciled=operation.run()
                if applied['iamMutations']!=1 or reconciled['iamMutations']!=0 or applied['runtimeAuthorityIssued'] or action_report['signaturesIssued']!=2:
                    raise ValueError('SCOPED_EXISTING_OWNER_SINGLE_MUTATION_UNPROVEN')
                report.update(actualScopedMapperTransactionPassed=True,completedMapperTransactionNotReplayed=True,
                    fixtureMapperMutations=1,fixtureCurrentHumanAndRealDualRoleCrypto=True,
                    actualExistingOwnerIssuerToIamActionPassed=True,fixtureExistingOwnerSignaturesIssued=2,
                    fixtureInstallationKeyAccessAttempted=True,fixturePrivateKeyReadCount=None,
                    actualActionClosureModuleCount=manifest['moduleCount'],actualStdlibByteBoundFileCount=review_report['stdlibFileCount'])
            finally:signed.doCleanups()
            # Expected subject comes from independent authenticated registration,
            # never from decoding/adopting the candidate token being validated.
            issuer='https://iam.fixture.test:18443/realms/fixture'
            profile=IamProfile(issuer,issuer+'/protocol/openid-connect/token',issuer+'/protocol/openid-connect/token/introspect','fixture-client',account['id'],'fixture-tenant','fixture-audience',('authorization.bundle.read',),('authorization.bundle.read','openid','profile','email','roles'),('127.0.0.1',))
            credential=root/'client-credential';credential.write_text(SECRET);credential.chmod(0o400)
            transport=PinnedIamOpener(profile,clock,context);admission=OnlineIamAdmission(profile,CredentialFile(credential),transport,clock)
            binding=Binding(profile.token_endpoint,profile.client_id,'authorization.bundle.read',str(root),'token.jwt',10001)
            phase='REAL_GRANT_AND_INTROSPECTION';admission.prepare(time.monotonic()+10)
            token=HttpsGrant(clock,opener=transport).request(binding,SECRET,time.monotonic()+10)['access_token']
            original_request=admission.request
            def observed_request(url,deadline,data=None):
                value=original_request(url,deadline,data)
                if url==profile.introspection_endpoint:
                    report['positiveIntrospectionActive']=type(value)is dict and value.get('active')is True
                    report['introspectionProtectedFieldPresence']={k:type(value)is dict and k in value
                        for k in ('iss','client_id','sub','aud','scope','iat','exp','tenant_id','ouf_actor_type')}
                return value
            try:
                with patch.object(admission,'request',side_effect=observed_request):
                    if admission.admit(token,time.monotonic()+300,time.monotonic()+10) is not True:raise ValueError('REAL_ISSUER_ADMISSION_FAILED')
            except Exception:
                # Fixture-only JWT inspection diagnoses issuer output; it never
                # admits/adopts the bearer or changes expected registration.
                claims=json.loads(base64.urlsafe_b64decode(token.split('.')[1]+'='*(-len(token.split('.')[1])%4)))
                report['disposableJwtDiagnosticOnlyNoAdmission']={
                    'issuerMatchesRegistered':claims.get('iss')==profile.issuer,
                    'subjectMatchesRegistered':claims.get('sub')==profile.subject_id,
                    'authorizedPartyMatchesRegistered':claims.get('azp')==profile.client_id,
                    'clientIdMatchesRegistered':claims.get('client_id')==profile.client_id,
                    'sidPresent':bool(claims.get('sid')),'sessionStatePresent':bool(claims.get('session_state')),
                    'issuedAtInteger':type(claims.get('iat'))is int,'expiresAtInteger':type(claims.get('exp'))is int,
                    'expiresAfterCurrentClock':type(claims.get('exp'))is int and claims['exp']>time.time()}
                raise
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
            # The added native transaction can outlast the initial synthetic
            # master admin bearer. Obtain a fresh fixture-only setup grant
            # before the distinct revocation test; never replay a mutation.
            status,value=call('POST','/realms/master/protocol/openid-connect/token',{'grant_type':'password','client_id':'admin-cli','username':'ci-admin','password':'DISPOSABLE_CI_ADMIN_PASSWORD'})
            report['fixtureRevocationSetupAdminGrantHttpStatus']=status
            if status!=200:raise ValueError('DISPOSABLE_REVOCATION_SETUP_AUTH_UNPROVEN')
            admin=value['access_token']
            status,current=call('GET','/admin/realms/fixture/clients/'+identifier,bearer=admin)
            report['fixtureRevocationClientReadHttpStatus']=status
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
            with patch.object(caller_plan,'CONTAINER',name),patch.object(caller_plan,'IMAGE',artifact_observation['imageId']):
                distribution,distribution_public=caller_plan.image_bindings({})
            if distribution['id']!=artifact_observation['imageId']:raise ValueError('DISPOSABLE_IMAGE_DISTRIBUTION_UNPROVEN')
            report.update(actualDockerDistributionMetadataObserved=True,
                qualifiedImageArchitecture=distribution_public['imageArchitecture'],
                observedTargetRepositoryDigestMatched=IMAGE in distribution['digests'])
            if IMAGE not in distribution['digests']:raise ValueError('EXACT_OBSERVED_REPOSITORY_DIGEST_NOT_MATCHED')
            report.update(matchesObservedTargetImage=artifact_observation['imageId']==TARGET_IMAGE_ID,
                observedTargetImageId=TARGET_IMAGE_ID,
                reviewedSourceSemanticsProfile=review_public['sourceSemanticsProfile'],
                fixtureServerHeapMaxMiB=512,fixtureCliHeapMaxMiB=128)
            report.update(imageId=result.stdout.decode().strip(),status='QUALIFIED_DISPOSABLE_KEYCLOAK_PROTOCOL',fixtureAdminAndRegistrationOnly=True,productionIssuerAccepted=False,targetInstallerReady=False)
    except Exception as e:
        code=str(e);report.update(status='QUALIFICATION_FAILED',failurePhase=phase,reason=code if code.isupper() and len(code)<=128 else 'DISPOSABLE_IAM_BOUNDARY_UNPROVEN')
        if hasattr(e,'safe_diagnostics'):report['iamEffectDiagnostics']=e.safe_diagnostics
    finally:
        if created:subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
    print('OUF_POLICY_TOKEN_REAL_KEYCLOAK='+json.dumps(report,sort_keys=True))
    Path('policy-token-real-keycloak-evidence.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    return 0 if report['status']=='QUALIFIED_DISPOSABLE_KEYCLOAK_PROTOCOL' else 1
if __name__=='__main__':raise SystemExit(main())
