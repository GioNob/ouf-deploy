"""Current installed workload credential/configuration, without a grant probe.

Parent-bound GETs use the selected existing kcadm session in the retained
Keycloak generation through the same pinned local Engine. Secret bytes remain
in memory. Keycloak's example-token JSON is configuration evidence, never an
issued bearer, introspection, provenance, HTTP readiness or complete admission.
No login, secret rotation, scope/role write or publication is implemented here.
"""
import copy,hmac,os,re,stat,subprocess,tempfile,uuid
from pathlib import Path
from urllib.parse import urlsplit
from .custody_capture import decode,digest,encoded,require
from .current_cohort import CurrentCohortRuntime,CurrentCohortEngine,INPUT_SCHEMA_V2,validate_inputs
from .native_profile import DiscoveryProfile
from .node_owner import ObservationBudget
from .private_review import hashed,absolute
from .publication_owner import DiscoveryAuthorization,OwnerTransport
from tools.semantic_provider_deployment_authentication import attributes
from tools.semantic_target_review.prepare_application_runtime_inputs import file_bytes
from engine_creation import Engine

SCHEMA='ouf.discovery-current-iam-workload-inputs.v1'
IDENTITY=re.compile('[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,255}')
CORE='id,clientId,enabled,serviceAccountsEnabled,publicClient,clientAuthenticatorType,protocol'


def registered_id(value):
    require(type(value) is str and str(uuid.UUID(value))==value,'EXACT_REGISTERED_WORKLOAD_IAM_ID_REQUIRED')
    return value


def validate(inputs):
    fields={'schema','sourceClosureHash','installationInputsHash','desiredProfileHash','cohortManifestHash',
        'executionProfileHash','dockerBinding','keycloakRuntimeBinding','realm','clientUuid','serviceAccountUuid',
        'expectedScopes','expectedAudiences'}
    require(type(inputs) is dict and set(inputs)==fields and inputs['schema']==SCHEMA
        and all(hashed(inputs[k]) for k in ('sourceClosureHash','installationInputsHash','desiredProfileHash',
            'cohortManifestHash','executionProfileHash')) and len(encoded(inputs))<=16384,
        'EXACT_CURRENT_IAM_WORKLOAD_INPUTS_REQUIRED')
    d=inputs['dockerBinding'];require(type(d) is dict and set(d)=={'path','sha256'} and hashed(d['sha256']),
        'PINNED_CURRENT_IAM_DOCKER_REQUIRED');absolute(d['path'])
    require(type(inputs['realm']) is str and re.fullmatch('[A-Za-z0-9_.-]{1,64}',inputs['realm']),
        'EXACT_CURRENT_WORKLOAD_REALM_REQUIRED')
    registered_id(inputs['clientUuid']);registered_id(inputs['serviceAccountUuid'])
    for name in ('expectedScopes','expectedAudiences'):
        values=inputs[name]
        require(type(values) is list and 1<=len(values)<=32 and all(type(v) is str and IDENTITY.fullmatch(v) for v in values)
            and values==sorted(set(values)),'EXACT_REVIEWED_WORKLOAD_SCOPE_AND_AUDIENCE_SETS_REQUIRED')
    require(type(inputs['keycloakRuntimeBinding']) is dict,'REVIEWED_CURRENT_KEYCLOAK_GENERATION_REQUIRED')
    return digest(inputs)


def bind_iam_workload_inputs(runtime_inputs,inputs):
    validate_inputs(runtime_inputs);sha=validate(inputs)
    require(all(runtime_inputs[k]==inputs[k] for k in ('sourceClosureHash','installationInputsHash','desiredProfileHash','cohortManifestHash'))
        and runtime_inputs['peers']['keycloak']['runtimeBinding']==inputs['keycloakRuntimeBinding'],
        'SAME_CURRENT_COHORT_AND_IAM_WORKLOAD_INPUTS_REQUIRED')
    result=copy.deepcopy(runtime_inputs);extra=result.setdefault('additionalInputsHashes',{})
    require('iamWorkload' not in extra or extra['iamWorkload']==sha,'CURRENT_IAM_WORKLOAD_BINDING_CANNOT_BE_REPLACED')
    result['schema']=INPUT_SCHEMA_V2;extra['iamWorkload']=sha;validate_inputs(result);return result


class CurrentIamEngine(CurrentCohortEngine):
    TARGET_COUNT=1
    MAX_GETS=2


class CurrentWorkloadIam:
    def __init__(self,runtime,authorization,inputs):
        require(type(runtime) is CurrentCohortRuntime and type(authorization) is DiscoveryAuthorization
            and runtime.selected is authorization.window.selected and type(authorization.transport) is OwnerTransport,
            'ACTUAL_SAME_DISCOVERY_COHORT_AND_AUTHORIZATION_OWNER_REQUIRED')
        self.runtime,self.authorization=runtime,authorization;self.inputs=copy.deepcopy(inputs);self.input_hash=validate(inputs)
        self.ids=(id(runtime),id(authorization),id(authorization.window),id(authorization.transport));self.guard()

    def guard(self):
        r,a,i=self.runtime,self.authorization,self.inputs;r.guard();a.window.lineage()
        require(self.ids==(id(r),id(a),id(a.window),id(a.transport)) and r.selected is a.window.selected
            and type(a.transport) is OwnerTransport and a.owner_ids==tuple(map(id,(a.window,a.journal,a.transport,a.action)))
            and a.plan==a.window.assembly['authorizationPlan'] and digest(a.plan)==a.hash
            and a.scope==a.window.component['authorization'] and a.transport.selection==a.plan['selection']
            and a.action.authority is a.window.gate.child and a.action.raw==a.window.gate.raw
            and a.action.authority_hash==a.window.child_hash,
            'CURRENT_IAM_AUTHORIZATION_OWNER_LINEAGE_CHANGED')
        app=r.selected.installation.application;p=app.profile;s=a.transport.selection
        require(type(p) is DiscoveryProfile and p.verify(app.request)==i['executionProfileHash']
            and validate(i)==self.input_hash and r.inputs['schema']==INPUT_SCHEMA_V2
            and r.inputs['additionalInputsHashes'].get('iamWorkload')==self.input_hash
            and all(r.inputs[k]==i[k] for k in ('sourceClosureHash','installationInputsHash','desiredProfileHash','cohortManifestHash'))
            and r.inputs['peers']['keycloak']['runtimeBinding']==i['keycloakRuntimeBinding']
            and s['keycloakContainer']==i['keycloakRuntimeBinding']['containerId'] and s['docker']==i['dockerBinding']
            and s['realm']==i['realm'],'EXACT_PARENT_BOUND_CURRENT_WORKLOAD_IAM_AND_KEYCLOAK_REQUIRED')
        refs=p.selection['references'];issuer=urlsplit(refs['OUF_IAM_ISSUER'])
        require(s['issuer']==refs['OUF_IAM_ISSUER'] and issuer.path=='/realms/'+i['realm']
            and refs['OUF_SCHEMA_GOV_TOKEN_ENDPOINT']==refs['OUF_IAM_ISSUER']+'/protocol/openid-connect/token'
            and refs['OUF_SCHEMA_GOV_WORKLOAD_SCOPE'] in i['expectedScopes']
            and refs['OUF_IAM_AUDIENCE'] in i['expectedAudiences'],
            'SAME_SIGNED_APPLICATION_WORKLOAD_ISSUER_TOKEN_ENDPOINT_SCOPE_AND_AUDIENCE_REQUIRED')
        file_bytes(i['dockerBinding']['path'],0,{0o755},limit=67108864,expected=i['dockerBinding']['sha256'])
        return app

    def credential(self):
        f=self.guard().profile.selection['files']['providerCredential'];path=Path(f['source']);before=attributes(path.lstat())
        info=path.lstat()
        require(digest(before)==f['metadataHash'] and (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))==(f['uid'],f['gid'],f['mode']),
            'CURRENT_WORKLOAD_CREDENTIAL_CUSTODY_CHANGED')
        raw=file_bytes(path,0,{0o440},limit=f['maxBytes'],expected=f['sha256'])
        # Canonical ASCII without whitespace avoids inventing application-side
        # normalization rules. The exact reviewed mounted bytes must match.
        require(re.fullmatch(rb'[!-~]{16,1024}',raw) and attributes(path.lstat())==before,
            'EXACT_REVIEWED_WORKLOAD_CREDENTIAL_BYTES_REQUIRED')
        return raw,before

    def get(self,path,query,budget,cli_config):
        self.guard();i=self.inputs;client='clients/'+i['clientUuid']
        allowed={client:[],client+'/service-account-user':[],client+'/default-client-scopes':[],
            client+'/optional-client-scopes':[],client+'/client-secret':[],
            client+'/evaluate-scopes/generate-example-access-token':[
                '-q','userId='+i['serviceAccountUuid'],'-q','scope='+self.runtime.selected.installation.application.profile.selection['references']['OUF_SCHEMA_GOV_WORKLOAD_SCOPE']]}
        require(path in allowed and query==allowed[path] and self.gets<12,'CLOSED_CURRENT_IAM_WORKLOAD_GET_ALLOWLIST_REQUIRED')
        self.gets+=1;engine=self.runtime.selected.images.engine
        args=[i['dockerBinding']['path'],'--host','unix://'+engine.path,'--config',cli_config,'exec',
            i['keycloakRuntimeBinding']['containerId'],'/opt/keycloak/bin/kcadm.sh','get',path,
            '--server','http://localhost:8080','-r',i['realm'],*query]
        if path==client:args+=['--fields',CORE]
        elif path==client+'/service-account-user':args+=['--fields','id,enabled']
        elif path.endswith('-client-scopes'):args+=['--fields','id,name,protocol']
        result=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
            timeout=budget.remaining(15),env={'PATH':'/usr/bin:/bin','LC_ALL':'C','HOME':cli_config})
        self.response_bytes+=len(result.stdout)
        require(result.returncode==0 and 0<len(result.stdout)<=262144 and self.response_bytes<=2097152,
            'BOUNDED_EXISTING_CURRENT_WORKLOAD_IAM_GET_REQUIRED')
        budget.check();return decode(result.stdout)

    def configuration(self,budget,cli_config):
        i=self.inputs;refs=self.guard().profile.selection['references'];client='clients/'+i['clientUuid']
        c=self.get(client,[],budget,cli_config);service=self.get(client+'/service-account-user',[],budget,cli_config)
        require(type(c) is dict and set(c)==set(CORE.split(',')) and encoded(c)==encoded({'id':i['clientUuid'],
            'clientId':refs['OUF_SCHEMA_GOV_CLIENT_ID'],'enabled':True,'serviceAccountsEnabled':True,
            'publicClient':False,'clientAuthenticatorType':'client-secret','protocol':'openid-connect'})
            and encoded(service)==encoded({'id':i['serviceAccountUuid'],'enabled':True}),
            'CURRENT_ENABLED_CONFIDENTIAL_WORKLOAD_SERVICE_ACCOUNT_REQUIRED')
        names=[]
        for suffix in ('default-client-scopes','optional-client-scopes'):
            values=self.get(client+'/'+suffix,[],budget,cli_config)
            require(type(values) is list and len(values)<=64,'BOUNDED_CURRENT_WORKLOAD_SCOPE_METADATA_REQUIRED')
            for row in values:
                require(type(row) is dict and {'id','name'}<=set(row)<={'id','name','protocol'}
                    and type(row['name']) is str and IDENTITY.fullmatch(row['name'])
                    and row.get('protocol','openid-connect')=='openid-connect','CURRENT_WORKLOAD_SCOPE_METADATA_REQUIRED')
                registered_id(row['id']);names.append(row['name'])
        require(len(names)==len(set(names)) and refs['OUF_SCHEMA_GOV_WORKLOAD_SCOPE'] in names,
            'REQUESTED_WORKLOAD_SCOPE_MUST_ALREADY_BE_ASSIGNED')
        current_secret=self.get(client+'/client-secret',[],budget,cli_config);mounted,pin=self.credential()
        require(type(current_secret) is dict and set(current_secret)=={'type','value'} and current_secret['type']=='secret'
            and type(current_secret['value']) is str and hmac.compare_digest(current_secret['value'].encode('utf-8'),mounted),
            'CURRENT_KEYCLOAK_AND_MOUNTED_WORKLOAD_CREDENTIAL_DIFFER')
        value=self.get(client+'/evaluate-scopes/generate-example-access-token',[
            '-q','userId='+i['serviceAccountUuid'],'-q','scope='+refs['OUF_SCHEMA_GOV_WORKLOAD_SCOPE']],budget,cli_config)
        require(type(value) is dict,'CURRENT_KEYCLOAK_WORKLOAD_EXAMPLE_PAYLOAD_REQUIRED')
        audiences=value.get('aud');audiences=[audiences] if type(audiences) is str else audiences
        scope=value.get('scope');require(type(scope) is str and len(scope)<=4096,'CURRENT_WORKLOAD_EXAMPLE_SCOPES_REQUIRED')
        scopes=scope.split(' ')
        require(all(value.get(k)==v for k,v in {'iss':refs['OUF_IAM_ISSUER'],'sub':i['serviceAccountUuid'],
            'azp':refs['OUF_SCHEMA_GOV_CLIENT_ID'],'tenant_id':self.authorization.transport.selection['tenant'],
            'ouf_actor_type':'SERVICE'}.items()) and type(audiences) is list
            and all(type(v) is str for v in audiences) and sorted(audiences)==i['expectedAudiences']
            and sorted(scopes)==i['expectedScopes'],'CURRENT_WORKLOAD_EFFECTIVE_EXAMPLE_IDENTITY_OR_SCOPES_DIFFER')
        require(self.credential()==(mounted,pin),'CURRENT_WORKLOAD_CREDENTIAL_CHANGED_DURING_IAM_READ')
        return {'configurationHash':digest({'client':c,'service':service,'assignedScopeNames':sorted(names),
            'scopes':i['expectedScopes'],'audiences':i['expectedAudiences']}),'credentialCustody':pin}

    def observe(self):
        budget=ObservationBudget(180);self.guard();held=self.runtime.selected.held();self.gets=0;self.response_bytes=0
        i=self.inputs;binding=i['keycloakRuntimeBinding']
        reader=CurrentIamEngine(self.runtime.selected.images.engine,self.runtime.inputs['engineBinding'],[binding['containerId']],budget)
        def peer():
            actual=reader.get(binding['containerId']);state=actual['State']
            require(Engine.runtime_binding(actual)==binding and state['Running'] is True and state['Paused'] is False
                and state['Restarting'] is False and actual['RestartCount']==0,'CURRENT_WORKLOAD_KEYCLOAK_GENERATION_CHANGED')
        peer()
        with tempfile.TemporaryDirectory(prefix='ouf-current-iam-cli-') as config:
            first=self.configuration(budget,config);require(self.configuration(budget,config)==first,
                'CURRENT_WORKLOAD_IAM_CHANGED_DURING_TWO_PASS_READ')
        peer();self.guard();self.runtime.selected.held(held);budget.check()
        require(self.gets==12 and reader.reads==2,'EXACT_TWO_PASS_CURRENT_WORKLOAD_IAM_OBSERVATION_REQUIRED')
        return {'schema':'ouf.discovery-current-workload-iam-configuration.v1','inputHash':self.input_hash,
            'heldHistoryHash':digest(held),'configurationHash':first['configurationHash'],
            'currentMountedCredentialMatchesKeycloak':True,'currentWorkloadConfigurationObserved':True,
            'examplePayloadIsConfigurationOnly':True,'iamMetadataGets':12,'engineGets':2,
            'actualWorkloadBearerAdmissionProven':False,'credentialPublisherProvenanceProvenHere':False,
            'tokenGrantProbesIssued':0,'iamMutations':0,'fullCohortProven':False,
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}
