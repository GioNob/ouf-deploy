"""Read-only selection for the single cohort preparer.

The projection path is the exact retained Gateway rollout source selection, not
an inferred filesystem search. Live Gateway Lua identities are subsequently
matched by prepare_gateway. HUMAN subject/tenant are intended context only until
the existing owner validates the actual session; no credential is issued here.
"""
import copy
import hashlib
import json
import re
import stat
import types
from pathlib import Path
from urllib.parse import urlsplit

from engine_creation import Engine
from tools.chatbot_file_cohort.plan import require, sha, environment, runtime_pin
from tools.chatbot_file_cohort.gateway import private_config

PROJECTION_PATH='/opt/ouf/installation/active-projection.json'
# Both qualified ops/apisix/prepare_r4a_runtime.py and prepare_r4a_route.py select it.
THS_MOUNT='/run/secrets/onboarding-ths.yaml'
PICKER_SOURCE='scripts/r4a_picker_onboarding_rollout.py'
SUBJECT='b93d8cf6-cd14-4ee6-91d7-84cd76c4f500'
TENANT='ouf-lab'
CHATGPT_CLIENT='ouf-chatgpt'


def flattened(value,prefix=()):
    require(type(value) is dict,'CONFIGURATION_OBJECT_REQUIRED')
    result={}
    for name,child in value.items():
        require(type(name) is str,'CONFIGURATION_KEY_REQUIRED')
        path=prefix+tuple(name.split('.'))
        if type(child) is dict:
            nested=flattened(child,path)
            require(not set(result)&set(nested),'AMBIGUOUS_CONFIGURATION_KEY')
            result.update(nested)
        else:
            require(path not in result,'AMBIGUOUS_CONFIGURATION_KEY');result[path]=child
    return result


def selected_ths_urls(raw):
    """Only literal issuer/public-origin scalars; never general YAML evaluation."""
    text=raw.decode('utf-8')
    if text.lstrip().startswith('{'):
        values=flattened(json.loads(text))
    else:
        values={};parents=[]
        for line in text.splitlines():
            if not line.strip() or line.lstrip().startswith('#'):continue
            match=re.fullmatch(r'( *)([A-Za-z0-9_.-]+):(?:[ ]+(.*))?',line)
            if not match:continue
            indent=len(match[1]);name=tuple(match[2].split('.'));raw_value=match[3]
            while parents and parents[-1][0]>=indent:parents.pop()
            path=(parents[-1][1] if parents else ())+name
            if raw_value is None:
                parents.append((indent,path));continue
            if path[-1] not in ('issuer-uri','public-origin'):continue
            require(path not in values,'DUPLICATE_SELECTED_THS_URL')
            value=raw_value.strip()
            if value.startswith('"'):
                try:value=json.loads(value)
                except ValueError:raise ValueError('THS_URL_LITERAL_REQUIRED') from None
            elif value.startswith("'"):
                require(value.endswith("'") and "'" not in value[1:-1],'THS_URL_LITERAL_REQUIRED')
                value=value[1:-1]
            require(type(value) is str and not any(c in value for c in ('#','$','{','}','&','*')),
                    'THS_URL_LITERAL_REQUIRED')
            values[path]=value
    return {k:v for k,v in values.items() if k[-1] in ('issuer-uri','public-origin')}


def https(value,issuer=False):
    require(type(value) is str,'HTTPS_SELECTION_REQUIRED')
    parsed=urlsplit(value)
    require(parsed.scheme=='https' and parsed.hostname and not parsed.username and not parsed.password
            and not parsed.query and not parsed.fragment and parsed.port in (None,443), 'HTTPS_SELECTION_REQUIRED')
    if issuer:
        match=re.fullmatch(r'/realms/([A-Za-z0-9._:-]{1,128})',parsed.path)
        require(match is not None,'EXACT_ISSUER_REALM_REQUIRED');return match[1]
    require(parsed.path in ('','/'),'OWNER_ORIGIN_WITHOUT_PATH_REQUIRED')


def effective_ths(raw,values,picker):
    client,scopes=picker.scopes_from_ths_config(raw.decode('utf-8'))
    urls=selected_ths_urls(raw)
    # The retained picker rollout uses this explicit JSON overlay; its scope
    # list overrides the mounted registration and is therefore observed too.
    overlay={}
    if values.get('SPRING_APPLICATION_JSON'):
        try:overlay=flattened(json.loads(values['SPRING_APPLICATION_JSON']))
        except (ValueError,TypeError):raise ValueError('SPRING_JSON_OVERLAY_UNREADABLE') from None
    registration=('spring','security','oauth2','client','registration','ouf-ths')
    client=overlay.get(registration+('client-id',),client)
    scopes=overlay.get(registration+('scope',),scopes)
    if type(scopes) is str:scopes=[v for v in re.split(r'[\s,]+',scopes) if v]
    require(type(client) is str and re.fullmatch(r'[A-Za-z0-9._-]{1,128}',client)
            and type(scopes) is list and 1<=len(scopes)<=256 and len(scopes)==len(set(scopes))
            and all(type(v) is str and re.fullmatch(r'[A-Za-z0-9._:-]{1,256}',v) for v in scopes),
            'EXACT_EFFECTIVE_THS_REGISTRATION_REQUIRED')
    require(not any(k.startswith('SPRING_SECURITY_OAUTH2_CLIENT_') for k in values),
            'DIRECT_OAUTH_ENV_OVERRIDE_REQUIRES_REVIEW')
    urls.update({k:v for k,v in overlay.items() if k[-1] in ('issuer-uri','public-origin')})
    return client,scopes,urls


def select_target(engine,docker_binding,picker,picker_source_hash,*,projection_path=PROJECTION_PATH,
                  subject=SUBJECT,tenant=TENANT,keycloak_container='ouf-keycloak'):
    require(type(engine) is Engine and type(picker) is types.ModuleType
            and picker.__name__=='qualified_onboarding_picker'
            and sha(picker_source_hash) and getattr(picker,'__qualified_source_sha256__',None)==picker_source_hash,
            'QUALIFIED_EXISTING_THS_PARSER_REQUIRED')
    require(subject==SUBJECT and tenant==TENANT,'RETAINED_HUMAN_CONTEXT_REQUIRED')
    require(set(docker_binding)=={'path','sha256'} and sha(docker_binding['sha256']),
            'EXACT_DOCKER_EXECUTABLE_BINDING_REQUIRED')
    binary=Path(docker_binding['path']);info=binary.lstat()
    require(binary.is_absolute() and stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,
            'CUSTODIED_DOCKER_EXECUTABLE_REQUIRED')
    with binary.open('rb') as stream:
        require(hashlib.file_digest(stream,'sha256').hexdigest()==docker_binding['sha256'],
                'DOCKER_EXECUTABLE_HASH_DRIFT')
    projection_raw,projection_binding=private_config(projection_path)
    projection=json.loads(projection_raw)
    issuer=projection['gateway']['issuerUrl'].rstrip('/')
    origin=projection['gateway']['publicApiBaseUrl'].rstrip('/')
    realm=https(issuer,True);https(origin)
    require(projection['iam']['workloadClients']['mcpServer']==projection['mcp']['environment']['MCP_OIDC_CLIENT_ID'],
            'PROJECTION_WORKLOAD_IDENTITY_CONFLICT')
    code,onboarding=engine.request('GET','/v1.44/containers/ouf-onboarding/json')
    require(code==200 and onboarding.get('Name')=='/ouf-onboarding','SELECTED_ONBOARDING_REQUIRED')
    onboarding_pin=runtime_pin(onboarding);values=environment(onboarding['Config'].get('Env') or [])
    mounts=[m for m in onboarding['Mounts'] if m.get('Destination')==THS_MOUNT]
    require(len(mounts)==1 and mounts[0].get('Type')=='bind' and mounts[0].get('RW') is False,
            'EXACT_CURRENT_THS_CONFIGURATION_BIND_REQUIRED')
    ths_raw,ths_binding=private_config(mounts[0]['Source'])
    client,scopes,urls=effective_ths(ths_raw,values,picker)
    issuer_urls=[v for k,v in urls.items() if k[:5]==('spring','security','oauth2','client','provider') and k[-1]=='issuer-uri']
    origins=[v for k,v in urls.items() if k==('ouf','authorization','ths','public-origin')]
    require(issuer_urls and all(type(v) is str and v.rstrip('/')==issuer for v in issuer_urls)
            and (not origins or all(type(v) is str and v.rstrip('/')==origin for v in origins)),
            'MOUNTED_THS_ISSUER_OR_ORIGIN_DISAGREES_WITH_PROJECTION')
    if 'OUF_RUNTIME_PUBLICATIONS_TENANT_ID' in values:
        require(values['OUF_RUNTIME_PUBLICATIONS_TENANT_ID']==tenant,'ONBOARDING_TENANT_CONTEXT_DRIFT')
    code,keycloak=engine.request('GET','/v1.44/containers/'+keycloak_container+'/json')
    require(code==200 and keycloak.get('Name')=='/'+keycloak_container,'SELECTED_CURRENT_KEYCLOAK_REQUIRED')
    keycloak_pin=runtime_pin(keycloak)
    selection={'origin':origin,'issuer':issuer,'tenant':tenant,'subject':subject,
               'docker':copy.deepcopy(docker_binding),'keycloakContainer':keycloak['Id'],'realm':realm,
               'clients':{'chatgpt':{'clientId':CHATGPT_CLIENT,'requestedScopes':[]},
                          'ths':{'clientId':client,'requestedScopes':scopes}}}
    private_config(projection_path,projection_binding);private_config(mounts[0]['Source'],ths_binding)
    for name,pin in (('ouf-onboarding',onboarding_pin),(keycloak_container,keycloak_pin)):
        code,current=engine.request('GET','/v1.44/containers/'+name+'/json')
        require(code==200 and runtime_pin(current)==pin,'SELECTED_RUNTIME_CHANGED_DURING_READ')
    return {'selection':selection,'projectionBinding':projection_binding,'thsConfigurationBinding':ths_binding,
            'onboardingRuntimeBinding':onboarding_pin,'keycloakRuntimeBinding':keycloak_pin,
            'helperBindings':{PICKER_SOURCE:picker_source_hash},'chatgptOptionalScopesRequestedProven':False,
            'humanSessionVerified':False,'serviceMutations':0,'iamMutations':0,'credentialFilesRead':1,
            'rawSourceOrEnvironmentPrinted':False,'runtimeAuthorityIssued':False,'notReleaseAcceptance':True}
