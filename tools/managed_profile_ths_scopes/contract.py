"""Additive THS OAuth request contract, reused from the retained Teatri/Resolution patch.

Local transformation only: no IAM binding, token, grant, lifecycle or job action.
Caller must obtain current owner configuration and separate deployment authority.
"""
import copy,json,re
from tools.managed_csv_recovery.retained_inputs import Stop,require,digest,decode
REQUIRED=('ouf.managed-source.preview','ouf.managed-source.file.profile','ouf.onboarding.quarantine.release')
REGISTRATION='ouf-ths'
SCOPE_PROPERTY='spring.security.oauth2.client.registration.ouf-ths.scope'
CLIENT_PROPERTY='spring.security.oauth2.client.registration.ouf-ths.client-id'

def normalized(key):return re.sub('[^a-z0-9]','',key.lower())

def spring_properties(obj):
    result={};nodes=[0]
    def walk(value,path=()):
        require(type(value)is dict and len(path)<=24,'BOUNDED_SPRING_JSON_OBJECT_REQUIRED')
        for key,item in value.items():
            nodes[0]+=1;require(nodes[0]<=16384 and type(key)is str and 0<len(key)<=512,'BOUNDED_SPRING_PROPERTY_REQUIRED')
            selected=path+(key,)
            if type(item)is dict:walk(item,selected)
            else:
                canonical=normalized('.'.join(selected))
                require(canonical not in result,'AMBIGUOUS_SPRING_JSON_PROPERTY')
                result[canonical]=(selected,item)
    walk(obj);return result

def scope_list(value):
    if type(value)is str:value=[s for s in re.split(r'[\s,]+',value)if s]
    require(type(value)is list and 0<len(value)<=128
            and all(type(s)is str and re.fullmatch('[A-Za-z0-9_.:-]{1,160}',s)for s in value) and len(value)==len(set(value)),
            'EXACT_EXISTING_THS_SCOPE_LIST_REQUIRED')
    return list(value)

def scope_patch(actual):
    require(type(actual)is dict and type(actual.get('Config'))is dict,'OWNER_CONFIG_REQUIRED')
    config=actual['Config'];values=config.get('Env');require(type(values)is list,'RETAINED_ENVIRONMENT_REQUIRED')
    env={}
    for row in values:
        require(type(row)is str and '='in row,'TYPED_ENVIRONMENT_REQUIRED')
        key,value=row.split('=',1)
        require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]*',key)and key not in env,'UNIQUE_ENVIRONMENT_REQUIRED');env[key]=value
    require(not any(env.get(k)for k in('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','JAVA_OPTS'))
            and not any(type(a)is not str or a.startswith(('-D','--'))for a in(config.get('Entrypoint')or[])+(config.get('Cmd')or[])),
            'UNREVIEWED_OAUTH_REQUEST_ARGUMENT_OVERRIDE')
    require(not any(k.startswith('SPRING_SECURITY_OAUTH2_CLIENT_')for k in env),'DIRECT_OAUTH_ENV_OVERRIDE_REQUIRES_REVIEW')
    require(0<len(env.get('SPRING_APPLICATION_JSON',''))<=1048576,'BOUNDED_EXISTING_SPRING_JSON_REQUIRED')
    original=decode(env['SPRING_APPLICATION_JSON']);properties=spring_properties(original)
    require(normalized(SCOPE_PROPERTY)in properties,'EXPLICIT_SPRING_JSON_SCOPE_OVERRIDE_REQUIRED')
    path,raw_scopes=properties[normalized(SCOPE_PROPERTY)];scopes=scope_list(raw_scopes)
    client=properties.get(normalized(CLIENT_PROPERTY),(None,None))[1]
    require(client is None or type(client)is str and re.fullmatch('[A-Za-z0-9_.:-]{1,128}',client),'LITERAL_CLIENT_ID_REQUIRED')
    missing=[s for s in REQUIRED if s not in scopes]
    proposal=copy.deepcopy(original);cursor=proposal
    for key in path[:-1]:cursor=cursor[key]
    cursor[path[-1]]=scopes+missing if type(raw_scopes)is list else ' '.join(scopes+missing)
    following=spring_properties(proposal)
    require({k:v for k,v in following.items()if k!=normalized(SCOPE_PROPERTY)}=={k:v for k,v in properties.items()if k!=normalized(SCOPE_PROPERTY)},'UNRELATED_SPRING_PROPERTY_CHANGED')
    require(scope_list(following[normalized(SCOPE_PROPERTY)][1])==scopes+missing,'EXACT_ADDITIVE_THS_SCOPE_REQUEST_REQUIRED')
    replacement=json.dumps(proposal,sort_keys=True,separators=(',',':'),allow_nan=False)
    patched=[('SPRING_APPLICATION_JSON='+replacement)if row.startswith('SPRING_APPLICATION_JSON=')else row for row in values] if missing else copy.deepcopy(values)
    require([row for row in patched if not row.startswith('SPRING_APPLICATION_JSON=')]==[row for row in values if not row.startswith('SPRING_APPLICATION_JSON=')],'UNRELATED_ENVIRONMENT_CHANGED')
    summary={'registrationId':REGISTRATION,'clientIdObservedFromJson':client,'clientIdFromLowerPriorityFileRead':False,
             'requestedScopes':scopes,'requiredRecoveryScopes':list(REQUIRED),'missingRequestScopes':missing,
             'retainedScopeCount':len(scopes),'scopeRequestProperty':SCOPE_PROPERTY,
             'requestBeforeHash':digest(original),'conditionalRequestAfterHash':digest(proposal)if missing else digest(original),
             'conditionalConfigurationPatchPrepared':bool(missing),'allOtherEnvironmentAndJsonPropertiesPreserved':True,
             'iamBindingObserved':False,'browserTokenInspected':False,'scopePatchApplied':False,
             'newGrantsGranted':0,'humanBudgetsGranted':0,'resumes':0}
    return summary,patched
