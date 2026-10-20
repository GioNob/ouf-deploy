"""Compile a reviewable finite intent sequence. Never grants runtime authority."""
import copy
import hashlib
import json
from pathlib import PurePosixPath
import re

PROFILE='ouf.ingestion-gateway-finite-rollout.v1'
AUTHORITY_KEY='ingestionGatewayRollout'
READINESS={'maximumAttempts':128,'maximumElapsedSeconds':900,'backoffSeconds':[5,15,60,300,900],
           'maximumJitterPercent':20,'respectRetryAfter':True,'automaticRenewalAllowed':False}
FORBIDDEN=('budgetReset','automaticReplayAllowed','automaticRollbackAllowed','newLoginAllowed','refreshAllowed',
           'databaseMigrationAllowed','ownerMutationAllowed','projectionPublicationAllowed','grantChangesAllowed',
           'sourceActivationAllowed','jobDispatchAllowed','nativeProfilePublicationAllowed')

class Denied(RuntimeError):pass
class Paused(RuntimeError):pass
def require(ok,code):
    if not ok:raise Denied(code)
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return hashlib.sha256(encoded(value)).hexdigest()
def path(value):
    require(type(value)is str and value.startswith('/')and '\0'not in value and len(value)<=4096
            and '..'not in PurePosixPath(value).parts and str(PurePosixPath(value))==value,'EXACT_ABSOLUTE_PROFILE_PATH_REQUIRED')
    return value
def hashed(value):return type(value)is str and re.fullmatch('[0-9a-f]{64}',value)is not None

def compile_review(packet,packet_binding,inputs,human_binding,execution_context):
    require(type(packet)is dict and packet.get('schema')=='ouf.ingestion-rollout-private-packet.v3'
            and packet.get('kind')=='PRIVATE_TEMPLATES_NOT_EXECUTABLE_AUTHORITY'
            and packet.get('runtimeAuthorityIssued')is False and packet.get('runtimeExecutorQualified')is False
            and packet.get('databaseAdmissionProven')is False and packet.get('targetApplyAuthorized')is False
            and packet.get('automaticReplayAllowed')is False and packet.get('budgetReset')is False
            and packet.get('newLoginAllowed')is False,'EXACT_UNAUTHORIZED_COMPLETE_PACKET_REQUIRED')
    require(set(packet_binding)=={'path','sha256'}and path(packet_binding['path'])
            and packet_binding['sha256']==digest(packet)and digest(inputs)==packet['verifiedInputsHash'],
            'EXACT_PACKET_AND_VERIFIED_INPUTS_BINDINGS_REQUIRED')
    for name in ('candidate','expectedRuntimeBindings','gatewayConfigBefore','retainedGatewayConfig','dedicatedOwnerKey','retainedClaims'):
        require(packet[name]==inputs[name],'PACKET_INPUTS_CONTENT_DRIFT')
    require(type(human_binding)is dict and all(type(human_binding.get(k))is str and human_binding[k]
            for k in ('sessionId','issuer','tenant','subject')),'EXPLICIT_HUMAN_SELECTION_REQUIRED')
    require(set(packet['frames'])==set(packet['expectedRuntimeBindings'])=={'ingestion','gateway'},'EXACT_TWO_APPLICATIONS_REQUIRED')
    stages=[]
    def add(name,kind,intent):
        require(kind in ('READ','EFFECT')and name not in [s['name']for s in stages],'UNIQUE_FINITE_STAGE_REQUIRED')
        stages.append({'name':name,'kind':kind,'intent':copy.deepcopy(intent),'intentHash':digest(intent)})
    add('VERIFY_CURRENT_GATES','READ',{'packetHash':packet_binding['sha256'],'requireCurrentHuman':True,
        'requireOwnerStrongEtagAndPayload':True,'requireFreshReadOnlyDatabaseAdmission':True,'requireLive82RouteMap':True})
    key=packet['dedicatedOwnerKey'];require(key['state']=='MISSING_AT_EXISTING_CUSTODIED_PARENT','EXCLUSIVE_MISSING_KEY_SCOPE_ONLY')
    key_path=path(key['path']);user=packet['candidate']['imageConfig'].get('User','')
    require(re.fullmatch('[1-9][0-9]{0,9}:[1-9][0-9]{0,9}',user),'EXPLICIT_QUALIFIED_NUMERIC_IMAGE_IDENTITY_REQUIRED')
    uid,gid=map(int,user.split(':'))
    require(uid<=4294967294 and gid<=4294967294,'BOUNDED_NATIVE_FILE_IDENTITY_REQUIRED')
    bind=packet['frames']['ingestion']['requestTemplate']['HostConfig'].get('Binds')or[]
    require(any(v.startswith(key_path+':')and v.endswith(':ro')for v in bind),'PUBLISHED_KEY_REFERENCE_MUST_MATCH_RUNTIME_BIND')
    add('CREATE_DEDICATED_KEY','EFFECT',{'path':key_path,'randomBytes':32,'encoding':'hex-ascii','fileBytes':64,
        'uid':uid,'gid':gid,'mode':0o400,'createExclusive':True,'overwriteAllowed':False,'publicValueOrHashAllowed':False})
    candidate=packet['candidate'];archive=candidate['nativeArchiveBinding']
    require(hashed(archive['sha256'])and re.fullmatch('sha256:[0-9a-f]{64}',candidate['nativeImageId'])
            and re.fullmatch('sha256:[0-9a-f]{64}',candidate['configurationImageId']),'EXACT_AUTHENTICATED_NATIVE_IMAGE_REQUIRED')
    add('IMPORT_INGESTION_IMAGE','EFFECT',{'archive':archive,'nativeImageId':candidate['nativeImageId'],
        'configurationImageId':candidate['configurationImageId'],'imageConfigHash':digest(candidate['imageConfig']),
        'rootfs':candidate['rootfs'],'repositoryTagWritesAllowed':False})
    for module in ('ingestion','gateway'):
        frame=packet['frames'][module];old=packet['expectedRuntimeBindings'][module];request=frame['requestTemplate']
        require(frame['module']==module and frame['targetApplyAuthorized']is False and frame['runtimeAuthorityIssued']is False
                and frame['resolveGatewaySecretAfterNativeAuthorityRequired']==(module=='gateway')
                and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',frame['name'])
                and re.fullmatch('[0-9a-f]{64}',old['containerId']),'EXACT_UNAUTHORIZED_FRAME_AND_RETAINED_IDENTITY_REQUIRED')
        require(request['HostConfig']['RestartPolicy']=={'Name':'no','MaximumRetryCount':0},'CREATE_WITH_RESTART_DISABLED_REQUIRED')
        if module=='ingestion':require(request['Image']==candidate['nativeImageId'],'EXACT_INGESTION_IMAGE_REQUIRED')
        else:
            require(request['Image']==old['imageId']and 'OUF_INGESTION_READ_OWNER_KEY=@ouf-secret-reference:ingestionReadOwnerKey'in request['Env'],
                    'UNCHANGED_GATEWAY_IMAGE_AND_UNRESOLVED_REFERENCE_REQUIRED')
        endpoints=request['NetworkingConfig']['EndpointsConfig']
        require(type(endpoints)is dict and 1<=len(endpoints)<=8 and len({e['NetworkID']for e in endpoints.values()})==len(endpoints),
                'BOUNDED_DISTINCT_PROFILE_ENDPOINTS_REQUIRED')
        add(module+'.DISABLE_OLD_RESTART','EFFECT',{'oldContainerId':old['containerId'],'restartPolicy':{'Name':'no','MaximumRetryCount':0}})
        add(module+'.STOP_OLD','EFFECT',{'oldContainerId':old['containerId'],'timeoutSeconds':10})
        for network in sorted(endpoints):
            e=endpoints[network];require(re.fullmatch('[0-9a-f]{64}',e['NetworkID'])and type(e.get('MacAddress'))is str,
                                        'EXPLICIT_PROFILE_NETWORK_AND_MAC_REQUIRED')
            add(module+'.DETACH_'+e['NetworkID'],'EFFECT',{'oldContainerId':old['containerId'],'networkName':network,'networkId':e['NetworkID']})
        retired=frame['name']+'-retained-'+digest({'packet':packet_binding['sha256'],'module':module})[:12]
        require(len(retired)<=255,'BOUNDED_RETAINED_CONTAINER_NAME_REQUIRED')
        add(module+'.RENAME_OLD','EFFECT',{'oldContainerId':old['containerId'],'retainedName':retired})
        add(module+'.CREATE_REPLACEMENT','EFFECT',{'name':frame['name'],'requestTemplate':request,
            'resolveSecretOnlyAfterCurrentAuthority':module=='gateway','sameGeneratedKeyFileRequired':module=='gateway'})
        add(module+'.START_REPLACEMENT','EFFECT',{'name':frame['name'],'requestHash':digest(request)})
        add(module+'.READINESS','READ',{'name':frame['name'],'requestHash':digest(request),'policy':READINESS})
        if module=='gateway':add('REBIND_GATEWAY_TRANSPORT','READ',{'newRuntimeRequired':True,
            'configBinding':packet['retainedGatewayConfig'],'oldNamespaceReuseAllowed':False,'requireCurrentOwnerAndDatabaseAdmission':True})
    routes=packet['routeDraft'];before,after=routes['beforeRoutes'],routes['afterRoutes']
    require(type(before)is dict and type(after)is dict and len(before)==len(after)==82 and set(before)==set(after)
            and routes['retainedOtherRoutes']==80 and routes['maximumPutRequests']==2,'EXACT_RETAINED82_ROUTE_DRAFT_REQUIRED')
    changed=sorted(k for k in before if before[k]!=after[k])
    require(set(changed)=={'mcp-ingestion-status','mcp-ingestion-history'},'EXACT_TWO_INGESTION_FUNCTION_CHANGES_REQUIRED')
    add('VERIFY_REBOUND_ROUTE_MAP','READ',{'beforeRoutesHash':digest(before),'routeCount':82,'unchangedRouteCount':80})
    for route in changed:
        add('PUT_ROUTE.'+route,'EFFECT',{'routeId':route,'expectedBeforeHash':digest(before[route]),'value':after[route],
            'maximumPutAttempts':1,'requireGenerationBoundTransport':True})
        add('READ_ROUTE.'+route,'READ',{'routeId':route,'expectedAfterHash':digest(after[route]),'requireCompleteMapAnd80Unchanged':True})
    add('VERIFY_FINAL','READ',{'afterRoutesHash':digest(after),'retainedOtherRoutes':80,'bothRuntimeReadinessRequired':True,
        'requireFreshReadOnlyDatabaseAdmission':True,'requireCurrentHumanAndOwner7':True,'acceptanceGranted':False})
    for module in ('ingestion','gateway'):
        add(module+'.RESTORE_RESTART','EFFECT',{'name':packet['frames'][module]['name'],
            'restartPolicy':packet['frames'][module]['restoreRestartPolicy']})
    add('VERIFY_RESTORED_FINAL','READ',{'bothRuntimeGenerationsAndRestartPoliciesRequired':True,'all82RoutesRequired':True})
    return {'schema':'ouf.ingestion-rollout-execution-review.v1','profile':PROFILE,'packetBinding':copy.deepcopy(packet_binding),
        'verifiedInputsHash':digest(inputs),'executionContext':path(execution_context),'humanBinding':copy.deepcopy(human_binding),
        'logicalOperationRef':digest({'profile':PROFILE,'packetHash':packet_binding['sha256']}),'stages':stages,
        'maximumExecutionSeconds':900,'maximumEffectAttemptsPerStage':1,'maximumGatewayPuts':2,
        'maximumSecretCreations':1,'maximumImageImports':1,'readinessPolicy':copy.deepcopy(READINESS),
        **{k:False for k in FORBIDDEN},'runtimeAuthorityIssued':False,'nativeProfilePublished':False,
        'completedTechnicalPhases':8,'functionalMilestonesProven':4,'notReleaseAcceptance':True}

def scope(review):
    require(type(review)is dict and review.get('schema')=='ouf.ingestion-rollout-execution-review.v1'
            and review.get('profile')==PROFILE and all(review.get(k)is False for k in FORBIDDEN)
            and review.get('runtimeAuthorityIssued')is False and review.get('maximumExecutionSeconds')==900
            and review.get('maximumEffectAttemptsPerStage')==1 and review.get('readinessPolicy')==READINESS
            and review.get('maximumGatewayPuts')==2 and review.get('maximumSecretCreations')==1
            and review.get('maximumImageImports')==1,'EXACT_FINITE_NON_REPLAY_REVIEW_REQUIRED')
    stages=review.get('stages');require(type(stages)is list and 25<=len(stages)<=48
            and len({s['name']for s in stages})==len(stages)
            and all(s['kind']in('READ','EFFECT')and s['intentHash']==digest(s['intent'])for s in stages),
            'EXACT_BOUNDED_ORDERED_INTENTS_REQUIRED')
    return {'profile':PROFILE,'reviewHash':digest(review),'packetHash':review['packetBinding']['sha256'],
        'logicalOperationRef':review['logicalOperationRef'],'executionContext':review['executionContext'],
        'humanBinding':copy.deepcopy(review['humanBinding']),'maximumExecutionSeconds':900,
        'maximumEffectAttemptsPerStage':1,'maximumReadAttempts':128,'maximumGatewayPuts':2,
        'stageIntentHashes':{s['name']:s['intentHash']for s in stages},**{k:False for k in FORBIDDEN}}
