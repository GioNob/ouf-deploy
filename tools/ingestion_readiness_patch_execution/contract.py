"""One-Ingestion finite patch contract. No I/O, issuance or old rollout replay."""
import copy
import hashlib
import json
from pathlib import PurePosixPath
import re
from tools.ingestion_rollout_preparation import frames

PROFILE = 'ouf.ingestion-readiness-patch-finite-execution.v1'
AUTHORITY_KEY = 'ingestionReadinessPatch'
READINESS = {'maximumAttempts': 128, 'maximumElapsedSeconds': 900, 'backoffSeconds': [5,15,60,300,900],
             'maximumJitterPercent': 20, 'respectRetryAfter': True, 'automaticRenewalAllowed': False}
FORBIDDEN = ('budgetReset','automaticReplayAllowed','automaticRollbackAllowed','newLoginAllowed','refreshAllowed',
             'databaseMigrationAllowed','ownerMutationAllowed','projectionPublicationAllowed','grantChangesAllowed',
             'sourceActivationAllowed','jobDispatchAllowed','nativeProfilePublicationAllowed')
class Denied(RuntimeError): pass
class Paused(RuntimeError): pass
class ReadTransient(RuntimeError):
    def __init__(self, retry_after_seconds=0):
        require(type(retry_after_seconds) in (int,float) and 0 <= retry_after_seconds < float('inf'),
                'FINITE_READ_TRANSIENT_RETRY_AFTER_REQUIRED')
        super().__init__('EXPLICIT_NATIVE_READ_TRANSIENT');self.retry_after_seconds=retry_after_seconds
def require(ok, code='PATCH_CONTRACT_DENIED'):
    if not ok: raise Denied(code)
def encoded(v): return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v): return hashlib.sha256(encoded(v)).hexdigest()
def hashed(v): return type(v) is str and re.fullmatch('[0-9a-f]{64}',v) is not None
def path(v):
    require(type(v) is str and v.startswith('/') and '\0' not in v and len(v)<=4096
            and '..' not in PurePosixPath(v).parts and str(PurePosixPath(v))==v,'EXACT_ABSOLUTE_PROFILE_PATH_REQUIRED')
    return v

def stages(bundle):
    frame=bundle['ingestionFrame'];request=frame['requestTemplate'];before=bundle['beforeIngestion']
    require(frame['module']=='ingestion' and frame['runtimeAuthorityIssued'] is frame['targetApplyAuthorized'] is False
            and frame['resolveGatewaySecretAfterNativeAuthorityRequired'] is False
            and request['HostConfig']['RestartPolicy']=={'Name':'no','MaximumRetryCount':0}
            and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',frame['name'])
            and before['Name']=='/'+frame['name'] and hashed(before['Id']), 'EXACT_ONE_INGESTION_FRAME_REQUIRED')
    candidate=bundle['candidate'];meta=candidate['Config'].get('Labels',{})
    require(candidate['Os']=='linux' and candidate['Architecture']=='amd64'
            and re.fullmatch('sha256:[0-9a-f]{64}',candidate['Id']) and request['Image']==candidate['Id']
            and candidate['Config']['User']=='10002:10002'
            and candidate['Config']['Entrypoint']==['java','-jar','/app/app.jar']
            and re.fullmatch('[0-9a-f]{40}',meta.get('org.opencontainers.image.revision',''))
            and request['Labels']['org.opencontainers.image.revision']==meta['org.opencontainers.image.revision'],
            'EXACT_QUALIFIED_PATCH_CANDIDATE_REQUIRED')
    expected=copy.deepcopy(before['Config']);expected.pop('MacAddress',None)
    if expected.get('Hostname')==before['Id'][:12]:expected['Hostname']=''
    expected['Image']=candidate['Id']
    expected['Labels']={**(expected.get('Labels')or{}),'org.opencontainers.image.revision':meta['org.opencontainers.image.revision']}
    host=copy.deepcopy(before['HostConfig']);restore=copy.deepcopy(host['RestartPolicy'])
    require(host.get('AutoRemove')is not True and host.get('Privileged')is not True
            and not host.get('Links')and not host.get('VolumesFrom')and not host.get('ContainerIDFile')
            and not str(host.get('PidMode','')).startswith('container:')
            and not str(host.get('IpcMode','')).startswith('container:'),'INDEPENDENT_RETAINED_INGESTION_REQUIRED')
    host['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
    expected.update(HostConfig=host,NetworkingConfig={'EndpointsConfig':frames.endpoints(before)})
    require(encoded(request)==encoded(expected) and encoded(frame['oldMounts'])==encoded(before['Mounts'])
            and encoded(frame['restoreRestartPolicy'])==encoded(restore)
            and restore in ({'Name':'no','MaximumRetryCount':0},{'Name':'unless-stopped','MaximumRetryCount':0}),
            'EXACT_CAPTURED_CONFIGURATION_AND_ENDPOINTS_REQUIRED')
    require(type(request.get('Cmd')) is list and request['Cmd'][-2:]==[
        '--spring.flyway.enabled=false','--ouf.ingestion.startup.schema-mode=VALIDATE_ONLY'],
        'RETAINED_VALIDATE_ONLY_STARTUP_REQUIRED')
    endpoints=request['NetworkingConfig']['EndpointsConfig']
    require(type(endpoints) is dict and 1<=len(endpoints)<=8
            and len({e['NetworkID'] for e in endpoints.values()})==len(endpoints)
            and all(hashed(e['NetworkID']) for e in endpoints.values()),'CLOSED_PATCH_NETWORKS_REQUIRED')
    source=bundle['finiteIntentContract'];original=source['stages'];result=[]
    expected=['VERIFY_CURRENT_GATES','IMPORT_INGESTION_IMAGE','ingestion.DISABLE_OLD_RESTART','ingestion.STOP_OLD']
    expected+=['ingestion.DETACH_NETWORK.'+str(i) for i in range(1,len(endpoints)+1)]
    expected+=['ingestion.RENAME_OLD','ingestion.CREATE_REPLACEMENT','ingestion.START_REPLACEMENT',
               'ingestion.READINESS','VERIFY_FINAL','ingestion.RESTORE_RESTART','VERIFY_RESTORED_FINAL']
    require([s['name'] for s in original]==expected and all(s['intentHash']==digest(s['intent']) for s in original),
            'EXACT_PREPARED_PATCH_SEQUENCE_REQUIRED')
    for index,s in enumerate(original):
        name=s['name'];intent=copy.deepcopy(s['intent'])
        if name.startswith('ingestion.DETACH_NETWORK.'):
            network,endpoint=list(endpoints.items())[index-4]
            require(intent=={'oldContainerId':before['Id'],'networkId':endpoint['NetworkID'],'force':False},
                    'EXACT_PREPARED_DETACH_INTENT_REQUIRED')
            name='ingestion.DETACH_'+endpoint['NetworkID']
        require(s['kind']==('READ' if name in ('VERIFY_CURRENT_GATES','ingestion.READINESS','VERIFY_FINAL',
                                              'VERIFY_RESTORED_FINAL') else 'EFFECT'),'CLOSED_PATCH_STAGE_KIND_REQUIRED')
        result.append({'name':name,'kind':s['kind'],'intent':intent,'intentHash':digest(intent)})
    intents={s['name']:s['intent'] for s in result}
    require(intents['ingestion.CREATE_REPLACEMENT']=={'name':frame['name'],'requestTemplate':request}
            and intents['ingestion.DISABLE_OLD_RESTART']=={'oldContainerId':before['Id'],'restartPolicy':{'Name':'no','MaximumRetryCount':0}}
            and intents['ingestion.STOP_OLD']=={'oldContainerId':before['Id'],'timeoutSeconds':30}
            and intents['ingestion.START_REPLACEMENT']=={'createdIdMustComeFromDurableCreateResponse':True}
            and intents['ingestion.RESTORE_RESTART']=={'createdIdMustComeFromDurableCreateResponse':True,
                                                      'restartPolicy':frame['restoreRestartPolicy']},
            'EXACT_PREPARED_LIFECYCLE_INTENTS_REQUIRED')
    logical=digest({'operation':'INGESTION_READINESS_WORKLOAD_PATCH','oldContainerId':before['Id'],
                    'candidateImageId':candidate['Id']})
    require(source['logicalOperationRef']==logical and source['maximumGatewayWrites']==source['maximumSecretCreations']==0
            and intents['ingestion.RENAME_OLD']=={'oldContainerId':before['Id'],
                'retainedName':frame['name']+'-retained-'+logical[:12]},'SAME_LOGICAL_PATCH_AND_RETAINED_PREDECESSOR_REQUIRED')
    return result

def scope(review):
    require(all(type(review.get(k)) is int for k in ('maximumExecutionSeconds','maximumEffectAttemptsPerStage',
            'maximumGatewayPuts','maximumSecretCreations','maximumImageImports')), 'TYPED_PATCH_LIMITS_REQUIRED')
    require(type(review) is dict and review.get('schema')=='ouf.ingestion-readiness-patch-execution-review.v1'
            and review.get('profile')==PROFILE and all(review.get(k) is False for k in FORBIDDEN)
            and review.get('runtimeAuthorityIssued') is False and review.get('maximumExecutionSeconds')==900
            and review.get('maximumEffectAttemptsPerStage')==1 and review.get('maximumGatewayPuts')==0
            and review.get('maximumSecretCreations')==0 and review.get('maximumImageImports')==1
            and encoded(review.get('readinessPolicy'))==encoded(READINESS),'EXACT_ONE_INGESTION_FINITE_REVIEW_REQUIRED')
    b=review['preparedInputs'];require(digest(b)==review['preparedInputsHash'],'EXACT_PREPARED_NATIVE_INPUTS_REQUIRED')
    wanted=stages(b);require(encoded(review['stages'])==encoded(wanted),'CLOSED_PATCH_INTENT_SEQUENCE_REQUIRED')
    logical=b['finiteIntentContract']['logicalOperationRef']
    require(review['logicalOperationRef']==logical and path(review['executionContext'])
            and all(type(review['humanBinding'].get(k)) is str and review['humanBinding'][k]
                    for k in ('sessionId','issuer','tenant','subject')),'EXACT_PATCH_CONTEXT_AND_HUMAN_REQUIRED')
    return {'profile':PROFILE,'reviewHash':digest(review),'packetHash':review['packetBinding']['sha256'],
            'logicalOperationRef':logical,'executionContext':review['executionContext'],
            'humanBinding':copy.deepcopy(review['humanBinding']),'maximumExecutionSeconds':900,
            'maximumEffectAttemptsPerStage':1,'maximumReadAttempts':128,'maximumGatewayPuts':0,
            'stageIntentHashes':{s['name']:s['intentHash'] for s in wanted},**{k:False for k in FORBIDDEN}}
