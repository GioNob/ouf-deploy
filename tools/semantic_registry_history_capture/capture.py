"""Offline historical lineage capture; never executes or renews old authority."""
import hashlib,json,os,re,signal,stat,sys,tempfile
from pathlib import Path

SCHEMA='ouf.semantic-registry-history-capture-result.v1'
CASE_SCHEMA='ouf.semantic-registry-history-capture-case.v1'
PHASES=('STOP_REVOKE_OLD_LEASE','QUIESCE_PRODUCERS','FENCED_BACKUP','RELEASE_OLD_ENDPOINT',
        'CREATE_REPLACEMENT','STAGE_PAUSED_REPLACEMENT','ATTEST_NEW_OCI_PEER',
        'ADMIT_MIGRATION','START_REPLACEMENT','VERIFY_APPLICATION','RELEASE_PRODUCERS')
GATES=('EXACT_HISTORICAL_OWNER_AND_CLAIM_CHAIN','COMPLETE_CURRENT_OCI_ROOTFS_AND_MOUNT_CUSTODY',
       'NEW_PROCESS_GENERATION_AND_ATTESTATION','CURRENT_DATABASE_OWNER_AND_STARTUP_ADMISSION',
       'CURRENT_TOKEN_OWNER_WITHOUT_UNREVIEWED_GRANTS','CURRENT_GATEWAY_ROUTE_MAP_AND_TARGET_BINDING',
       'QUALIFIED_GOVERNED_RECOVERY_EXECUTOR','FRESH_EXACT_HUMAN_RUNTIME_AUTHORITY')

def hashed(value):return type(value) is str and re.fullmatch('[a-f0-9]{64}',value) is not None

def exact_path(path,parent):
    require(type(path) is str and Path(path).is_absolute() and '..' not in Path(path).parts
            and Path(path).is_relative_to(parent) and str(Path(path))==path,'EXACT_OWNED_METADATA_PATH_REQUIRED')
    return path

def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()

def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()

class Stop(Exception):
    pass

def require(ok, code):
    if not ok:
        raise Stop(code)

def unique(items):
    result = {}
    for key, value in items:
        require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result

def decode(raw):
    return json.loads(raw, object_pairs_hook=unique)

def private_json(path):
    p = Path(path)
    require(p.is_absolute() and '..' not in p.parts and str(p.resolve()) == str(p),
            'EXACT_PRIVATE_PATH_REQUIRED')
    for parent in p.parents:
        info=parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,
                'ROOT_CONTROLLED_METADATA_ANCESTRY_REQUIRED')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0
                and not before.st_mode & 0o022 and 0 < before.st_size <= 8_388_608,
                'ROOT_OWNED_BOUNDED_METADATA_REQUIRED')
        raw = bytearray()
        while len(raw) <= before.st_size:
            block = os.read(fd, min(65_536, before.st_size + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode,
                              s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(len(raw) == before.st_size
                and identity(before) == identity(os.fstat(fd)) == identity(p.lstat()),
                'PRIVATE_METADATA_CHANGED')
        return decode(raw), bytes(raw)
    finally:
        os.close(fd)

def stopped(error):
    reason = str(error) if type(error) is Stop else 'DIAGNOSTIC_UNCONFIRMED_' + type(error).__name__
    if re.fullmatch('[A-Z][A-Z0-9_]{0,127}', reason) is None:
        reason = 'DIAGNOSTIC_UNCONFIRMED'
    return {'schema': SCHEMA, 'status': 'STOP_RECONCILE', 'reasonCode': reason,
            'readOnlyRuntime': True, 'runtimeEffectsDispatched': 0, 'activationResubmitted': False,
            'automaticReplayAllowed': False, 'budgetReset': False, 'rootCauseEstablished': False}

def publish(case,proposal):
    parent=Path(case['privateParent'])
    for path in [parent,*parent.parents]:
        info=path.lstat()
        require(path.resolve()==path and stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,
                'ROOT_CONTROLLED_PROPOSAL_PARENT_REQUIRED')
    # Only a new private proposal directory/file; no journal/claim/runtime mutation.
    root=Path(tempfile.mkdtemp(prefix='semantic-registry-history-capture-',dir=parent))
    os.chmod(root,0o700)
    parent_fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(parent_fd)
    finally:os.close(parent_fd)
    path=root/'inputs.json';raw=encoded(proposal)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        remaining=memoryview(raw)
        while remaining:
            count=os.write(fd,remaining);require(count>0,'PROPOSAL_WRITE_INCOMPLETE');remaining=remaining[count:]
        os.fsync(fd);os.fchmod(fd,0o400);os.fsync(fd)
    finally:os.close(fd)
    require(private_json(str(path))[1]==raw,'PRIVATE_PROPOSAL_READBACK_FAILED')
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
    return str(path),digest(proposal)


def candidate_contract(proposal,history_hash,predecessor_incident_ref):
    require(proposal['requiredGates']==list(GATES) and proposal['unresolvedGateCount']==8,
            'EXACT_UNRESOLVED_PROPOSAL_GATES_REQUIRED')
    require(hashed(predecessor_incident_ref),'EXACT_PREDECESSOR_INCIDENT_LINEAGE_REQUIRED')
    logical=digest({'operation':'REGISTRY_FRESH_GATED_GENERATION_RECOVERY',
                    'registryId':proposal['registry']['containerId'],'proposalHash':digest(proposal),
                    'historyHash':history_hash})
    order=[('VERIFY_CURRENT_GATES','READ'),('START_NEW_WAIT_GATE','EFFECT'),
           ('VERIFY_NEW_WAIT_GENERATION','READ'),('PAUSE_NEW_WAIT_GATE','EFFECT'),
           ('VERIFY_PAUSED_OCI_AND_MOUNTS','READ'),('ATTEST_NEW_GENERATION','EFFECT'),
           ('VERIFY_CURRENT_ADMISSION','READ'),('UNPAUSE_ATTESTED_GENERATION','EFFECT'),
           ('VERIFY_UNPAUSED_SAME_GATE','READ'),('RELEASE_SAME_GENERATION_SIGUSR1','EFFECT'),
           ('VERIFY_APPLICATION_READINESS','READ'),('VERIFY_FINAL','READ')]
    stages=[]
    for name,kind in order:
        intent={'logicalOperationRef':logical,'stage':name,'registryId':proposal['registry']['containerId'],
                'proposalHash':digest(proposal),'historicalChainHash':history_hash,
                'newGenerationMustComeFromDurableStartEvidence':name not in ('VERIFY_CURRENT_GATES','START_NEW_WAIT_GATE')}
        stages.append({'name':name,'kind':kind,'maximumEffectAttempts':1 if kind=='EFFECT' else 0,
                       'intent':intent,'intentHash':digest(intent)})
    return {'schema':'ouf.semantic-registry-gated-recovery-candidate-contract.v1',
            'logicalOperationRef':logical,'stages':stages,'remainingGates':list(GATES[1:]),
            'retainedPredecessorIncidentRef':predecessor_incident_ref,
            'maximumRuntimeSecondsProposed':900,'maximumReadAttemptsProposed':128,
            'newRuntimeBudgetGranted':False,'newOAuthBudgetProposed':False,
            'persistentRecoveryIncidentRequired':True,'cumulativeOAuthHistoryMustBePreserved':True,
            'incidentCauseEquivalenceEstablished':False,'existingClaimsRemainConsumed':True,
            'oldAttestationOrGenerationAdoptionAllowed':False,'effectRetryAllowed':False,
            'claimedEffectReadOnlyReconciliationRequired':True,'providerRecoveryAllowed':False,
            'gatewayWritesAllowed':False,'databaseMigrationAllowed':False,
            'automaticAuthenticationAllowed':False,'sourceActivationAllowed':False,
            'nativeExecutorQualified':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
            'automaticReplayAllowed':False,'budgetReset':False}


def capture(case):
    require(type(case) is dict and set(case)=={'schema','privateParent','proposalPath','proposalHash',
            'historicalContext','historicalReviewHash','historicalAuthorityHash','historicalSourceCommit','historicalUnit'}
            and case['schema']==CASE_SCHEMA and case['privateParent']=='/etc/ouf/deploy-snapshots'
            and all(hashed(case[k]) for k in ('proposalHash','historicalReviewHash','historicalAuthorityHash')),
            'EXACT_HISTORY_CAPTURE_CASE_REQUIRED')
    saved={}
    def read(path,expected=None):
        exact_path(path,case['privateParent']);value,raw=private_json(path)
        require(expected is None or hashlib.sha256(raw).hexdigest()==expected,'HISTORICAL_METADATA_HASH_CHANGED')
        require(path not in saved or saved[path]==raw,'HISTORICAL_METADATA_CHANGED_DURING_CAPTURE')
        saved[path]=raw;require(len(saved)<=16,'HISTORICAL_READ_SET_BOUND');return value
    proposal=read(case['proposalPath'],case['proposalHash'])
    require(digest(proposal)==case['proposalHash'] and proposal['schema']=='ouf.semantic-registry-blocked-recovery-proposal.v1'
            and proposal['kind']=='REVIEW_INPUTS_ONLY_NOT_EXECUTABLE_AUTHORITY'
            and all(proposal[k] is False for k in ('runtimeAuthorityIssued','targetApplyAuthorized','nativeExecutorQualified',
                    'providerRecoveryProposed','newOAuthBudgetProposed','newHumanWindowProposed','automaticReplayAllowed','budgetReset')),
            'EXACT_BLOCKED_UNAUTHORIZED_PROPOSAL_REQUIRED')
    context=case['historicalContext'];exact_path(context,case['privateParent'])
    review=read(context+'/review.json',case['historicalReviewHash'])
    authority=read(context+'/authority.json',case['historicalAuthorityHash'])
    require(review['sourceClosure']['declaration']['sourceCommit']==case['historicalSourceCommit']
            and all(authority.get(k)==v for k,v in review['scopes'].items()),'RETAINED_AUTHORITY_SCOPE_BINDING_CHANGED')
    process=review['scopes']['finiteActionProcess']
    require(process['unit']==case['historicalUnit'] and process['authorityDirectory']==context,
            'EXACT_RETAINED_ACTION_PROCESS_REQUIRED')
    operation=process['logicalOperationHash']
    require(hashed(operation) and context==case['privateParent']+'/chatbot-file-cohort-signed-'+operation
            and process['unit']=='ouf-file-cohort-'+operation[:32]+'.service', 'EXACT_HISTORICAL_PROCESS_OPERATION_REQUIRED')
    claim=read(case['privateParent']+'/chatbot-file-cohort-process-'+operation+'.claim.json')
    require(type(claim.get('runtimeMaxSeconds')) is int and 1<=claim['runtimeMaxSeconds']<=process['maximumElapsedSeconds']<=3600
            and claim=={'schema':'ouf.chatbot-file-cohort-process-claim.v1','planHash':digest(process),
                'authorityHash':case['historicalAuthorityHash'],'state':'START_CONSUMED_OUTCOME_UNPROVEN',
                'automaticReplayAllowed':False,'runtimeMaxSeconds':claim['runtimeMaxSeconds']},
            'EXACT_CONSUMED_HISTORICAL_PROCESS_CLAIM_REQUIRED')
    binding=process['bundle'];bundle=read(binding['path'],binding['sha256']);prepared=bundle['prepared']
    require(bundle['declaration']==review['sourceClosure']['declaration']
            and digest(prepared)==review['privateInputHashes']['preparedInputs'],'EXACT_RETAINED_PREPARED_BUNDLE_REQUIRED')
    registry=prepared['registry'];scope=review['scopes']['applicationRegistryCutover']
    require(registry['schema']=='ouf.semantic-file-only-installation-inputs.v1'
            and scope['creationRequestHash']==digest(registry['creationRequest'])
            and scope['preparedHash']==digest(registry)
            and set(registry['intents'])==set(PHASES)
            and scope['phaseIntentHashes']=={p:digest(registry['intents'][p]) for p in PHASES},
            'EXACT_HISTORICAL_REGISTRY_SCOPE_REQUIRED')
    paths=registry['directoryPlan']
    require(paths['transition']==paths['root']+'/transition' and paths['evidence']==paths['root']+'/evidence',
            'EXACT_HISTORICAL_REGISTRY_DIRECTORY_PLAN_REQUIRED')
    transition=read(paths['transition']+'/recovery.json')
    n=transition['nextPhase'];effects=transition['effects']
    require(transition['schema']=='ouf.semantic-cutover-journal.v2'
            and transition['deploymentProfile']=='ouf.semantic-file-only-native-proposal.v1'
            and transition['creationRequestHash']==scope['creationRequestHash']
            and type(n) is int and 10<=n<=11 and len(effects)==n
            and transition['state']==('COMPLETED' if n==11 else 'READY')
            and [e['phase'] for e in effects]==list(PHASES[:n])
            and all(e['state']=='APPLIED' and hashed(e['nativeEvidenceHash']) and hashed(e['intentHash'])
                    and hashed(e['authorityEvidenceHash']) for e in effects)
            and transition['automaticReplayAllowed'] is False and transition['preMigrationRestoreAllowed'] is False
            and transition['databaseMayHaveChanged'] is True and transition['applicationWritesMayHaveOccurred'] is True,
            'EXACT_COMPLETED_HISTORICAL_REGISTRY_PREFIX_REQUIRED')
    context_fields=('creationRequestHash','predecessorHistoryHash','predecessorIncidentRef','transitionAuthorityEvidenceHash',
                    'deploymentProfile','executionProfileHash')
    require(all(hashed(transition[k]) for k in context_fields if k!='deploymentProfile')
            and transition['contextHash']==digest({k:transition[k] for k in context_fields}), 'HISTORICAL_TRANSITION_CONTEXT_CHANGED')
    bridge=scope.get('postGrantRecovery')
    if bridge is not None:
        require(bridge.get('appliedPrefixPhaseCount')==10 and bridge.get('registryPhaseReplayAllowed') is False
                and bridge.get('appliedPrefixHash')==digest(effects[:10]),'EXACT_RETAINED_PREFIX_BRIDGE_REQUIRED')
    else:
        require(all(e['intentHash']==scope['phaseIntentHashes'][e['phase']] for e in effects[:10]),
                'HISTORICAL_PHASE_INTENT_CHANGED')
    payloads={}
    for phase in ('CREATE_REPLACEMENT','ATTEST_NEW_OCI_PEER','START_REPLACEMENT','VERIFY_APPLICATION'):
        effect=next(e for e in effects if e['phase']==phase)
        payloads[phase]=read(paths['evidence']+'/'+phase+'.json',effect['nativeEvidenceHash'])
    created=payloads['CREATE_REPLACEMENT'];released=payloads['START_REPLACEMENT'];verified=payloads['VERIFY_APPLICATION']
    current=proposal['registry'];request=registry['creationRequest'];runtime=released['runtimeBinding']
    require(created['Id']==runtime['containerId']==current['containerId'] and created['Image']==runtime['imageId']==current['imageId']==request['Image']
            and verified['runtimeBinding']==runtime and verified['creationRequestHash']==scope['creationRequestHash']
            and verified['readinessScopeHash']==digest(registry['readinessScope']), 'EXACT_HISTORICAL_CONTAINER_AND_VERIFICATION_REQUIRED')
    # The old network allocation/PID are historical; never adopt them for recovery.
    require(current['configHash']==runtime['configHash'], 'CURRENT_PROPOSAL_CONFIG_DIFFERS_FROM_HISTORICAL_VERIFIED_CONFIG')
    historical={'reviewHash':case['historicalReviewHash'],'authorityHash':case['historicalAuthorityHash'],
        'finiteProcessClaimHash':digest(claim),'finiteProcessClaimRemainsConsumed':True,
        'preparedBundleHash':binding['sha256'],'registryScopeHash':digest(scope),
        'transitionHash':digest(transition),'appliedPrefixHash':digest(effects[:10]),
        'predecessorIncidentRef':transition['predecessorIncidentRef'],
        'nativeEvidenceHashes':{p:digest(v) for p,v in payloads.items()},
        'historicalDeploymentChainBound':True,'historicalAuthorityReactivated':False,
        'proposalConfigHashMatchesHistoricalVerified':True,'oldProcessGenerationReusable':False}
    inputs={'schema':'ouf.semantic-registry-recovery-private-historical-inputs.v1',
        'kind':'OFFLINE_COMPOSITION_INPUTS_NOT_EXECUTABLE_AUTHORITY','proposal':proposal,
        'proposalHash':case['proposalHash'],'historicalBinding':historical,
        'registryInputs':registry,'historicalSourceClosure':review['sourceClosure'],
        'historicalFiniteProcessClaim':claim,
        'historicalTransition':transition,'historicalNativeEvidence':payloads,
        'candidateContract':candidate_contract(proposal,digest(historical),transition['predecessorIncidentRef']),
        'historicalGateReconciled':GATES[0],'unresolvedGateCount':7,
        'nativeExecutorQualified':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
        'currentRegistryIdentityEstablished':False,'oldAuthorityIsCurrent':False,
        'oauthRequests':0,'engineGets':0,'databaseCalls':0,'credentialFilesOpened':0,
        'providerRecoveryProposed':False,'automaticReplayAllowed':False,'budgetReset':False,
        'releaseAcceptance':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
    require(len(encoded(inputs))<=8_388_608,'PRIVATE_HISTORY_INPUTS_SIZE_BOUND')
    for path,raw in saved.items():require(private_json(path)[1]==raw,'HISTORICAL_INPUT_CHANGED_AFTER_CAPTURE')
    return inputs,len(saved)*2


if __name__=='__main__':
    try:
        require(os.geteuid()==0 and sys.flags.isolated,'ROOT_ISOLATED_CAPTURE_REQUIRED')
        signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(Stop('OFFLINE_CAPTURE_DEADLINE')));signal.alarm(35)
        require(len(sys.argv)==2,'ONE_CASE_FILE_REQUIRED')
        with open(sys.argv[1],'rb') as source:raw=source.read(8193)
        require(len(raw)<=8192,'BOUNDED_CASE_REQUIRED');case=decode(raw)
        inputs,reads=capture(case);path,sha=publish(case,inputs)
        print(json.dumps({'schema':SCHEMA,'status':'HISTORICAL_REGISTRY_INPUTS_RECONCILED_NO_RUNTIME_AUTHORITY',
            'complete':True,'privateInputsPath':path,'privateInputsHash':sha,'metadataReads':reads,
            'historicalDeploymentChainBound':True,'proposalConfigHashMatchesHistoricalVerified':True,
            'unresolvedGateCount':7,'nativeExecutorQualified':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
            'engineGets':0,'databaseCalls':0,'oauthRequests':0,'credentialFilesOpened':0,'runtimeEffectsDispatched':0,
            'activationResubmitted':False,'providerRecoveryProposed':False,'automaticReplayAllowed':False,
            'budgetReset':False,'releaseAcceptance':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4},sort_keys=True),flush=True)
    except Exception as error:
        print(json.dumps(stopped(error),sort_keys=True),flush=True);sys.exit(1)
