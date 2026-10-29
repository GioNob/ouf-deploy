"""Read-only recovery source composition; no runtime execution interface."""
import hashlib,http.client,json,os,re,signal,socket,stat,sys,tempfile
from pathlib import Path

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

class BaseEngine:
    def check(self):
        p = Path(self.binding['socketPath'])
        require(p.is_absolute() and '..' not in p.parts and str(p.resolve()) == str(p),
                'EXACT_ENGINE_PATH_REQUIRED')
        s = p.lstat()
        require(stat.S_ISSOCK(s.st_mode) and s.st_uid == 0
                and stat.S_IMODE(s.st_mode) in (0o600, 0o660)
                and [s.st_dev, s.st_ino, s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)]
                == self.binding['socketBinding'], 'ENGINE_BINDING_CHANGED')

    def get(self, path):
        require(path in self.paths and self.calls < MAX_GETS, 'CLOSED_SIX_GET_BUDGET')
        self.check()
        selected = self.binding['socketPath']

        class Connection(http.client.HTTPConnection):
            def connect(connection):
                connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.sock.settimeout(connection.timeout)
                connection.sock.connect(selected)

        connection = Connection('retained-engine', timeout=4)
        try:
            self.calls += 1
            connection.request('GET', path, headers={'Connection': 'close'})
            response = connection.getresponse()
            raw = response.read(MAX_BYTES + 1)
            require(len(raw) <= MAX_BYTES, 'LOG_OR_METADATA_LIMIT_REACHED')
            self.check()
            require(response.status == 200, 'ENGINE_GET_STATUS_' + str(response.status))
            return raw
        finally:
            connection.close()

    def inspect(self, cid):
        path = '/v1.44/containers/' + cid + '/json'
        require(path in self.inspects, 'EXACT_INSPECT_ID_REQUIRED')
        value = decode(self.get(path))
        require(value['Id'] == cid, 'EXACT_INSPECT_ID_REQUIRED')
        return value

def generation(actual, pin):
    s = actual['State']
    require(actual['Id'] == pin['containerId'] and s['Pid'] == pin['pid']
            and s['StartedAt'] == pin['startedAt'] and s['Running'] is True
            and not s.get('Paused') and not s.get('Restarting') and not s.get('Dead'),
            'GATEWAY_GENERATION_CHANGED')
    require(actual['Image'] == pin['imageId'] and all(digest(actual[field]) == pin[key]
            for field,key in [('Config','configHash'),('HostConfig','hostConfigHash'),
                              ('NetworkSettings','networkSettingsHash')]), 'GATEWAY_BINDING_CHANGED')

def stable_fields(actual):
    # Omit continuously changing health-check history; bind lifecycle/config/network.
    return {'Id': actual['Id'], 'Image': actual['Image'], 'Config': actual['Config'],
            'HostConfig':actual['HostConfig'], 'Mounts':actual['Mounts'],
            'NetworkSettings': actual['NetworkSettings'], 'RestartCount': actual['RestartCount'],
            'State': {key: actual['State'].get(key) for key in STATE_FIELDS}}

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
    root=Path(tempfile.mkdtemp(prefix='semantic-registry-recovery-composition-',dir=parent))
    os.chmod(root,0o700)
    parent_fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(parent_fd)
    finally:os.close(parent_fd)
    path=root/'composition.json';raw=encoded(proposal)
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

SCHEMA="ouf.semantic-registry-recovery-composition-result.v1"
MAX_GETS=6
MAX_BYTES=2097152
STATE_FIELDS=("Status","Running","Paused","Restarting","Dead","OOMKilled","Pid","ExitCode","Error","StartedAt","FinishedAt")

FIELDS=('User','Entrypoint','Cmd','Env','WorkingDir','Labels','Volumes','ExposedPorts','StopSignal','Healthcheck','Shell')

def manifest_bytes(audit):
    """Exact Docker schema2 descriptors, with unchanged config/layer bytes."""
    require(audit.get('imageId')=='sha256:'+audit['configSha256']
            and type(audit.get('configBytes')) is int and 0<audit['configBytes']<=2097152,
            'EXACT_CONFIGURATION_BYTE_IDENTITY_REQUIRED')
    descriptor=lambda media,digest,size:{'mediaType':media,'digest':digest,'size':size}
    layers=[]
    for row in audit['layers']:
        plain='sha256:'+row['blobSha256']==row['diffId']
        layers.append(descriptor('application/vnd.docker.image.rootfs.diff.tar'+('' if plain else '.gzip'),
            'sha256:'+row['blobSha256'],row['archiveBytes']))
    value={'schemaVersion':2,'mediaType':'application/vnd.docker.distribution.manifest.v2+json',
        'config':descriptor('application/vnd.docker.container.image.v1+json',audit['imageId'],audit['configBytes']),
        'layers':layers}
    # Descriptor order matches the image-spec encoding; no native metadata is
    # normalized or guessed. This exact byte string is included in the archive.
    return json.dumps(value,separators=(',',':'),allow_nan=False).encode()

def native_identity(audit):
    raw=manifest_bytes(audit)
    return {'profile':'ouf.config-and-native-manifest-identity.v1',
        'configurationImageId':audit['imageId'],'nativeImageId':'sha256:'+hashlib.sha256(raw).hexdigest(),
        'manifestBytes':len(raw),'platform':'linux/amd64'}

def runtime_image_id(audit):
    binding=audit.get('nativeIdentity')
    if binding is None:return audit['imageId']
    require(binding==native_identity(audit),'EXACT_NATIVE_MANIFEST_IDENTITY_REQUIRED')
    return binding['nativeImageId']

def loaded(audit,native):
    expected=runtime_image_id(audit)
    require(type(native) is dict and native.get('Id')==expected
            and native.get('Os')=='linux' and native.get('Architecture')=='amd64','NATIVE_IMAGE_IDENTITY_DRIFT')
    require(native.get('RootFS')=={'Type':'layers','Layers':[r['diffId'] for r in audit['layers']]},'NATIVE_ROOTFS_CUSTODY_DRIFT')
    require(type(native.get('Config')) is dict and all(native['Config'].get(k)==audit['imageConfig'].get(k) for k in FIELDS),'NATIVE_IMAGE_EXECUTION_CONFIG_DRIFT')
    return {'schema':'ouf.loaded-image-byte-custody.v1','imageId':expected,
            'sourceCommit':audit['sourceCommit'],'archiveSha256':audit['archiveSha256'],
            'rootfsLayerCount':len(audit['layers']),'nativeConfigProjectionHash':digest({k:native['Config'].get(k) for k in FIELDS}),
            'nativeRootfsHash':digest(native['RootFS']),'imageByteCustodyProven':True,
            'completeContainerOciProven':False,'transportClosureProven':False,'targetApplyAuthorized':False}

GATES=('EXACT_HISTORICAL_OWNER_AND_CLAIM_CHAIN','COMPLETE_CURRENT_OCI_ROOTFS_AND_MOUNT_CUSTODY',
       'NEW_PROCESS_GENERATION_AND_ATTESTATION','CURRENT_DATABASE_OWNER_AND_STARTUP_ADMISSION',
       'CURRENT_TOKEN_OWNER_WITHOUT_UNREVIEWED_GRANTS','CURRENT_GATEWAY_ROUTE_MAP_AND_TARGET_BINDING',
       'QUALIFIED_GOVERNED_RECOVERY_EXECUTOR','FRESH_EXACT_HUMAN_RUNTIME_AUTHORITY')

def hashed(value):return type(value) is str and re.fullmatch('[a-f0-9]{64}',value) is not None

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


def validate_case(case):
    require(type(case) is dict and set(case)=={'schema','privateParent','inputsPath','inputsHash',
            'proposalHash','sourceRef','componentPins'} and case['schema']=='ouf.semantic-registry-recovery-composition-case.v1'
            and case['privateParent']=='/etc/ouf/deploy-snapshots'
            and hashed(case['inputsHash']) and hashed(case['proposalHash'])
            and re.fullmatch('[a-f0-9]{40}',case['sourceRef']) is not None,
            'EXACT_COMPOSITION_CASE_REQUIRED')
    path=Path(case['inputsPath'])
    require(path.is_absolute() and '..' not in path.parts and str(path.parent.parent)==case['privateParent']
            and path.name=='inputs.json' and path.parent.name.startswith('semantic-registry-history-capture-'),
            'EXACT_RETAINED_INPUT_PATH_REQUIRED')
    components={
        'tools/semantic_application_cutover/gated_stage_adapter.py':'INCOMPATIBLE_CREATED_ONLY_REQUIRES_NEW_EXITED_GENERATION_ADAPTER',
        'tools/semantic_application_cutover/gated_release_adapter.py':'INCOMPATIBLE_COMBINED_UNPAUSE_SIGNAL_REQUIRES_SPLIT_CLAIMS',
        'tools/semantic_application_cutover/file_only_node_owner.py':'REQUIRES_NEW_TYPED_SCOPE_AND_FRESH_PAUSED_BINDING',
        'tools/semantic_application_cutover/gated_process_observation.py':'OBSERVATION_PRIMITIVE_ONLY_NO_OLD_GENERATION_ADOPTION',
        'tools/ingestion_readiness_patch_execution/native.py':'MODULE_SPECIFIC_EXECUTOR_NOT_DIRECTLY_REUSABLE',
        'tools/semantic_application_cutover/image_custody.py':'PURE_LOADED_IMAGE_PREDICATES_ONLY'}
    pins=case['componentPins']
    require(type(pins) is list and len(pins)==len(components)
            and {r['path'] for r in pins}==set(components)
            and all(set(r)=={'path','gitBlobSha'} and re.fullmatch('[a-f0-9]{40}',r['gitBlobSha']) for r in pins),
            'EXACT_COMPONENT_SOURCE_PINS_REQUIRED')
    return components,pins


def compile_composition(case,inputs):
    components,pins=validate_case(case)
    require(digest(inputs)==case['inputsHash'] and inputs['schema']=='ouf.semantic-registry-recovery-private-historical-inputs.v1'
            and inputs['kind']=='OFFLINE_COMPOSITION_INPUTS_NOT_EXECUTABLE_AUTHORITY'
            and inputs['historicalGateReconciled']==GATES[0] and inputs['unresolvedGateCount']==7,
            'EXACT_RECONCILED_HISTORY_INPUTS_REQUIRED')
    require(all(inputs[k] is False for k in ('nativeExecutorQualified','runtimeAuthorityIssued','targetApplyAuthorized',
            'currentRegistryIdentityEstablished','oldAuthorityIsCurrent','providerRecoveryProposed',
            'automaticReplayAllowed','budgetReset','releaseAcceptance'))
            and all(type(inputs[k]) is int and inputs[k]==0 for k in ('oauthRequests','engineGets','databaseCalls','credentialFilesOpened')),
            'HISTORY_ONLY_NO_AUTHORITY_REQUIRED')
    proposal=inputs['proposal'];history=inputs['historicalBinding']
    require(proposal['schema']=='ouf.semantic-registry-blocked-recovery-proposal.v1'
            and digest(proposal)==case['proposalHash']==inputs['proposalHash']
            and all(proposal[k] is False for k in ('nativeExecutorQualified','runtimeAuthorityIssued',
                    'targetApplyAuthorized','providerRecoveryProposed','automaticReplayAllowed','budgetReset')),
            'EXACT_BLOCKED_PROPOSAL_REQUIRED')
    require(history['historicalDeploymentChainBound'] is True
            and history['proposalConfigHashMatchesHistoricalVerified'] is True
            and history['finiteProcessClaimRemainsConsumed'] is True
            and history['historicalAuthorityReactivated'] is False and history['oldProcessGenerationReusable'] is False,
            'HISTORICAL_GENERATION_NOT_CURRENT_REQUIRED')
    expected=candidate_contract(proposal,digest(history),inputs['historicalTransition']['predecessorIncidentRef'])
    require(inputs['candidateContract']==expected,'CANDIDATE_CONTRACT_CHANGED')
    return {'schema':'ouf.semantic-registry-recovery-source-composition.v1',
            'kind':'BLOCKED_SOURCE_DESCRIPTOR_NOT_EXECUTOR_OR_AUTHORITY',
            'sourceRef':case['sourceRef'],'inputsHash':case['inputsHash'],'proposalHash':case['proposalHash'],
            'components':[dict(r,compatibility=components[r['path']]) for r in pins],
            'candidateContractHash':digest(expected),'remainingGates':list(GATES[1:]),'unresolvedGateCount':7,
            'nativeExecutorQualified':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
            'oldGenerationAdoptionAllowed':False,'providerRecoveryProposed':False,
            'automaticReplayAllowed':False,'budgetReset':False}


class Engine(BaseEngine):
    def __init__(self,binding,ids,image_id):
        require(len(ids)==len(set(ids))==2 and all(type(cid) is str and re.fullmatch('[a-f0-9]{64}',cid) for cid in ids)
                and re.fullmatch('sha256:[a-f0-9]{64}',image_id) is not None,'EXACT_PREFLIGHT_IDENTITIES_REQUIRED')
        self.binding,self.calls=binding,0
        self.inspects={'/v1.44/containers/'+cid+'/json' for cid in ids}
        self.image_path='/v1.44/images/'+image_id+'/json'
        self.paths=self.inspects|{self.image_path}

    def image(self):
        return decode(self.get(self.image_path))


def registry_baseline(actual,pin):
    state=actual['State']
    require(actual['Id']==pin['containerId'] and actual['Image']==pin['imageId']
            and state['Status']=='exited' and state['Running'] is False and state['Pid']==0
            and not any(state.get(k) for k in ('Paused','Restarting','Dead')),
            'EXACT_STOPPED_REGISTRY_REQUIRED')
    require(digest(stable_fields(actual))==pin['stableMetadataHash']
            and all(digest(actual[field])==pin[key] for field,key in [('Config','configHash'),
                    ('HostConfig','hostConfigHash'),('NetworkSettings','networkSettingsHash')])
            and digest(sorted(actual['Mounts'],key=lambda m:m['Destination']))==pin['mountsHash'],
            'STOPPED_REGISTRY_BASELINE_CHANGED')


def mount_declarations(registry,recipe,tree):
    files=recipe['launch']['sources'];token=recipe['renewableToken']
    require(type(files) is list and len(files)==2,'TWO_STATIC_KEY_DECLARATIONS_REQUIRED')
    bindings=[{k:s[k] for k in ('source','target','readOnly')} for s in files]
    bindings += [{k:tree[k] for k in ('source','target','readOnly')},
                 {k:token[k] for k in ('source','target')}|{'readOnly':True}]
    require(recipe['launch']['manifest']['mounts']==bindings and all(b['readOnly'] is True for b in bindings)
            and len({b['source'] for b in bindings})==len({b['target'] for b in bindings})==4,
            'FOUR_DISTINCT_READONLY_MOUNT_DECLARATIONS_REQUIRED')
    for b in bindings:
        for k in ('source','target'):
            p=Path(b[k]);require(p.is_absolute() and '..' not in p.parts and str(p)==b[k] and b[k]!='/',
                                'CANONICAL_MOUNT_DECLARATION_REQUIRED')
    require(not any(a[k].startswith(b[k]+'/') for a in bindings for b in bindings if a is not b
                    for k in ('source','target')),'SHADOWING_MOUNT_DECLARATIONS_DENIED')
    actual=registry['Mounts']
    require(type(actual) is list and len(actual)==4 and all(m.get('Type')=='bind' and m.get('RW') is False for m in actual)
            and sorted((m['Source'],m['Destination']) for m in actual)==sorted((b['source'],b['target']) for b in bindings),
            'RETAINED_BIND_MOUNT_DECLARATIONS_CHANGED')
    # No stat/open of keys, configtree or token directory; declarations only.
    return {'mountCount':4,'declarationsHash':digest(bindings),'readOnlyBindDeclarationsMatch':True,
            'hostFileCustodyProven':False,'liveMountCustodyProven':False,'currentTokenValidityProven':False}


def capture(case):
    validate_case(case)
    inputs,raw=private_json(case['inputsPath'])
    require(hashlib.sha256(raw).hexdigest()==case['inputsHash'],'RETAINED_INPUT_BYTES_CHANGED')
    composition=compile_composition(case,inputs)
    proposal=inputs['proposal'];pin=proposal['registry'];gateway_pin=proposal['gatewayBinding']
    registry_inputs=inputs['registryInputs'];audit=registry_inputs['imageAudit']
    image_id=runtime_image_id(audit)
    require(image_id==pin['imageId'],'AUDITED_IMAGE_DIFFERS_FROM_STOPPED_REGISTRY')
    engine=Engine(proposal['engineBinding'],[gateway_pin['containerId'],pin['containerId']],image_id)
    gateway=engine.inspect(gateway_pin['containerId']);generation(gateway,gateway_pin)
    registry=engine.inspect(pin['containerId']);registry_baseline(registry,pin)
    image=engine.image();image_evidence=loaded(audit,image)
    mounts=mount_declarations(registry,registry_inputs['nodeRecipe'],registry_inputs['configtree'])
    after_image=engine.image();loaded(audit,after_image)
    after_registry=engine.inspect(pin['containerId']);registry_baseline(after_registry,pin)
    after_gateway=engine.inspect(gateway_pin['containerId']);generation(after_gateway,gateway_pin)
    image_fields=('Id','Os','Architecture','RootFS','Config')
    require(all(image.get(k)==after_image.get(k) for k in image_fields)
            and stable_fields(registry)==stable_fields(after_registry)
            and stable_fields(gateway)==stable_fields(after_gateway),'PREFLIGHT_RESOURCE_DRIFT')
    require(private_json(case['inputsPath'])[1]==raw,'RETAINED_INPUTS_CHANGED_DURING_PREFLIGHT')
    composition.update(imageMetadataEvidence=image_evidence,mountDeclarations=mounts,
            retainedInputsPath=case['inputsPath'],engineGets=engine.calls,
            imageLayerBytesReaudited=False,completeCurrentOciProven=False,
            currentRegistryIdentityEstablished=False,currentDatabaseAdmissionProven=False,
            currentTokenAdmissionProven=False,liveGatewayRouteMapRead=False,
            rootCauseEstablished=False,runtimeEffectsDispatched=0)
    return composition,engine.calls


if __name__=='__main__':
    try:
        require(os.geteuid()==0 and sys.flags.isolated,'ROOT_ISOLATED_PREFLIGHT_REQUIRED')
        signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(Stop('READ_ONLY_PREFLIGHT_DEADLINE')));signal.alarm(45)
        require(len(sys.argv)==2,'ONE_CASE_FILE_REQUIRED')
        with open(sys.argv[1],'rb') as source:raw=source.read(8193)
        require(len(raw)<=8192,'BOUNDED_CASE_REQUIRED');case=decode(raw)
        composition,calls=capture(case);path,sha=publish(case,composition)
        print(json.dumps({'schema':SCHEMA,'status':'SOURCE_COMPOSITION_AND_IMAGE_DECLARATIONS_OBSERVED',
            'complete':True,'readOnlyRuntime':True,'privateCompositionPath':path,'privateCompositionHash':sha,
            'sourceCompositionPrepared':True,'currentImageMetadataMatchesHistoricalAudit':True,
            'imageLayerBytesReaudited':False,'readOnlyMountDeclarationsMatch':True,
            'hostFileCustodyProven':False,'completeCurrentOciProven':False,
            'currentRegistryIdentityEstablished':False,'currentTokenAdmissionProven':False,
            'currentDatabaseAdmissionProven':False,'liveGatewayRouteMapRead':False,
            'unresolvedGateCount':7,'nativeExecutorQualified':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
            'engineGets':calls,'maximumEngineGets':MAX_GETS,'databaseCalls':0,'oauthRequests':0,'credentialFilesOpened':0,
            'runtimeEffectsDispatched':0,'activationResubmitted':False,'providerRecoveryProposed':False,
            'automaticReplayAllowed':False,'budgetReset':False,'rootCauseEstablished':False,'releaseAcceptance':False,
            'completedTechnicalPhases':8,'functionalMilestonesProven':4},sort_keys=True),flush=True)
    except Exception as error:
        print(json.dumps(stopped(error),sort_keys=True),flush=True);sys.exit(1)
