"""Capture selected private coordinator/history inputs for adapter wiring.

No source/configuration discovery, key bytes, native commands, grants, signatures,
claims, service/container/DB/network operation. Private copies stay root-private.
Historical intake is never current runtime/transition authority.
"""
import hashlib,json,os,re,stat,sys,types
from pathlib import Path

HASHES={'atomic':'c113f578b027c39573b4562cd3ac324abb8108a393b82dde19f8eb53d98e0ea6','custody':'cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf','prepare':'693ec0196a60d3a9f6adee96571947306df4a0cffb449905c3dcf8c09a34da1b'}
BASE=Path('/etc/ouf/deploy-snapshots')
COORDINATOR=BASE/'semantic-coordinated-boot-install-v2-e4repg0a'/'coordinated-configuration.json'
COORDINATOR_HASH='656c23f18e3f3eb4c1ce630f5056be87f7883eab7b048065092dafbd018284a8'
CONTEXT=BASE/'semantic-provider-v2-approved-context-mf9x0eqd'
AUTHORITY=BASE/'semantic-creation-issuer-install-USjonf22'/'installation-authority-profile.json'
AUTHORITY_HASH='7fb7880d58e43ab40f9f53dac07a5dbad462d12e3a96f3b1287c6763b1d7ce18'
R12_AUTH_HASH='9730f8006a4257cbd2bf7576e6d0e49e41258360e0ca367f3e37852d57826e2b'
NATIVE_INTAKE_HASH='9ec18cf053e5925e42df93b75990343cc1d09696975fc2a224d76b4b28becdae'
NATIVE_INTAKE=BASE/('semantic-native-v11-intake-'+NATIVE_INTAKE_HASH)

def require(ok,why):
    if not ok:raise ValueError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def boot_id():return Path('/proc/sys/kernel/random/boot_id').read_text().strip()
def parse(raw):
    def unique(pairs):
        value={}
        for k,v in pairs:require(k not in value,'DUPLICATE_COORDINATION_INPUT_KEY');value[k]=v
        return value
    value=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('NONFINITE_COORDINATION_INPUT')))
    require(type(value) is dict,'EXACT_COORDINATION_INPUT_OBJECT_REQUIRED');return value
def modules(sources):
    require(type(sources) is dict and set(sources)==set(HASHES),'EXACT_COORDINATION_SOURCE_CLOSURE_REQUIRED')
    for name,h in HASHES.items():require(type(sources[name]) is bytes and len(sources[name])<=131072 and sha(sources[name])==h,'COORDINATION_SOURCE_HASH_MISMATCH')
    result={}
    for name in HASHES:
        module=types.ModuleType('sealed_coordination_'+name);exec(compile(sources[name],'sealed-coordination-'+name,'exec'),module.__dict__);result[name]=module
    return result

def collect(prepare,custody):
    reads={};files={}
    def read(name,path,expected=None):
        raw=custody.file_bytes(path,0,{0o600},expected=expected);value=parse(raw)
        reads[str(path)]=(raw,expected);files[name]=raw;return value
    original_manifest=read('native-review-intake.json',NATIVE_INTAKE/'intake.json',NATIVE_INTAKE_HASH)
    require(original_manifest.get('schema')=='ouf.native-v11-atomic-review-intake.v1'
            and original_manifest.get('observationsAreHistorical') is True
            and all(original_manifest.get(k) is False for k in ('applicationCutoverAuthorized','productionApplyReady','runtimeAuthorityIssued')),'EXACT_EXISTING_HISTORICAL_NATIVE_INTAKE_REQUIRED')
    authority=read('existing-authority-profile.json',AUTHORITY,AUTHORITY_HASH)
    require(authority.get('schema')=='ouf.semantic-existing-installation-authority-bindings.v1','EXACT_EXISTING_AUTHORITY_BINDINGS_REQUIRED')
    coordinator=read('existing-coordinator.json',COORDINATOR,COORDINATOR_HASH)
    human=read('retained-human-binding.json',CONTEXT/'human-approval-binding.json')
    configuration_hash=human.get('configurationHash');require(type(configuration_hash) is str and re.fullmatch('[0-9a-f]{64}',configuration_hash) is not None,'RETAINED_EXECUTION_CONFIGURATION_HASH_REQUIRED')
    execution=read('retained-execution-configuration.json',CONTEXT/'execution-configuration.json',configuration_hash)
    auth=read('r12-authorization.json',prepare.R12/'authorization.json',R12_AUTH_HASH)
    require(auth.get('schema')=='ouf.provider-resilient-r12-authorization.v1' and auth.get('programHashes')==prepare.R12_PROGRAMS
            and sha(encoded({k:v for k,v in auth.items() if k!='contextRef'}))==auth.get('contextRef')
            and auth.get('incidentRef')==prepare.R12_INCIDENT and auth.get('ownerConfigurationHash')==COORDINATOR_HASH
            and auth.get('automaticRestart') is False and auth.get('enableAtBoot') is False,'EXACT_RETAINED_R12_SOURCE_CONTEXT_REQUIRED')
    claim=read('r12-activation-claim.json',prepare.R12_CLAIM)
    require(claim==auth.get('activationClaim') and claim.get('startAuthorized') is False,'RETAINED_R12_CLAIM_BINDING_DRIFT')
    invocation=read('r12-worker-invocation.json',prepare.R12/'worker-invocation-claim.json')
    worker=read('r12-worker-status.json',prepare.R12/'worker-status.json')
    history=read('r12-recovery-history.json',prepare.R12/'retry/recovery.json')
    boot=boot_id()
    require(auth.get('hostBootId')==boot and invocation=={'contextRef':auth['contextRef'],'pid':worker.get('workerPid'),'hostBootId':boot}
            and type(worker.get('workerPid')) is int and worker['workerPid']>1
            and worker.get('schema')=='ouf.provider-resilient-worker-status.v1' and worker.get('incidentRef')==prepare.R12_INCIDENT
            and worker.get('doNotRerunApply') is True and worker.get('startAuthorized') is False,'CURRENT_RETAINED_WORKER_CONTEXT_REQUIRED')
    require(history.get('contextRef')==auth['contextRef'] and history.get('generationRef')==auth.get('generationRef')
            and history.get('timeAccountingProfile')=='ouf.lease-cumulative-recovery-time.v1'
            and type(history.get('attempts')) is int and history['attempts']>=0
            and type(history.get('publicationCount')) is int and history['publicationCount']>=0,'EXACT_CUMULATIVE_RECOVERY_HISTORY_REQUIRED')
    for name,h in prepare.R12_PROGRAMS.items():custody.file_bytes(prepare.R12/name,0,{0o600},expected=h)
    # Do not load coordinator/issuer configuration as code or follow key paths.
    require(type(coordinator) is dict and type(execution.get('commandBindings')) is dict,'RETAINED_COORDINATION_CONTRACT_REQUIRED')
    for path,(raw,h) in reads.items():require(custody.file_bytes(path,0,{0o600},expected=h)==raw,'COORDINATION_INPUT_CHANGED_DURING_READ')
    for name,h in prepare.R12_PROGRAMS.items():custody.file_bytes(prepare.R12/name,0,{0o600},expected=h)
    return files,{'nativeReviewIntakeHash':NATIVE_INTAKE_HASH,'authorityProfileHash':AUTHORITY_HASH,'coordinatorConfigurationHash':COORDINATOR_HASH,
                  'executionConfigurationHash':configuration_hash,'r12AuthorizationHash':R12_AUTH_HASH,'r12ContextRef':auth['contextRef'],
                  'r12GenerationRef':auth['generationRef'],'r12IncidentRef':prepare.R12_INCIDENT,'retainedProgramCountVerified':len(prepare.R12_PROGRAMS),
                  'recoveryAttempts':history['attempts'],'leasePublicationCount':history['publicationCount'],'workerPid':worker['workerPid']}

def main():
    report={'schema':'ouf.native-v11-coordination-inputs-capture.v1','applicationCutoverAuthorized':False,'runtimeAuthorityIssued':False,'productionApplyReady':False,
            'containerLifecycleOperations':0,'serviceLifecycleOperations':0,'databaseQueries':0,'databaseWrites':0,'providerCalls':0,'dnsQueries':0,'firewallWrites':0,
            'imageImports':0,'signaturesIssued':0,'privateKeysRead':0,'credentialFilesOpened':0,'newClaimCreated':False,'budgetReset':False,'r12Touched':False,
            'privateValuesPrinted':False,'notReleaseAcceptance':True,'observationsAreHistorical':True,'newRecoveryAuthorityIssued':False,
            'readConsistencyMode':'STABLE_REREADS_NOT_RUNTIME_TRANSITION_AUTHORITY','protectedFileWriteAttempts':0,'protectedFileWrites':0}
    phase='VERIFY_SELECTED_SEALED_COORDINATION_READER'
    try:
        require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode and len(sys.argv)==1,'ISOLATED_ROOT_COORDINATION_CAPTURE_REQUIRED')
        m=modules(globals().get('__coordination_sources__'));files,bindings=collect(m['prepare'],m['custody'])
        phase='ATOMIC_PRIVATE_COORDINATION_INPUT_PUBLICATION'
        manifest={'schema':'ouf.native-v11-atomic-review-intake.v1','collectionKind':'EXISTING_COORDINATOR_AND_CUMULATIVE_HISTORY_INPUTS',
                  'fileHashes':{n:sha(raw) for n,raw in files.items()},'sourceHashes':HASHES,'bindings':bindings,
                  'applicationCutoverAuthorized':False,'productionApplyReady':False,'runtimeAuthorityIssued':False,'observationsAreHistorical':True}
        def checkpoint(point):
            if point.startswith('BEFORE_FILE_'):report['protectedFileWriteAttempts']+=1
            if point.startswith('AFTER_FILE_'):report['protectedFileWrites']+=1
        published=m['atomic'].publish(BASE,files,manifest,0,checkpoint)
        require(published['protectedFileWrites']==report['protectedFileWrites'],'PRIVATE_COORDINATION_WRITE_ACCOUNTING_UNPROVEN')
        report.update(published);report.update(status='SELECTED_COORDINATION_INPUTS_AND_RETAINED_HISTORY_CAPTURED_NO_RUNTIME_AUTHORITY',bindings=bindings);code=0
    except Exception as error:
        reason=str(error);report.update(status='COORDINATION_INPUT_CAPTURE_BLOCKED',phase=phase,reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,120}',reason) else 'COORDINATION_INPUT_CAPTURE_UNPROVEN');code=1
        if phase=='ATOMIC_PRIVATE_COORDINATION_INPUT_PUBLICATION' and report['protectedFileWriteAttempts']:
            report['publicationOutcomeRequiresReconciliation']=True
        if report['protectedFileWriteAttempts']!=report['protectedFileWrites']:
            report.update(protectedFileWrites=None,privateWriteOutcomeRequiresReconciliation=True)
    print('OUF_NATIVE_V11_COORDINATION_INPUTS='+json.dumps(report,sort_keys=True));return code

if __name__=='__main__':raise SystemExit(main())
