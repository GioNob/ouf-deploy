"""Freeze provider/env and role mount contracts from the protected intake; no apply."""
import copy,hashlib,json,os,re,stat,sys,tempfile,types
from pathlib import Path
SOURCE_HASH='cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf'
INTAKE=Path('/etc/ouf/deploy-snapshots/semantic-discovery-protected-bindings-qb3381ho/private-protected-bindings.json')
INTAKE_HASH='6521033c3c9c1c5dd0963d630e3748003b20e9d6a8a0f71fcc23e92471e5b358'
def require(v,reason):
    if not v:raise ValueError(reason)
def env(cfg):
    out={}
    for row in cfg['Env']:
        k,v=row.split('=',1);require(k not in out,'UNIQUE_APPLICATION_ENV_REQUIRED');out[k]=v
    return out
def compile_contract(intake):
    draft=intake['replacementConfigurationDraft'];manifest=intake['runtimeInputManifest'];binding=intake['originalProviderBinding'];trust=intake['javaTrustReceipt']
    require(intake['productionApplyReady'] is False and draft['applyAuthorized'] is False and manifest['mountsInstalled'] is False,'UNAPPLIED_INTAKE_REQUIRED')
    settings=env(draft['candidateConfig']);routes=binding['routes'];admission=binding['adapter']['admission']
    for key in ('issuer','audience','workload','scope'):
        require(routes[key]==admission[key],'FROZEN_PROVIDER_ADMISSION_MISMATCH')
    pairs={'OUF_SCHEMA_GOV_SEARCH_PATH':'searchPath','OUF_SCHEMA_GOV_FETCH_PATH':'fetchPath','OUF_SCHEMA_GOV_CLIENT_ID':'workload','OUF_SCHEMA_GOV_WORKLOAD_SCOPE':'scope'}
    for setting,key in pairs.items():require(settings[setting]==routes[key],'CANDIDATE_PROVIDER_ROUTE_OR_WORKLOAD_MISMATCH')
    for key in ('searchPath','fetchPath'):require(routes[key]==binding['adapter'][key] and re.fullmatch('/[A-Za-z0-9_/-]{1,255}',routes[key]),'EXACT_PROVIDER_REQUEST_PATH_REQUIRED')
    require(settings['OUF_IAM_ISSUER']==routes['issuer'] and settings['OUF_IAM_AUDIENCE']==routes['audience'] and settings['OUF_SCHEMA_GOV_TOKEN_ENDPOINT']==routes['issuer']+'/protocol/openid-connect/token','EXACT_PROVIDER_IAM_CONTRACT_REQUIRED')
    require(binding['tlsIdentities']['southboundHostname']=='ouf-semantic-southbound-v2' and settings['OUF_SCHEMA_GOV_GATEWAY_BASE_URL']=='https://ouf-semantic-southbound-v2:10443','EXACT_PROVIDER_TLS_IDENTITY_REQUIRED')
    require(manifest['consumerIdentities']=={'semantic':{'uid':10001,'gid':10001},'gateway':{'uid':636,'gid':636}},'EXACT_RUNTIME_ROLE_IDENTITIES_REQUIRED')
    mounts=copy.deepcopy(draft['newReadOnlyMounts']);expected=[('schema-gov-client-secret',settings['OUF_SCHEMA_GOV_CLIENT_SECRET_FILE'],manifest['existingWorkloadCredentialHash']),('semantic-discovery-owner.key',settings['OUF_SEMANTIC_DISCOVERY_DELEGATION_KEY_FILE'],manifest['discoveryMacKeyHash']),('java-truststore.p12','/run/ouf-discovery-trust/java-truststore.p12',trust['truststoreHash'])]
    require(len(mounts)==3,'EXACT_THREE_APPLICATION_MOUNTS_REQUIRED')
    for mount,(filename,target,digest) in zip(mounts,expected):
        require(Path(mount['source']).name==filename and mount['target']==target and mount['uid']==mount['gid']==10001 and mount['mode']==0o400 and mount['readOnly'] is True and re.fullmatch('[a-f0-9]{64}',digest),'EXACT_ROLE_OWNED_READ_ONLY_MOUNT_REQUIRED')
        mount['sha256']=digest;mount['secretBytesFreshlyVerified']=False
    require(len({v['target'] for v in mounts})==3,'DISTINCT_APPLICATION_MOUNT_TARGETS_REQUIRED')
    result={'schema':'ouf.discovery.private-application-input-contract.v1','candidateConfig':draft['candidateConfig'],'roleOwnedReadOnlyMounts':mounts,'retainedConsultationMounts':draft['retainedAuthMounts'],'originalProviderBinding':binding,'runtimeInputManifest':manifest,'protectedIntakeHash':INTAKE_HASH,'providerContractVerifiedAgainstFrozenBinding':True,'roleFileMetadataRequiredAtApply':True,'secretBytesMustBeReverifiedPrivatelyAtApply':True,'currentNativeGenerationMustBeReverifiedAtApply':True,'completeReplacementOciProven':False,'productionApplyReady':False,'applicationCutoverAuthorized':False}
    public={'providerContractVerifiedAgainstFrozenBinding':True,'providerSearchPath':routes['searchPath'],'providerFetchPath':routes['fetchPath'],'providerWorkload':routes['workload'],'discoveryCallerWorkload':settings['OUF_SEMANTIC_DISCOVERY_DELEGATION_WORKLOAD'],'roleOwnedReadOnlyMountCount':3,'secretBytesFreshlyVerified':False,'completeReplacementOciProven':False,'productionApplyReady':False}
    return result,public

def role_metadata(mount):
    path=Path(mount['source']);require(path.is_absolute() and '..' not in path.parts,'EXACT_MOUNT_SOURCE_REQUIRED')
    for parent in path.parents:
        s=parent.lstat();require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'ROOT_PROTECTED_MOUNT_ANCESTOR_REQUIRED')
    s=path.lstat();require(stat.S_ISREG(s.st_mode) and s.st_uid==mount['uid'] and s.st_gid==mount['gid'] and stat.S_IMODE(s.st_mode)==mount['mode'] and s.st_nlink==1,'ROLE_OWNED_SOURCE_METADATA_REQUIRED')
    return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def main():
    report={'schema':'ouf.discovery.application-input-contract-preparation.v1','existingConfigurationWrites':0,'containerLifecycleOperations':0,'imageImports':0,'databaseWrites':0,'firewallWrites':0,'providerCalls':0,'iamRequests':0,'credentialFilesOpened':0,'privateKeyFilesOpened':0,'privateValuesPrinted':False,'commonLockAcquired':False,'r9Touched':False,'signaturesIssued':0,'mountsInstalled':False,'notReleaseAcceptance':True,'readOnlyRetrySafe':True}
    try:
        require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode and len(sys.argv)==1,'ISOLATED_ROOT_CONTRACT_COMPILATION_REQUIRED')
        source=globals().get('__custody_source__');require(type(source) is bytes and hashlib.sha256(source).hexdigest()==SOURCE_HASH,'SEALED_CUSTODY_SOURCE_REQUIRED')
        c=types.ModuleType('custody');exec(compile(source,'sealed-custody','exec'),c.__dict__)
        raw=c.file_bytes(INTAKE,0,{0o600},expected=INTAKE_HASH);intake=json.loads(raw);contract,public=compile_contract(intake)
        metadata=[role_metadata(v) for v in contract['roleOwnedReadOnlyMounts']]
        require(c.file_bytes(INTAKE,0,{0o600},expected=INTAKE_HASH)==raw and metadata==[role_metadata(v) for v in contract['roleOwnedReadOnlyMounts']],'CONTRACT_INPUT_CHANGED_DURING_PREPARATION')
        root=Path(tempfile.mkdtemp(prefix='semantic-discovery-application-contract-',dir=c.BASE));root.chmod(0o700);encoded=c.encoded(contract);c.create(root/'private-application-input-contract.json',encoded)
        report.update(status='APPLICATION_INPUT_CONTRACT_PREPARED_NOT_APPLY_READY',evidenceDirectory=str(root),privateContractHash=hashlib.sha256(encoded).hexdigest(),roleFileMetadataVerified=True,**public);c.create(root/'receipt.json',c.encoded(report));code=0
    except Exception as error:
        reason=str(error);report.update(status='APPLICATION_INPUT_CONTRACT_BLOCKED',reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,120}',reason) else 'APPLICATION_INPUT_CONTRACT_UNPROVEN',errorType=type(error).__name__);code=1
    print('OUF_APPLICATION_INPUT_CONTRACT='+json.dumps(report,sort_keys=True));return code
if __name__=='__main__':raise SystemExit(main())
