"""Protected metadata intake only: never opens credential, MAC or TLS key files."""
import hashlib,json,os,pwd,re,sys,tempfile,types
from pathlib import Path
CUSTODY_HASH='cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf'
INPUTS=Path('/etc/ouf/deploy-snapshots/semantic-discovery-runtime-inputs-682nr5ky')
MANIFEST_HASH='732a633e46cb06bb720352aa6a90946281ba6489e94aa35dc04820eae56b4a70'
BINDING=Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-inputs-XE7IwlGm/binding.json')
BINDING_HASH='3f1872a332da691667a306db11d0749065ec2149080437853eada820ff7ec47a'
TRUST=Path('/etc/ouf/deploy-snapshots/semantic-discovery-java-trust-4pgerb71')
DRAFT=Path('/home/oufadmin/ouf-replacement-configuration-draft-ncbqgw9g/private-replacement-configuration.json')
DRAFT_HASH='742796d0da0e910fa5d113e117c56d43ce3024d004010971a4982c18da4d8090'
def require(v,reason):
    if not v:raise ValueError(reason)
def validate(manifest,binding,trust,draft):
    require(manifest['schema']=='ouf.discovery.private-runtime-input-manifest.v1' and manifest['mountsInstalled'] is False and manifest['applicationCutoverAuthorized'] is False,'EXACT_UNMOUNTED_INPUT_MANIFEST_REQUIRED')
    for k in ('existingWorkloadCredentialHash','discoveryMacKeyHash','publicCaHash'):require(re.fullmatch('[a-f0-9]{64}',manifest[k]),'INPUT_HASH_BINDINGS_REQUIRED')
    require(trust['status']=='CANDIDATE_PUBLIC_JAVA_TRUST_PREPARED_NOT_MOUNTED' and trust['runtimeInputManifestHash']==MANIFEST_HASH and trust['truststoreHash']=='dcfb221cf3382ab02b752bce3274f64a63c0d822227a5359d1329dee38008079' and trust['containsPrivateKeys'] is False and trust['toolContainerCleanupProven'] is True,'EXACT_COMPLETED_PUBLIC_TRUST_RECEIPT_REQUIRED')
    require(draft['runtimeInputManifestHash']==MANIFEST_HASH and draft['applyAuthorized'] is False and draft['completeReplacementOciProven'] is False,'EXACT_UNAPPLIED_PRIVATE_DRAFT_REQUIRED')
    require(type(binding) is dict and type(binding.get('routes')) is dict,'ORIGINAL_PROVIDER_ROUTE_BINDING_REQUIRED')
    return {'schema':'ouf.discovery.protected-replacement-binding-intake.v1','runtimeInputManifest':manifest,'originalProviderBinding':binding,'javaTrustReceipt':trust,'replacementConfigurationDraft':draft,'stableRereadsOnly':True,'completeReplacementOciProven':False,'productionApplyReady':False,'applicationCutoverAuthorized':False}
def main():
    report={'schema':'ouf.discovery.protected-replacement-binding-read.v1','existingConfigurationWrites':0,'containerLifecycleOperations':0,'imageImports':0,'databaseWrites':0,'firewallWrites':0,'dnsQueries':0,'providerCalls':0,'iamRequests':0,'privateKeyFilesOpened':0,'credentialFilesOpened':0,'privateValuesPrinted':False,'commonLockAcquired':False,'r9Touched':False,'signaturesIssued':0,'readOnlyRetrySafe':True,'productionApplyReady':False,'notReleaseAcceptance':True}
    try:
        require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode and len(sys.argv)==1,'ISOLATED_ROOT_METADATA_READ_REQUIRED')
        source=globals().get('__custody_source__');require(type(source) is bytes and hashlib.sha256(source).hexdigest()==CUSTODY_HASH,'SEALED_CUSTODY_SOURCE_REQUIRED')
        c=types.ModuleType('sealed_custody');exec(compile(source,'sealed-custody','exec'),c.__dict__)
        specs=[(INPUTS/'private-input-manifest.json',0,MANIFEST_HASH),(BINDING,0,BINDING_HASH),(TRUST/'receipt.json',0,None),(DRAFT,pwd.getpwnam('oufadmin').pw_uid,DRAFT_HASH)]
        raws=[c.file_bytes(p,uid,{0o600},expected=h) for p,uid,h in specs]
        plan=validate(*map(json.loads,raws))
        require(all(c.file_bytes(p,uid,{0o600},expected=h)==raw for (p,uid,h),raw in zip(specs,raws)),'PROTECTED_METADATA_CHANGED_DURING_READ')
        root=Path(tempfile.mkdtemp(prefix='semantic-discovery-protected-bindings-',dir=c.BASE));root.chmod(0o700)
        output=c.encoded(plan);c.create(root/'private-protected-bindings.json',output)
        report.update(status='PROTECTED_REPLACEMENT_BINDINGS_CAPTURED_NOT_APPLY_READY',evidenceDirectory=str(root),privateIntakeHash=hashlib.sha256(output).hexdigest(),providerBindingHash=BINDING_HASH,runtimeInputManifestHash=MANIFEST_HASH,privateDraftHash=DRAFT_HASH,newProtectedSnapshotFilesCreated=1)
        c.create(root/'receipt.json',c.encoded(report));code=0
    except Exception as error:
        reason=str(error);report.update(status='PROTECTED_BINDING_READ_BLOCKED',reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,120}',reason) else 'PROTECTED_BINDING_READ_UNPROVEN',errorType=type(error).__name__);code=1
    print('OUF_REPLACEMENT_PROTECTED_BINDINGS='+json.dumps(report,sort_keys=True));return code
if __name__=='__main__':raise SystemExit(main())
