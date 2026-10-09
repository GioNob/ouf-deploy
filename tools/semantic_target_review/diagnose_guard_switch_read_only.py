"""Exact retained-attempt diagnosis; no signing, publication, switch or start."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import traceback

PACKAGE=Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-transaction-source-ff13uh3n')
CONTEXT=Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-approved-context-kanx36_x')
REPORT={'schema':'ouf.semantic-guard-switch-read-only-diagnosis.v1','privateKeysRead':0,
    'containerLifecycleOperations':0,'existingConfigurationWrites':0,'startAuthorized':False,
    'notReleaseAcceptance':True,'privateValuesPrinted':False}
PHASE='VERIFY_ORIGINAL_SEALED_ENTRY'
try:
    assert os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode
    path=PACKAGE/'provider_transaction_intake.py'
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:raw=os.read(fd,131073)
    finally:os.close(fd)
    assert hashlib.sha256(raw).hexdigest()=='edc3c97d54a9d241c93ea9791f4dffce9984565763c2236ad1644e8b90c4c4b5'
    entry={'__name__':'read_only_diagnostic_entry','__file__':str(path)}
    exec(compile(raw,str(path),'exec'),entry)
    assert entry['read'](path)==raw
    entry['load'](PACKAGE)
    PHASE='READ_RETAINED_ISSUANCE_AND_PUBLICATION_RECEIPTS'
    approval=entry['parse'](entry['read'](CONTEXT/'human-approval-binding.json'))
    cfg=entry['parse'](entry['bound']({'path':str(CONTEXT/'execution-configuration.json'),'sha256':approval['configurationHash']}))
    output=Path(cfg['outputRoot']);assert output==CONTEXT.parent/'semantic-provider-v2-transaction-kanx36_x'
    REPORT['transactionDirectory']=str(output)
    REPORT['roleIssuance']={}
    for role in ('adapter','southbound'):
        receipt=entry['parse'](entry['read'](PACKAGE/'role-authority'/role/'role-issuance-receipt.json'))
        REPORT['roleIssuance'][role]={k:receipt.get(k) for k in ('status','signaturesIssued','startPerformed')}
    REPORT['claimsPresent']={n:os.path.lexists(output/n) for n in ('runtime-switch-claim.json','runtime-switch-receipt.json','runtime-switch-denial.json')}
    PHASE='VERIFY_PUBLISHED_FILE_HASHES_READ_ONLY'
    receipt=entry['parse'](entry['read'](output/'installation-receipt.json'))
    hashes=receipt['fileHashes']
    assert type(hashes) is dict and len(hashes)<=256
    for name,expected in hashes.items():
        assert Path(name).is_relative_to(output) and '..' not in Path(name).parts
        entry['bound']({'path':name,'sha256':expected})
    REPORT['publishedFilesHashMatched']=len(hashes)
    PHASE='OBSERVE_CURRENT_NATIVE_EMPTY_GUARD_READ_ONLY'
    pointer=entry['parse'](entry['bound'](cfg['guardPointerBinding']))
    binding={'path':pointer['receiptFile'],'sha256':pointer['receiptHash']}
    guard_receipt=entry['parse'](entry['bound'](binding))
    owner_hash='656c23f18e3f3eb4c1ce630f5056be87f7883eab7b048065092dafbd018284a8'
    owner=entry['parse'](entry['bound']({'path':str(Path(binding['path']).parent/'coordinated-configuration.json'),'sha256':owner_hash}))
    from authenticate_provider_transaction import TARGETS
    from transaction_guard_observation import observe_locked
    candidates={v['containerId']:{'imageManifestDigest':v['imageManifestDigest'],'runtimeName':'ouf-semantic-admitted-v2'} for v in TARGETS.values()}
    fd=os.open(owner['commonLockFile'],os.O_RDWR|os.O_NOFOLLOW)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        REPORT['nativeGuardObservation']=observe_locked(fd,binding,owner_hash,candidates,cfg['commandBindings'])
    finally:os.close(fd)
    REPORT.update(status='READ_ONLY_CHECKS_PASS',phase=PHASE)
except Exception as error:
    REPORT.update(status='READ_ONLY_DIAGNOSIS_BLOCKED',phase=PHASE,errorType=type(error).__name__)
    if isinstance(error,OSError):REPORT['errno']=error.errno
    diagnosis=getattr(error,'diagnosis',None)
    if type(diagnosis) is dict:
        REPORT['reason']=diagnosis.get('reason');REPORT['innerStage']=diagnosis.get('stage')
    elif isinstance(error,(RuntimeError,ValueError)) and re.fullmatch('[A-Z][A-Z0-9_]{0,95}',str(error)):
        REPORT['reason']=str(error)
    allowed={'directory','sourceHashes','fileHashes','kernel','bootGuardFile','compilerFile','journalFile','guardCommand','artifactHashes','configurationHash','lockFile','bootConfigurationHash','bootProfileHash'}
    if isinstance(error,KeyError) and len(error.args)==1 and error.args[0] in allowed:REPORT['missingField']=error.args[0]
    REPORT['exceptionPoints']=[{'file':Path(t.filename).name,'function':t.name,'line':t.lineno} for t in traceback.extract_tb(error.__traceback__)[-4:]]
print('OUF_SWITCH_READ_ONLY_DIAGNOSIS='+json.dumps(REPORT,sort_keys=True))
