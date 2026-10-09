"""Read retained R3 and actual containerd state paths; never retry admission."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tomllib
import traceback

PACKAGE=Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-transaction-source-ff13uh3n')
CONTEXT=Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-approved-context-rsj9dtwr')
OUTPUT=CONTEXT.parent/'semantic-provider-v2-transaction-rsj9dtwr'
REPORT={'schema':'ouf.semantic-r3-bundle-parent-read-only.v1','privateKeysRead':0,
    'containerLifecycleOperations':0,'existingConfigurationWrites':0,'signaturesIssued':0,
    'privateValuesPrinted':False,'startAuthorized':False,'notReleaseAcceptance':True}
PHASE='VERIFY_RETAINED_SEALED_SOURCE'

def option(args,name):
    for i,value in enumerate(args):
        if value==name and i+1<len(args):return args[i+1]
        if value.startswith(name+'='):return value[len(name)+1:]
    return None

try:
    assert os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode
    path=PACKAGE/'provider_transaction_intake.py'
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:raw=os.read(fd,131073)
    finally:os.close(fd)
    assert hashlib.sha256(raw).hexdigest()=='edc3c97d54a9d241c93ea9791f4dffce9984565763c2236ad1644e8b90c4c4b5'
    entry={'__name__':'r3_read_only_entry','__file__':str(path)}
    exec(compile(raw,str(path),'exec'),entry)
    entry['read'](path);entry['load'](PACKAGE)
    PHASE='VERIFY_PUBLISHED_R3_WRAPPER_AND_BUNDLE_BINDINGS'
    approval=entry['parse'](entry['read'](CONTEXT/'human-approval-binding.json'))
    assert approval['approvalRef']=='OUF_PROVIDER_V2_POST_SIGNATURE_RECOVERY_HUMAN_APPROVAL_20261009_093008'
    cfg=entry['parse'](entry['bound']({'path':str(CONTEXT/'execution-configuration.json'),'sha256':approval['configurationHash']}))
    assert cfg['outputRoot']==str(OUTPUT)
    receipt=entry['parse'](entry['read'](OUTPUT/'installation-receipt.json'))
    for name,expected in receipt['fileHashes'].items():
        assert Path(name).is_relative_to(OUTPUT) and '..' not in Path(name).parts
        entry['bound']({'path':name,'sha256':expected})
    REPORT['publishedFileHashesMatched']=len(receipt['fileHashes'])
    switched=entry['parse'](entry['read'](OUTPUT/'runtime-switch-receipt.json'))
    wrapper=entry['read']('/usr/local/sbin/ouf-semantic-admitted-v2',True)
    assert hashlib.sha256(wrapper).hexdigest()==switched['installedWrapperHash']
    REPORT['wrapperSwitchStatus']=switched['status'];REPORT['installedWrapperHash']=switched['installedWrapperHash']
    from authenticate_provider_transaction import TARGETS
    proposal=entry['parse'](entry['read'](OUTPUT/'runtime-configuration-proposal.json'))
    REPORT['roles']={}
    for role,target in TARGETS.items():
        cid=target['containerId'];values=cfg['recordsByRole'][role]
        context=entry['parse'](entry['bound'](values['context']))
        assert context['containerId']==cid
        REPORT['roles'][role]={'containerId':cid,'approvedContextBundleParent':context['bundleParent'],
            'runtimeBundleParents':proposal['candidates'][cid]['bundleParents']}
    PHASE='READ_ACTUAL_CONTAINERD_STATE_METADATA'
    REPORT['containerdProcesses']=[]
    allowed_configs={'/etc/containerd/config.toml','/run/docker/containerd/containerd.toml'}
    for item in Path('/proc').iterdir():
        if not item.name.isdigit():continue
        try:
            if (item/'comm').read_text().strip()!='containerd':continue
            executable=(item/'exe').resolve(strict=True)
            if executable.name!='containerd' or item.stat().st_uid!=0:continue
            with (item/'cmdline').open('rb') as stream:raw=stream.read(16385)
            assert len(raw)<=16384
            args=raw.decode('utf-8').rstrip('\0').split('\0')
            state=option(args,'--state');config=option(args,'--config') or option(args,'-c')
            value={'pid':int(item.name),'executable':str(executable),'stateSource':None,'statePath':None}
            if state:value.update(stateSource='EXPLICIT_PROCESS_ARGUMENT',statePath=state)
            elif config:
                p=Path(config).resolve(strict=True)
                value['configurationPath']=str(p)
                if str(p) in allowed_configs:
                    info=p.lstat();assert stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022
                    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
                    try:raw=os.read(fd,131073)
                    finally:os.close(fd)
                    assert len(raw)<=131072
                    state=tomllib.loads(raw.decode('utf-8')).get('state')
                    if state:value.update(stateSource='EXPLICIT_CONTAINERD_CONFIGURATION',statePath=state)
            if value['statePath']:
                p=Path(value['statePath']);assert p.is_absolute() and '..' not in p.parts
                parent=p/'io.containerd.runtime.v2.task/moby'
                value['containerdV2MobyBundleParent']=str(parent)
                value['parentPresent']=parent.is_dir()
                value['candidateDirectoriesPresent']={t['containerId']:(parent/t['containerId']).is_dir() for t in TARGETS.values()}
                value['matchesApprovedParent']={r:str(parent) in v['runtimeBundleParents'] for r,v in REPORT['roles'].items()}
            REPORT['containerdProcesses'].append(value)
        except (FileNotFoundError,ProcessLookupError,PermissionError):continue
    REPORT.update(status='READ_ONLY_METADATA_CAPTURED',phase=PHASE,
        actualRuntimeInvocationBundleCaptured=False,defaultStateInferred=False,
        note='Configured containerd state is metadata, not a retained capture of the failed runtime argv.')
except Exception as error:
    REPORT.update(status='READ_ONLY_DIAGNOSIS_BLOCKED',phase=PHASE,errorType=type(error).__name__)
    if isinstance(error,OSError):REPORT['errno']=error.errno
    REPORT['exceptionPoints']=[{'file':Path(t.filename).name,'function':t.name,'line':t.lineno}
        for t in traceback.extract_tb(error.__traceback__)[-4:]]
print('OUF_R3_BUNDLE_PARENT_DIAGNOSIS='+json.dumps(REPORT,sort_keys=True))
