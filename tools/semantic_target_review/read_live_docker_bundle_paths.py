"""Read kernel cwd/endpoint of existing Docker shims, never create a task."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import traceback

def option(args,name):
    for i,value in enumerate(args):
        if value==name and i+1<len(args):return args[i+1]
        if value.startswith(name+'='):return value[len(name)+1:]
    return None

def process_metadata(item):
    before=(item/'stat').read_bytes()
    with (item/'cmdline').open('rb') as stream:raw=stream.read(16385)
    assert len(raw)<=16384 and item.stat().st_uid==0
    args=raw.decode().rstrip('\0').split('\0')
    executable=(item/'exe').resolve(strict=True)
    cwd=(item/'cwd').resolve(strict=True)
    after=(item/'stat').read_bytes()
    assert before.rsplit(b')',1)[1].split()[19]==after.rsplit(b')',1)[1].split()[19]
    return args,executable,cwd

def shim_bundles(socket,namespace,requested_cids=()):
    expected_socket=Path(socket).resolve(strict=True);groups={}
    for item in Path('/proc').iterdir():
        if not item.name.isdigit():continue
        try:
            if not (item/'comm').read_text().startswith('containerd-shim'):continue
            args,executable,cwd=process_metadata(item)
            if executable.name!='containerd-shim-runc-v2':continue
            address=option(args,'-address');ns=option(args,'-namespace');cid=option(args,'-id')
            if not address or ns!=namespace or not re.fullmatch('[0-9a-f]{64}',cid or ''):continue
            if Path(address.removeprefix('unix://')).resolve(strict=True)!=expected_socket:continue
            if cwd.name!=cid:continue
            parent=str(cwd.parent)
            group=groups.setdefault(parent,{'kernelShimCwdSamples':0,'requestedCidMatches':[]})
            group['kernelShimCwdSamples']+=1
            if cid in requested_cids:group['requestedCidMatches'].append(cid)
        except (FileNotFoundError,ProcessLookupError,PermissionError,AssertionError):continue
    return groups

def main():
    report={'schema':'ouf.semantic-live-docker-shim-bundle-read-only.v1','privateKeysRead':0,
        'containerLifecycleOperations':0,'existingConfigurationWrites':0,'signaturesIssued':0,
        'privateValuesPrinted':False,'startAuthorized':False,'notReleaseAcceptance':True,
        'historicalTargetRuntimeArgvCaptured':False,'defaultsInferred':False}
    phase='READ_APPROVED_R3_CONTEXT'
    try:
        assert os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode
        package=Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-transaction-source-ff13uh3n')
        path=package/'provider_transaction_intake.py'
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try:raw=os.read(fd,131073)
        finally:os.close(fd)
        assert hashlib.sha256(raw).hexdigest()=='edc3c97d54a9d241c93ea9791f4dffce9984565763c2236ad1644e8b90c4c4b5'
        entry={'__name__':'live_shim_reader','__file__':str(path)}
        exec(compile(raw,str(path),'exec'),entry)
        root=Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-approved-context-rsj9dtwr')
        approval=entry['parse'](entry['read'](root/'human-approval-binding.json'))
        cfg=entry['parse'](entry['bound']({'path':str(root/'execution-configuration.json'),'sha256':approval['configurationHash']}))
        contexts={r:entry['parse'](entry['bound'](b['context'])) for r,b in cfg['recordsByRole'].items()}
        parents={r:v['bundleParent'] for r,v in contexts.items()};cids=[v['containerId'] for v in contexts.values()]
        report['approvedBundleParents']=parents
        phase='READ_RUNNING_DOCKER_ENDPOINT'
        daemons=[]
        for item in Path('/proc').iterdir():
            if not item.name.isdigit():continue
            try:
                if (item/'comm').read_text().strip()!='dockerd':continue
                args,executable,cwd=process_metadata(item)
                assert executable.name=='dockerd'
                daemons.append({'pid':int(item.name),'containerdSocket':option(args,'--containerd'),
                    'namespaceArgument':option(args,'--containerd-namespace')})
            except (FileNotFoundError,ProcessLookupError):continue
        report['dockerDaemons']=daemons
        assert len(daemons)==1 and daemons[0]['containerdSocket']
        namespace=Path(next(iter(parents.values()))).name
        assert namespace=='moby' and len(set(parents.values()))==1
        assert daemons[0]['namespaceArgument'] in (None,namespace)
        phase='READ_KERNEL_CWD_OF_EXISTING_SHIMS'
        groups=shim_bundles(daemons[0]['containerdSocket'].removeprefix('unix://'),namespace,cids)
        report['observedBundleParents']=groups
        report['matchesApprovedLiteralParent']={r:v in groups for r,v in parents.items()}
        report['approvedParentCanonicalPaths']={r:str(Path(v).resolve()) for r,v in parents.items()}
        report['matchesApprovedCanonicalParent']={r:v in groups for r,v in report['approvedParentCanonicalPaths'].items()}
        report.update(status='LIVE_SHIM_METADATA_CAPTURED' if groups else 'NO_MATCHING_LIVE_SHIM_EVIDENCE',phase=phase)
    except Exception as error:
        report.update(status='READ_ONLY_SHIM_DIAGNOSIS_BLOCKED',phase=phase,errorType=type(error).__name__)
        if isinstance(error,OSError):report['errno']=error.errno
        report['exceptionPoints']=[{'file':Path(t.filename).name,'function':t.name,'line':t.lineno}
            for t in traceback.extract_tb(error.__traceback__)[-4:]]
    print('OUF_LIVE_DOCKER_BUNDLE_DIAGNOSIS='+json.dumps(report,sort_keys=True))
    return 0 if report['status']=='LIVE_SHIM_METADATA_CAPTURED' else 1

if __name__=='__main__':raise SystemExit(main())
