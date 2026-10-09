"""Read current R6 task/process/shim custody and native empty guard. Never cleanup or retry."""
import hashlib
import fcntl
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import traceback

PACKAGE=Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-transaction-source-ff13uh3n')
CONTEXT=PACKAGE.parent/'semantic-provider-v2-approved-context-aj1j95xl'
ROOT=PACKAGE.parent/'semantic-provider-v2-transaction-aj1j95xl'
ADAPTER='f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67'

def requested_tasks(raw, cids):
    lines=raw.decode('utf-8').splitlines()
    assert lines and lines[0].split()==['TASK','PID','STATUS'], 'TASK_LIST_HEADER_UNPROVEN'
    rows={}
    for line in lines[1:]:
        fields=line.split()
        assert len(fields)==3 and fields[1].isdigit(), 'TASK_LIST_FORMAT_UNPROVEN'
        cid,pid,status=fields
        if cid in cids:
            assert cid not in rows, 'DUPLICATE_TASK_ID_UNPROVEN'
            rows[cid]={'taskPresent':True,'pid':int(pid),'status':status if status in ('RUNNING','CREATED','STOPPED','PAUSED','PAUSING','UNKNOWN') else 'UNPROVEN'}
    return rows

def process_review(row):
    return {'taskPidPresent':Path('/proc',str(row['pid'])).exists() if row['taskPresent'] and row['pid'] else False,
            'taskPidAbsentRequiredBeforeCleanup':True,'shims':[]}

def main():
    report={'schema':'ouf.semantic-r6-terminal-state-review-read-only.v1','privateKeysRead':0,
        'containerLifecycleOperations':0,'existingConfigurationWrites':0,'signaturesIssued':0,
        'privateValuesPrinted':False,'startAuthorized':False,'notReleaseAcceptance':True,
        'runtimeRootSource':'RETAINED_ADAPTER_PHASE_JOURNAL','defaultsInferred':False}
    phase='READ_EXISTING_APPROVED_R6_RUNTIME_BINDING'
    try:
        assert os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode, 'ISOLATED_ROOT_READER_REQUIRED'
        p=PACKAGE/'provider_transaction_intake.py';fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
        try:raw=os.read(fd,131073)
        finally:os.close(fd)
        assert hashlib.sha256(raw).hexdigest()=='edc3c97d54a9d241c93ea9791f4dffce9984565763c2236ad1644e8b90c4c4b5', 'SEALED_ENTRY_HASH_DRIFT'
        entry={'__name__':'r6_terminal_reader','__file__':str(p)}
        exec(compile(raw,str(p),'exec'),entry);entry['load'](PACKAGE)
        approval=entry['parse'](entry['read'](CONTEXT/'human-approval-binding.json'))
        assert approval['approvalRef']=='OUF_PROVIDER_V2_POST_TERMINAL_ADMISSION_APPROVED_20261009T165118_CEST_R6'
        cfg=entry['parse'](entry['bound']({'path':str(CONTEXT/'execution-configuration.json'),'sha256':approval['configurationHash']}))
        assert cfg['outputRoot']==str(ROOT), 'RETAINED_R6_OUTPUT_SCOPE_DRIFT'
        journal_raw=entry['bound']({'path':str(ROOT/'registry'/ADAPTER/'adapter.json'),
            'sha256':'5b850802dbc61cd8d9d1ccbfe9c75b57917c52222f9d65d43ffc24930c560198'})
        journal=entry['parse'](journal_raw);runtime_root=journal['runtimeRoot']
        assert journal['state']=='DELETING' and type(runtime_root) is str, 'RETAINED_DELETING_RUNTIME_ROOT_REQUIRED'
        root=Path(runtime_root)
        assert root.is_absolute() and '..' not in root.parts and root.is_relative_to('/run') and root!=Path('/run')
        assert str(root.resolve())==runtime_root, 'RETAINED_RUNTIME_ROOT_CANONICAL_DRIFT'
        values=cfg['recordsByRole']['adapter']
        template=entry['parse'](entry['bound'](values['preparerTemplate']))
        runtime=template['candidate']['runtimeBinding']
        from transaction_guard_observation import executable_binding
        from authenticate_provider_transaction import TARGETS
        executable_binding(runtime)
        phase='READ_RUNC_INVENTORY_AT_RETAINED_ROOT'
        result=subprocess.run([runtime['path'],'--root',runtime_root,'list','--format','json'],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        report['runcListExitCode']=result.returncode
        assert result.returncode==0, 'RUNC_INVENTORY_READ_FAILED'
        assert len(result.stdout)<=131072, 'RUNC_INVENTORY_OUTPUT_UNBOUNDED'
        rows=entry['parse'](result.stdout);assert type(rows) is list and len(rows)<=1024
        report['runtimeRootHash']=hashlib.sha256(runtime_root.encode()).hexdigest()
        report['requestedEntriesAtRetainedRoot']={}
        for target in TARGETS.values():
            cid=target['containerId'];matches=[v for v in rows if v.get('id')==cid];assert len(matches)<=1
            row=matches[0] if matches else {}
            report['requestedEntriesAtRetainedRoot'][cid]={'entryPresent':bool(matches),
                'status':row.get('status') if row.get('status') in ('creating','created','running','stopped') else None,
                'pid':row.get('pid') if type(row.get('pid')) is int else None}
        phase='READ_EXPLICIT_DOCKER_CONTAINERD_TASK_METADATA'
        endpoints=[]
        for proc in Path('/proc').iterdir():
            if not proc.name.isdecimal():continue
            try:
                exe=os.readlink(proc/'exe')
                if exe!='/usr/bin/dockerd':continue
                argv=(proc/'cmdline').read_bytes().split(b'\0')
                for index,arg in enumerate(argv):
                    if arg.startswith(b'--containerd='):endpoints.append(arg.split(b'=',1)[1].decode())
                    elif arg==b'--containerd':endpoints.append(argv[index+1].decode())
            except (FileNotFoundError,ProcessLookupError,PermissionError):continue
        assert endpoints==['/run/containerd/containerd.sock'], 'EXPLICIT_DOCKER_CONTAINERD_ENDPOINT_UNPROVEN'
        context=entry['parse'](entry['bound'](values['context']))
        assert context['bundleParent']=='/run/containerd/io.containerd.runtime.v2.task/moby', 'ACCEPTED_TASK_NAMESPACE_UNPROVEN'
        ctr=Path('/usr/bin/ctr');ctr_raw=entry['read'](ctr,True)
        info=ctr.stat();assert info.st_uid==info.st_gid==0 and info.st_mode&0o111 and not info.st_mode&0o022
        report['ctrExecutableHash']=entry['digest'](ctr_raw)
        assert report['ctrExecutableHash']=='8bb9bc5014e0f7623603d6a0dc1f7fedfe5b5a9ea5e265cc00dfbbae23ee984e', 'OBSERVED_CTR_EXECUTABLE_DRIFT'
        wrapper=entry['read']('/usr/local/sbin/ouf-semantic-admitted-v2',True)
        report['installedWrapperHash']=entry['digest'](wrapper)
        assert report['installedWrapperHash']=='cc4645eefedb2301afb6c7ac898716950f866cc5a19086e8c8ec854d26493d8b', 'OBSERVED_R6_WRAPPER_DRIFT'
        def command(args):
            assert entry['read'](ctr,True)==ctr_raw, 'CTR_EXECUTABLE_DRIFT'
            result=subprocess.run([str(ctr),'--address',endpoints[0],'--namespace','moby',*args],
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
            assert len(result.stdout)<=131072, 'CONTAINERD_OUTPUT_UNBOUNDED'
            return result
        result=command(['tasks','list']);assert result.returncode==0, 'CONTAINERD_TASK_LIST_UNPROVEN'
        rows=requested_tasks(result.stdout,{v['containerId'] for v in TARGETS.values()})
        report['containerdRequestedTasks']={}
        for target in TARGETS.values():
            cid=target['containerId'];row=rows.get(cid,{'taskPresent':False,'pid':None,'status':None})
            result=command(['containers','info',cid])
            row['containerMetadataReadExit']=result.returncode
            if result.returncode==0:
                meta=entry['parse'](result.stdout)
                assert meta['ID']==cid, 'CONTAINERD_METADATA_ID_DRIFT'
                row['containerMetadataHash']=entry['digest'](result.stdout)
                runtime_name=meta.get('Runtime',{}).get('Name')
                row['runtimeKind']=runtime_name if runtime_name in ('io.containerd.runc.v2','io.containerd.runtime.v1.linux') else 'UNPROVEN'
            report['containerdRequestedTasks'][cid]=row
        phase='REVIEW_TERMINAL_TASK_PROCESS_AND_SHIM_OWNERSHIP'
        report['terminalTaskReview']={}
        for cid,row in report['containerdRequestedTasks'].items():
            review=process_review(row)
            report['terminalTaskReview'][cid]=review
            for proc in Path('/proc').iterdir():
                if not proc.name.isdecimal():continue
                try:
                    exe=os.readlink(proc/'exe')
                    if not exe.endswith('/containerd-shim-runc-v2'):continue
                    args=(proc/'cmdline').read_bytes().split(b'\0')
                    if b'-id' not in args or args[args.index(b'-id')+1]!=cid.encode():continue
                    cwd=os.readlink(proc/'cwd')
                    assert cwd=='/run/containerd/io.containerd.runtime.v2.task/moby/'+cid, 'EXACT_SHIM_BUNDLE_OWNER_UNPROVEN'
                    assert b'-namespace' in args and args[args.index(b'-namespace')+1]==b'moby', 'EXACT_SHIM_NAMESPACE_UNPROVEN'
                    stat_raw=(proc/'stat').read_bytes()
                    tail=stat_raw[stat_raw.rfind(b')')+2:].split()
                    review['shims'].append({'pid':int(proc.name),'startTicks':int(tail[19]),
                        'exactBundleOwner':True,'exactNamespace':True,'executableHash':entry['digest'](entry['read'](exe,True)),
                        'argvHash':entry['digest'](b'\0'.join(args)), 'bundlePathHash':entry['digest'](cwd.encode())})
                except (FileNotFoundError,ProcessLookupError):continue
            assert len(review['shims'])<=1, 'MULTIPLE_EXACT_SHIMS_UNPROVEN'
        result=command(['version']);assert result.returncode==0, 'CONTAINERD_VERSION_READ_UNPROVEN'
        report['containerdVersions']={}
        section=None
        for line in result.stdout.decode().splitlines():
            stripped=line.strip()
            if stripped in ('Client:','Server:'):section=stripped[:-1]
            if section and stripped.startswith('Version:'):
                version=stripped.split(':',1)[1].strip()
                assert re.fullmatch(r'v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9_.-]+)?',version), 'SYMBOLIC_CONTAINERD_VERSION_REQUIRED'
                report['containerdVersions'][section]=version
        assert set(report['containerdVersions'])=={'Client','Server'}, 'EXACT_CONTAINERD_VERSION_PAIR_REQUIRED'
        phase='OBSERVE_CURRENT_EMPTY_NATIVE_GUARD_WITHOUT_LIFECYCLE'
        from transaction_guard_observation import observe_locked
        pointer=entry['parse'](entry['bound'](cfg['guardPointerBinding']))
        receipt_binding={'path':pointer['receiptFile'],'sha256':pointer['receiptHash']}
        owner_hash='656c23f18e3f3eb4c1ce630f5056be87f7883eab7b048065092dafbd018284a8'
        owner=entry['parse'](entry['bound']({'path':str(Path(receipt_binding['path']).parent/'coordinated-configuration.json'),'sha256':owner_hash}))
        fd=os.open(owner['commonLockFile'],os.O_RDWR|os.O_NOFOLLOW)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            candidates={t['containerId']:{'imageManifestDigest':t['imageManifestDigest'],'runtimeName':'ouf-semantic-admitted-v2'} for t in TARGETS.values()}
            observation=observe_locked(fd,receipt_binding,owner_hash,candidates,cfg['commandBindings'])
            report['nativeEmptyGuardObservation']=observation
        finally:os.close(fd)
        report['allRecordedTaskPidsAbsent']=all(not r['taskPidPresent'] for r in report['terminalTaskReview'].values())
        report['cleanupAuthorized']=False
        report['retainedAdapterJournalHash']=entry['digest'](journal_raw)
        report['retainedOutput']=str(ROOT)
        expected_states={
            'f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67':'90ad7da25dd59e78566b06512e8bf57e4b7022bb101b6e701585ed7a79fcab58',
            '1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916':'7674a0e65ecc160881ecaa65c30c61c1d64b91a3dab78c3c5c9a9183acb762bc'}
        assert observation['candidateStateHashes']==expected_states, 'OBSERVED_R6_CANDIDATE_STATE_DRIFT'
        assert entry['digest'](entry['read']('/usr/local/sbin/ouf-semantic-admitted-v2',True))==report['installedWrapperHash'], 'R6_WRAPPER_CHANGED_DURING_READ'
        report['containerdEndpointSource']='LIVE_DOCKER_EXPLICIT_ARGV'
        report['namespaceSource']='ACCEPTED_CONTEXT_AND_OBSERVED_SHIM_PARENT'
        executable_binding(runtime)
        assert entry['read'](ROOT/'registry'/ADAPTER/'adapter.json')==journal_raw
        report.update(status='R6_TERMINAL_REVIEW_CAPTURED',phase=phase,
            note='Runc inventory is scoped to retained R6 adapter root; task metadata is read separately. No kill/delete/retry.')
    except Exception as error:
        report.update(status='RUNC_READ_ONLY_DIAGNOSIS_BLOCKED',phase=phase,errorType=type(error).__name__,
            reason=str(error) if re.fullmatch('[A-Z][A-Z0-9_]{0,95}',str(error)) else 'RETAINED_RUNC_READ_UNPROVEN',
            exceptionPoints=[{'file':Path(t.filename).name,'function':t.name,'line':t.lineno} for t in traceback.extract_tb(error.__traceback__)[-4:]])
    print('OUF_R6_TERMINAL_STATE_READ_ONLY='+json.dumps(report,sort_keys=True))
    return 0 if report['status']=='R6_TERMINAL_REVIEW_CAPTURED' else 1

if __name__=='__main__':sys.exit(main())
