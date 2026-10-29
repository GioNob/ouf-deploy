"""Compare exact requested containerd tasks and runc at retained R5 adapter root; read only."""
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import traceback

PACKAGE=Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-transaction-source-ff13uh3n')
CONTEXT=PACKAGE.parent/'semantic-provider-v2-approved-context-155oj3tc'
ROOT=PACKAGE.parent/'semantic-provider-v2-transaction-155oj3tc'
ADAPTER='f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67'

def main():
    report={'schema':'ouf.semantic-r5-containerd-runc-inventory-read-only.v1','privateKeysRead':0,
        'containerLifecycleOperations':0,'existingConfigurationWrites':0,'signaturesIssued':0,
        'privateValuesPrinted':False,'startAuthorized':False,'notReleaseAcceptance':True,
        'runtimeRootSource':'RETAINED_ADAPTERBOUND_PHASE_JOURNAL','defaultsInferred':False}
    phase='READ_EXISTING_APPROVED_R5_RUNTIME_BINDING'
    try:
        assert os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode, 'ISOLATED_ROOT_READER_REQUIRED'
        p=PACKAGE/'provider_transaction_intake.py';fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
        try:raw=os.read(fd,131073)
        finally:os.close(fd)
        assert hashlib.sha256(raw).hexdigest()=='edc3c97d54a9d241c93ea9791f4dffce9984565763c2236ad1644e8b90c4c4b5', 'SEALED_ENTRY_HASH_DRIFT'
        entry={'__name__':'r5_runc_reader','__file__':str(p)}
        exec(compile(raw,str(p),'exec'),entry);entry['load'](PACKAGE)
        approval=entry['parse'](entry['read'](CONTEXT/'human-approval-binding.json'))
        assert approval['approvalRef']=='OUF_PROVIDER_V2_BROKER_SOURCE_RECOVERY_HUMAN_APPROVAL_20261009_130246'
        cfg=entry['parse'](entry['bound']({'path':str(CONTEXT/'execution-configuration.json'),'sha256':approval['configurationHash']}))
        assert cfg['outputRoot']==str(ROOT), 'RETAINED_R5_OUTPUT_SCOPE_DRIFT'
        journal_raw=entry['bound']({'path':str(ROOT/'registry'/ADAPTER/'adapter.json'),
            'sha256':'845f651d465db7371b0323dff59e34a1fa7eb745ce4187d77dce5c2432eb013f'})
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
        def command(args):
            assert entry['read'](ctr,True)==ctr_raw, 'CTR_EXECUTABLE_DRIFT'
            result=subprocess.run([str(ctr),'--address',endpoints[0],'--namespace','moby',*args],
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
            assert len(result.stdout)<=131072, 'CONTAINERD_OUTPUT_UNBOUNDED'
            return result
        result=command(['tasks','list']);assert result.returncode==0, 'CONTAINERD_TASK_LIST_UNPROVEN'
        rows={}
        for line in result.stdout.decode('utf-8').splitlines()[1:]:
            fields=line.split();assert len(fields)==3 and fields[1].isdigit(), 'TASK_LIST_FORMAT_UNPROVEN'
            cid,pid,status=fields
            if cid in [v['containerId'] for v in TARGETS.values()]:
                assert cid not in rows, 'DUPLICATE_TASK_ID_UNPROVEN'
                rows[cid]={'taskPresent':True,'pid':int(pid),'status':status if status in ('RUNNING','CREATED','STOPPED','PAUSED','PAUSING','UNKNOWN') else 'UNPROVEN'}
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
        report['containerdEndpointSource']='LIVE_DOCKER_EXPLICIT_ARGV'
        report['namespaceSource']='ACCEPTED_CONTEXT_AND_OBSERVED_SHIM_PARENT'
        executable_binding(runtime)
        assert entry['read'](ROOT/'registry'/ADAPTER/'adapter.json')==journal_raw
        report.update(status='R5_TASK_INVENTORIES_CAPTURED',phase=phase,
            note='Runc inventory is scoped to retained R5 adapter root; task metadata is read separately. No kill/delete/retry.')
    except Exception as error:
        report.update(status='RUNC_READ_ONLY_DIAGNOSIS_BLOCKED',phase=phase,errorType=type(error).__name__,
            reason=str(error) if re.fullmatch('[A-Z][A-Z0-9_]{0,95}',str(error)) else 'RETAINED_RUNC_READ_UNPROVEN',
            exceptionPoints=[{'file':Path(t.filename).name,'function':t.name,'line':t.lineno} for t in traceback.extract_tb(error.__traceback__)[-4:]])
    print('OUF_R5_TASK_INVENTORY_READ_ONLY='+json.dumps(report,sort_keys=True))
    return 0 if report['status']=='R5_TASK_INVENTORIES_CAPTURED' else 1

if __name__=='__main__':sys.exit(main())
