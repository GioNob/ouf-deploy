"""Inspect runc at the actual root retained by southbound; no lifecycle or replay."""
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import traceback

PACKAGE=Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-transaction-source-ff13uh3n')
CONTEXT=PACKAGE.parent/'semantic-provider-v2-approved-context-kaa8rbxd'
ROOT=PACKAGE.parent/'semantic-provider-v2-transaction-kaa8rbxd'
SOUTH='1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916'

def main():
    report={'schema':'ouf.semantic-r4-retained-runc-read-only.v1','privateKeysRead':0,
        'containerLifecycleOperations':0,'existingConfigurationWrites':0,'signaturesIssued':0,
        'privateValuesPrinted':False,'startAuthorized':False,'notReleaseAcceptance':True,
        'runtimeRootSource':'RETAINED_SOUTHBOUND_PHASE_JOURNAL','defaultsInferred':False}
    phase='READ_EXISTING_APPROVED_R4_RUNTIME_BINDING'
    try:
        assert os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode, 'ISOLATED_ROOT_READER_REQUIRED'
        p=PACKAGE/'provider_transaction_intake.py';fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
        try:raw=os.read(fd,131073)
        finally:os.close(fd)
        assert hashlib.sha256(raw).hexdigest()=='edc3c97d54a9d241c93ea9791f4dffce9984565763c2236ad1644e8b90c4c4b5', 'SEALED_ENTRY_HASH_DRIFT'
        entry={'__name__':'r4_runc_reader','__file__':str(p)}
        exec(compile(raw,str(p),'exec'),entry);entry['load'](PACKAGE)
        approval=entry['parse'](entry['read'](CONTEXT/'human-approval-binding.json'))
        assert approval['approvalRef']=='OUF_PROVIDER_V2_BUNDLE_CONTEXT_RECOVERY_HUMAN_APPROVAL_20261009_102223'
        cfg=entry['parse'](entry['bound']({'path':str(CONTEXT/'execution-configuration.json'),'sha256':approval['configurationHash']}))
        assert cfg['outputRoot']==str(ROOT), 'RETAINED_R4_OUTPUT_SCOPE_DRIFT'
        journal_raw=entry['bound']({'path':str(ROOT/'registry'/SOUTH/'adapter.json'),
            'sha256':'b30e44bc9eb98cc6964a2c715e4601c87e834e5a8ac160a50517f4c9cd6a8214'})
        journal=entry['parse'](journal_raw);runtime_root=journal['runtimeRoot']
        assert journal['state']=='DELETING' and type(runtime_root) is str, 'RETAINED_DELETING_RUNTIME_ROOT_REQUIRED'
        root=Path(runtime_root)
        assert root.is_absolute() and '..' not in root.parts and root.is_relative_to('/run') and root!=Path('/run')
        assert str(root.resolve())==runtime_root, 'RETAINED_RUNTIME_ROOT_CANONICAL_DRIFT'
        values=cfg['recordsByRole']['southbound']
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
        executable_binding(runtime)
        assert entry['read'](ROOT/'registry'/SOUTH/'adapter.json')==journal_raw
        report.update(status='RETAINED_RUNC_INVENTORY_CAPTURED',phase=phase,
            note='Absence is scoped to the retained southbound runtime root; no other root is inferred.')
    except Exception as error:
        report.update(status='RUNC_READ_ONLY_DIAGNOSIS_BLOCKED',phase=phase,errorType=type(error).__name__,
            reason=str(error) if re.fullmatch('[A-Z][A-Z0-9_]{0,95}',str(error)) else 'RETAINED_RUNC_READ_UNPROVEN',
            exceptionPoints=[{'file':Path(t.filename).name,'function':t.name,'line':t.lineno} for t in traceback.extract_tb(error.__traceback__)[-4:]])
    print('OUF_R4_RETAINED_RUNC_READ_ONLY='+json.dumps(report,sort_keys=True))
    return 0 if report['status']=='RETAINED_RUNC_INVENTORY_CAPTURED' else 1

if __name__=='__main__':sys.exit(main())
