"""Read retained R4 phase journals and static broker checks; never operate/replay."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import traceback
from types import SimpleNamespace

PACKAGE=Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-transaction-source-ff13uh3n')
CONTEXT=PACKAGE.parent/'semantic-provider-v2-approved-context-kaa8rbxd'
ROOT=PACKAGE.parent/'semantic-provider-v2-transaction-kaa8rbxd'
NAMES=('adapter.json','broker-state.json','deployment.json','admission.json','preexec.json',
    'attestation-emission.json','approval-emission.json','node-signing-claim.json','installer-signing-claim.json',
    'attestation.json','approval.json','creation.json','driver.json','preparer.json','bundle/config.json')

def symbolic(error):
    value=str(error)
    return value if re.fullmatch('[A-Z][A-Z0-9_]{0,95}',value) else 'READ_ONLY_CHECK_UNPROVEN'

def journal_summary(raw):
    value=json.loads(raw)
    result={'sha256':hashlib.sha256(raw).hexdigest()}
    state=value.get('state')
    if state in {'STAGED','CREATING','CREATED','PREPARING','PROTECTED','ADMITTED','READY','STARTING','STARTED','DELETING','DELETED','CLEANED'}:
        result['state']=state
    result['runtimeRootPresent']=type(value.get('runtimeRoot')) is str
    return result

def main():
    report={'schema':'ouf.semantic-r4-broker-read-only.v1','privateKeysRead':0,
        'containerLifecycleOperations':0,'existingConfigurationWrites':0,'signaturesIssued':0,
        'privateValuesPrinted':False,'startAuthorized':False,'notReleaseAcceptance':True,
        'historicalBrokerExceptionCaptured':False,'brokerOperateInvoked':False,'roles':{}}
    phase='VERIFY_R4_RETAINED_CONTEXT'
    try:
        assert os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode
        path=PACKAGE/'provider_transaction_intake.py'
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try:raw=os.read(fd,131073)
        finally:os.close(fd)
        assert hashlib.sha256(raw).hexdigest()=='edc3c97d54a9d241c93ea9791f4dffce9984565763c2236ad1644e8b90c4c4b5'
        entry={'__name__':'r4_read_only_entry','__file__':str(path)}
        exec(compile(raw,str(path),'exec'),entry)
        entry['load'](PACKAGE)
        approval=entry['parse'](entry['read'](CONTEXT/'human-approval-binding.json'))
        assert approval['approvalRef']=='OUF_PROVIDER_V2_BUNDLE_CONTEXT_RECOVERY_HUMAN_APPROVAL_20261009_102223'
        cfg=entry['parse'](entry['bound']({'path':str(CONTEXT/'execution-configuration.json'),'sha256':approval['configurationHash']}))
        assert cfg['outputRoot']==str(ROOT)
        denial=entry['parse'](entry['read'](ROOT/'cohort-activation-denial.json'))
        assert denial['reason']=='COHORT_ADMITTED_RUNNING_STATE_UNPROVEN' and denial['dockerStartRequests']==2
        switched=entry['parse'](entry['read'](ROOT/'runtime-switch-receipt.json'))
        wrapper=entry['read']('/usr/local/sbin/ouf-semantic-admitted-v2',True)
        assert hashlib.sha256(wrapper).hexdigest()==switched['installedWrapperHash']
        report['installedWrapperHash']=switched['installedWrapperHash']
        proposal=entry['parse'](entry['read'](ROOT/'runtime-configuration-proposal.json'))
        receipt=entry['parse'](entry['read'](ROOT/'installation-receipt.json'))
        from authenticate_provider_transaction import TARGETS
        from transaction_guard_observation import executable_binding
        docker=cfg['commandBindings']['docker'];executable_binding(docker)
        phase='READ_CURRENT_DOCKER_AND_RETAINED_PHASE_JOURNALS'
        for role,target in TARGETS.items():
            cid=target['containerId'];root=ROOT/'registry'/cid
            summary={'containerId':cid,'journals':{}}
            report['roles'][role]=summary
            fmt='{"id":{{json .Id}},"image":{{json .Image}},"runtime":{{json .HostConfig.Runtime}},"state":{{json .State}}}'
            result=subprocess.run([docker['path'],'--config',str(ROOT/'activation-docker-cli'),'inspect','--type','container','--format',fmt,cid],
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','DOCKER_HOST':'unix:///var/run/docker.sock'})
            assert result.returncode==0 and len(result.stdout)<=16384
            value=entry['parse'](result.stdout);state=value['state']
            assert value['id']==cid and value['image']==target['imageManifestDigest'] and value['runtime']=='ouf-semantic-admitted-v2'
            safe=re.search(r'SEMANTIC_DOCKER_RUNTIME_BLOCKED_([A-Z0-9_]{1,80})',state.get('Error',''))
            summary['docker']={'stateHash':entry['digest'](entry['encoded'](value)),
                'status':state['Status'] if state['Status'] in ('created','running','exited','dead','removing','paused','restarting') else 'UNPROVEN',
                'running':state['Running'],'pid':state['Pid'],'neverStarted':state['StartedAt'].startswith('0001-'),
                'nativeDenialReason':safe.group(1) if safe else None}
            for name in NAMES:
                p=root/name
                if not os.path.lexists(p):summary['journals'][name]={'present':False};continue
                try:summary['journals'][name]={'present':True,**journal_summary(entry['read'](p))}
                except Exception as error:summary['journals'][name]={'present':True,'errorType':type(error).__name__,'reason':symbolic(error)}
            phase='CHECK_EXISTING_BROKER_LOAD_WITHOUT_OPERATE'
            binding=proposal['candidates'][cid]
            broker_path=Path(binding['admissionConfiguration'])
            assert broker_path==root/'broker.json'
            broker_raw=entry['bound']({'path':str(broker_path),'sha256':binding['admissionConfigurationHash']})
            broker_cfg=entry['parse'](broker_raw)
            source=ROOT/'source/scripts/semantic_provider_deployment_broker.py'
            source_raw=entry['bound']({'path':str(source),'sha256':receipt['fileHashes'][str(source)]})
            module={'__name__':'r4_static_broker_check','__file__':str(source)}
            exec(compile(source_raw,str(source),'exec'),module)
            try:
                loaded,loaded_raw=module['load'](str(broker_path))
                summary['brokerLoad']={'status':'PASS'}
                adapter=entry['parse'](entry['read'](root/'adapter.json'))
                broker_state=entry['parse'](entry['read'](root/'broker-state.json'))
                runtime_root=adapter.get('runtimeRoot') or broker_state.get('runtimeRoot')
                if runtime_root:
                    args=SimpleNamespace(container_id=cid,bundle=str(root/'bundle'),runtime_root=runtime_root,mode='READ_ONLY_NO_OPERATION')
                    broker=module['Broker'](loaded,loaded_raw,str(broker_path),args)
                    broker.record();broker.gate.record()
                    summary['brokerConstructorAndJournalChecks']={'status':'PASS','runtimeRootSource':'RETAINED_PHASE_JOURNAL'}
                else:summary['brokerConstructorAndJournalChecks']={'status':'NOT_RUN','reason':'ACTUAL_RUNTIME_ROOT_UNCAPTURED_NO_DEFAULT_INFERRED'}
            except Exception as error:
                summary['brokerStaticCheckDenial']={'errorType':type(error).__name__,'reason':symbolic(error),
                    'exceptionPoints':[{'file':Path(t.filename).name,'function':t.name,'line':t.lineno} for t in traceback.extract_tb(error.__traceback__)[-4:]]}
        executable_binding(docker)
        report.update(status='R4_READ_ONLY_PHASES_CAPTURED',phase=phase)
    except Exception as error:
        report.update(status='R4_READ_ONLY_DIAGNOSIS_BLOCKED',phase=phase,errorType=type(error).__name__,reason=symbolic(error),
            exceptionPoints=[{'file':Path(t.filename).name,'function':t.name,'line':t.lineno} for t in traceback.extract_tb(error.__traceback__)[-4:]])
    print('OUF_R4_BROKER_READ_ONLY='+json.dumps(report,sort_keys=True))
    return 0 if report['status']=='R4_READ_ONLY_PHASES_CAPTURED' else 1

if __name__=='__main__':sys.exit(main())
