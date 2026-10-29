"""Read retained R5 phase journals and redacted broker exceptions; never operate/replay."""
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
CONTEXT=PACKAGE.parent/'semantic-provider-v2-approved-context-155oj3tc'
ROOT=PACKAGE.parent/'semantic-provider-v2-transaction-155oj3tc'
NAMES=('adapter.json','broker-state.json','deployment.json','admission.json','preexec.json',
    'attestation-emission.json','approval-emission.json','node-signing-claim.json','installer-signing-claim.json',
    'attestation.json','approval.json','creation.json','driver.json','preparer.json','bundle/config.json')
DENIAL_NAMES=tuple('broker-denial-'+phase+'.json' for phase in ('authorize-create','record-created','cohort-ready','prepare','cleanup'))

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

def safe_denial(value):
    assert value.get('schema')=='ouf.semantic-broker-phase-denial.v1'
    assert value.get('secretValuesPrinted') is False and value.get('notReleaseAcceptance') is True
    phase=value.get('phase')
    assert phase in ('authorize-create','record-created','cohort-ready','prepare','cleanup','UNKNOWN')
    reason=value.get('reason');kind=value.get('errorType')
    assert isinstance(reason,str) and re.fullmatch('[A-Z][A-Z0-9_]{0,95}',reason)
    assert isinstance(kind,str) and re.fullmatch('[A-Za-z][A-Za-z0-9_]{0,63}',kind)
    points=value.get('exceptionPoints');assert isinstance(points,list) and len(points)<=4
    safe=[]
    for point in points:
        name=point.get('file');function=point.get('function');line=point.get('line')
        assert isinstance(name,str) and re.fullmatch('[A-Za-z0-9_.-]{1,120}',name) and name not in ('.','..')
        assert isinstance(function,str) and re.fullmatch('[A-Za-z0-9_<>]{1,80}',function)
        assert type(line) is int and 0<line<100000
        safe.append({'file':name,'function':function,'line':line})
    return {'phase':phase,'reason':reason,'errorType':kind,'exceptionPoints':safe,
            'diagnosisSaved':value.get('diagnosisSaved') is True,'secretValuesPrinted':False}

def main():
    report={'schema':'ouf.semantic-r5-broker-read-only.v1','privateKeysRead':0,
        'containerLifecycleOperations':0,'existingConfigurationWrites':0,'signaturesIssued':0,
        'privateValuesPrinted':False,'startAuthorized':False,'notReleaseAcceptance':True,
        'historicalBrokerExceptionCaptured':False,'brokerOperateInvoked':False,'roles':{}}
    phase='VERIFY_R5_RETAINED_CONTEXT'
    try:
        assert os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode
        path=PACKAGE/'provider_transaction_intake.py'
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try:raw=os.read(fd,131073)
        finally:os.close(fd)
        assert hashlib.sha256(raw).hexdigest()=='edc3c97d54a9d241c93ea9791f4dffce9984565763c2236ad1644e8b90c4c4b5'
        entry={'__name__':'r5_read_only_entry','__file__':str(path)}
        exec(compile(raw,str(path),'exec'),entry)
        entry['load'](PACKAGE)
        approval=entry['parse'](entry['read'](CONTEXT/'human-approval-binding.json'))
        assert approval['approvalRef']=='OUF_PROVIDER_V2_BROKER_SOURCE_RECOVERY_HUMAN_APPROVAL_20261009_130246'
        cfg=entry['parse'](entry['bound']({'path':str(CONTEXT/'execution-configuration.json'),'sha256':approval['configurationHash']}))
        assert cfg['outputRoot']==str(ROOT)
        denial=entry['parse'](entry['read'](ROOT/'cohort-activation-denial.json'))
        assert denial['reason']=='COHORT_ADMITTED_RUNNING_STATE_UNPROVEN' and denial['dockerStartRequests']==2
        switched=entry['parse'](entry['read'](ROOT/'runtime-switch-receipt.json'))
        wrapper=entry['read']('/usr/local/sbin/ouf-semantic-admitted-v2',True)
        assert hashlib.sha256(wrapper).hexdigest()==switched['installedWrapperHash']
        report['installedWrapperHash']=switched['installedWrapperHash']
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
            summary['retainedBrokerDenials']={}
            phase='READ_RETAINED_R5_BROKER_DENIALS'
            for name in DENIAL_NAMES:
                path=root/name
                if not os.path.lexists(path):
                    summary['retainedBrokerDenials'][name]={'present':False}
                    continue
                raw=entry['read'](path)
                summary['retainedBrokerDenials'][name]={'present':True,'sha256':entry['digest'](raw),**safe_denial(entry['parse'](raw))}
                report['historicalBrokerExceptionCaptured']=True
        executable_binding(docker)
        report.update(status='R5_READ_ONLY_PHASES_CAPTURED',phase=phase)
    except Exception as error:
        report.update(status='R5_READ_ONLY_DIAGNOSIS_BLOCKED',phase=phase,errorType=type(error).__name__,reason=symbolic(error),
            exceptionPoints=[{'file':Path(t.filename).name,'function':t.name,'line':t.lineno} for t in traceback.extract_tb(error.__traceback__)[-4:]])
    print('OUF_R5_BROKER_READ_ONLY='+json.dumps(report,sort_keys=True))
    return 0 if report['status']=='R5_READ_ONLY_PHASES_CAPTURED' else 1

if __name__=='__main__':sys.exit(main())
