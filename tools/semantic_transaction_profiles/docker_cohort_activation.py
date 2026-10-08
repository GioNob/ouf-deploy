"""Two-CID concurrent Docker activation through the authenticated named runtime.

No standalone CLI. The sealed root transaction must supply accepted complete
records and fixed target bindings. All actual native admission remains inside
the named runtime/broker/node/installer path, not a caller-provided CI flag.
"""
from concurrent.futures import ThreadPoolExecutor
import fcntl
import os
from pathlib import Path
import re
import subprocess
import tempfile

from authenticate_provider_transaction import TARGETS, TransactionDenied, build_install_plan, require
from assemble_provider_profiles import digest,encoded
from authenticated_runtime_switch import make_locked_switch_verifier
from guarded_runtime_switch import custody,wrapper_bytes
from publish_provider_transaction import publish_once,sync
from transaction_guard_observation import private_binding,executable_binding
from tools.semantic_provider_deployment_authentication import decode,DetachedAuthenticator,VerificationBudget


def activate(root,records,authority,sources,observer_raw,python_binding,crypto,empty_adapter,
             receipt_binding,expected_owner_hash,command_bindings,
             wrapper_path='/usr/local/sbin/ouf-semantic-admitted-v2'):
    """Request both starts together only after fresh locked acceptance checks.

    Neither common guard nor adapter scheduling/per-CID locks may be held while
    invoking Docker: the production runtime must obtain those locks itself.
    No retries/automatic rollback/lease activation are performed. Any partial or
    uncertain outcome retains the claim and requires explicit scoped recovery.
    """
    root=Path(root);stage='AUTHENTICATE_DOCKER_COHORT';claimed=False;requests=[];facts={};codes={}
    try:
        require(os.geteuid()==0,stage,'ROOT_COHORT_TRANSACTION_REQUIRED')
        require(not os.path.lexists(root/'cohort-activation-claim.json'),stage,'DO_NOT_REPLAY_DOCKER_COHORT')
        verifier=DetachedAuthenticator(crypto['policyBinding'],crypto['signatureDirectory'],crypto['opensslBinding'],
                                         budget=VerificationBudget(18))
        plan=build_install_plan(str(root),str(root/'source'),records,authority,sources,observer_raw,
                                python_binding,crypto,verifier,empty_adapter)
        proposed=wrapper_bytes(python_binding['path'],root/'source',root/'runtime-configuration-proposal.json')
        require(custody(wrapper_path,0o755)[0]==proposed,stage,'AUTHENTICATED_RUNTIME_WRAPPER_NOT_INSTALLED')
        switched=decode(custody(root/'runtime-switch-receipt.json',0o600)[0],131072)
        require(switched['status']=='WRAPPER_SWITCHED' and switched['installedWrapperHash']==digest(proposed),
                stage,'DURABLE_RUNTIME_SWITCH_READBACK_REQUIRED')
        guard_receipt=decode(private_binding(receipt_binding),131072)
        owner=decode(private_binding({'path':str(Path(guard_receipt['directory'])/'coordinated-configuration.json'),
                                     'sha256':expected_owner_hash}),131072)
        locked=make_locked_switch_verifier(root,records,authority,sources,observer_raw,python_binding,crypto,
            empty_adapter,receipt_binding,expected_owner_hash,command_bindings)
        fd=os.open(owner['commonLockFile'],os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);locked(fd,'BEFORE_COHORT_CLAIM')
            require(custody(wrapper_path,0o755)[0]==proposed,stage,'RUNTIME_WRAPPER_CHANGED_BEFORE_COHORT')
            publish_once(root/'cohort-activation-claim.json',encoded({
                'schema':'ouf.semantic-provider-cohort-activation-claim.v1','state':'ACTIVATING',
                'containerIds':sorted(v['containerId'] for v in TARGETS.values()),
                'runtimeConfigurationHash':digest(encoded(plan['adapterConfiguration'])),
                'installedWrapperHash':digest(proposed),'notReleaseAcceptance':True}))
            claimed=True;stage='RECHECK_BEFORE_DOCKER_COHORT_START';locked(fd,'BEFORE_COHORT_START')
        finally:os.close(fd)
        # No common/native/adapter scheduling lock is held below this point.
        stage='REQUEST_CONTROLLED_DOCKER_COHORT_START'
        docker=command_bindings['docker'];binary=executable_binding(docker)
        cfgdir=root/'activation-docker-cli';cfgdir.mkdir(mode=0o700);sync(root)
        def command(args,timeout=45):
            require(executable_binding(docker)==binary,stage,'DOCKER_EXECUTABLE_CHANGED_BEFORE_OPERATION')
            with tempfile.TemporaryFile() as out:
                result=subprocess.run([docker['path'],'--config',str(cfgdir),*args],stdin=subprocess.DEVNULL,
                    stdout=out,stderr=subprocess.DEVNULL,timeout=timeout,
                    env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','DOCKER_HOST':'unix:///var/run/docker.sock'})
                out.seek(0);raw=out.read(16385)
            require(len(raw)<=16384,stage,'DOCKER_COHORT_OUTPUT_UNBOUNDED')
            return result.returncode,raw
        cids=sorted(v['containerId'] for v in TARGETS.values())
        def start(cid):
            requests.append(cid)
            try:
                code,raw=command(['start',cid]);return code,code==0 and raw.strip()==cid.encode(),None
            except Exception as error:return None,False,type(error).__name__
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures={cid:pool.submit(start,cid) for cid in cids}
            for cid,future in futures.items():
                code,ok,error_type=future.result();codes[cid]={'exitCode':code,'exactCidAcknowledged':ok,'errorType':error_type}
        stage='VERIFY_CONTROLLED_DOCKER_COHORT_READBACK'
        fmt='{"id":{{json .Id}},"image":{{json .Image}},"runtime":{{json .HostConfig.Runtime}},"state":{{json .State}}}'
        admitted={}
        for role,target in TARGETS.items():
            cid=target['containerId'];code,raw=command(['inspect','--type','container','--format',fmt,cid],10)
            require(code==0,stage,'COHORT_NATIVE_STATE_READBACK_FAILED',role)
            value=decode(raw,16384);state=value['state'];journal_path=root/'registry'/cid/'adapter.json'
            journal_raw=custody(journal_path,0o600)[0];journal=decode(journal_raw,131072)
            expected_journal=decode(plan['files'][str(journal_path)],131072)
            error=state.get('Error','');safe=re.search(r'SEMANTIC_DOCKER_RUNTIME_BLOCKED_([A-Z0-9_]{1,80})',error)
            facts[cid]={'stateHash':digest(encoded(value)),'adapterJournalHash':digest(journal_raw),
                'adapterState':journal.get('state') if journal.get('state') in ('STAGED','CREATING','CREATED','PREPARING','STARTING','STARTED','DELETING','DELETED') else 'UNPROVEN',
                'nativeDenialReason':safe.group(1) if safe else None}
            admitted[role]=(codes[cid]['exactCidAcknowledged'] and value['id']==cid
                    and value['image']==target['imageManifestDigest'] and value['runtime']=='ouf-semantic-admitted-v2'
                    and state['Running'] is True and state['Status']=='running' and type(state['Pid']) is int and state['Pid']>0
                    and not state['StartedAt'].startswith('0001-') and journal['state']=='STARTED'
                    and journal['containerId']==cid and journal['configurationHash']==expected_journal['configurationHash'])
        for role,accepted in admitted.items():
            require(accepted,stage,'COHORT_ADMITTED_RUNNING_STATE_UNPROVEN',role)
        require(custody(wrapper_path,0o755)[0]==proposed and executable_binding(docker)==binary,
                stage,'RUNTIME_CUSTODY_CHANGED_AFTER_COHORT')
        report={'schema':'ouf.semantic-provider-cohort-activation.v1','status':'TWO_CANDIDATE_RUNTIME_STARTED',
            'dockerStartRequests':len(requests),'candidates':facts,'providerLeaseIssuedByOrchestrator':False,
            'daemonRestartRequested':False,'notReleaseAcceptance':True}
        publish_once(root/'cohort-activation-receipt.json',encoded(report));return report
    except Exception as error:
        diagnosis=error.diagnosis.copy() if isinstance(error,TransactionDenied) else {
            'status':'BLOCKED','stage':stage,'reason':'CONTROLLED_DOCKER_COHORT_UNPROVEN','secretValuesPrinted':False}
        diagnosis.update(evidenceDirectory=str(root),doNotRerunApply=claimed or os.path.lexists(root/'cohort-activation-claim.json'),
            dockerStartRequests=len(requests),dockerResults=codes,candidateObservations=facts,
            containerLifecycleOperations=None if requests else 0,privateKeysRead=None if requests else 0,
            cohortOutcome='UNPROVEN' if requests else 'NOT_REQUESTED',automaticRetryPerformed=False,notReleaseAcceptance=True)
        if isinstance(error,OSError):diagnosis.update(errorType=type(error).__name__,errno=error.errno)
        if claimed:
            try:publish_once(root/'cohort-activation-denial.json',encoded(diagnosis))
            except Exception:diagnosis['diagnosisSaved']=False
        failure=TransactionDenied(stage,diagnosis['reason']);failure.diagnosis=diagnosis;raise failure from None
