"""Fixed R7 diagnostic: retained records, current stopped rootfs, no admission.

Reuse the existing offline image and exact v1 sealer. If Docker's rootfs is not
mounted, hold one stopped export while observing its underlying filesystem.
Never unpack the export, enter the container, read private bind contents,
operate the broker, sign, clean up tasks or change accepted seals.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import tempfile
import time
import traceback
import types
from contextlib import contextmanager

BASE=Path('/etc/ouf/deploy-snapshots')
ORIGINAL=BASE/'semantic-provider-v2-transaction-source-ff13uh3n'
CONTEXT=BASE/'semantic-provider-v2-approved-context-cbuyoyo2'
OUTPUT=BASE/'semantic-provider-v2-transaction-cbuyoyo2'
OFFLINE=BASE/'semantic-provider-v2-offline-rootfs-s3BU0nDX'
ORIGINAL_ENTRY='edc3c97d54a9d241c93ea9791f4dffce9984565763c2236ad1644e8b90c4c4b5'
R7_ENTRY='a4e9c02915cc32ab839456de57f88e57d42aa607922ba6db8a320fd27bfdc240'
OPERATOR_DENIAL='636659ed76cbef4f45ad9838dff9cf1706b4f53ee07b9aafc159e2cfa3a056e2'
CLOSURE='4b9fbd3149b417a2a696302784aa54d0569b5e87ddc66ac439c153c9ab16bc02'
OWNER='656c23f18e3f3eb4c1ce630f5056be87f7883eab7b048065092dafbd018284a8'
RUNTIME_ROOT_HASH='c64c266a92b2d9ff052a8f2b817ee730406b2ddde47d550a52effb822b181342'
ROLE_IDS={'adapter':'f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67',
          'southbound':'1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916'}
OFFLINE_SEALS={'adapter':'8a67afc590854316165176c39fbc0d393bb9b38ab6662430d2a36d3313858cf8',
               'southbound':'ec013e0317560153aece8e08a393442c95aaa13f64e3df274c61987953e546d8'}
IMAGE_SEALS={'adapter':'7984421ed76f37ae43681fd369b900c173e2e70a143f93517fed1c434ef578d9',
             'southbound':'e979252f1b43958071d5e497c3753058c76a4071ec92df678299b0bf5c71cfea'}
PHASE='VERIFY_EXACT_RETAINED_R7_CONTEXT'
DIAGNOSTIC=None


def require(value,reason):
    if not value:raise ValueError(reason)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def symbolic(error):
    return str(error) if re.fullmatch('[A-Z][A-Z0-9_]{0,95}',str(error)) else 'R7_READ_UNPROVEN'
def save(path,value):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb',closefd=False) as stream:stream.write(encoded(value));stream.flush();os.fsync(fd)
    finally:os.close(fd)


class ReadBudget:
    def __init__(self):self.deadline=time.monotonic()+180
    def check(self):require(time.monotonic()<self.deadline,'DIAGNOSTIC_READ_DEADLINE_MISSED')


def entries(sealer,path,limits):
    result={};original=sealer.__globals__['encoded']
    def record(item):
        require(item['path'] not in result,'DUPLICATE_SEAL_ENTRY')
        result[item['path']]=item
        return original(item)
    clone=types.FunctionType(sealer.__code__,{**sealer.__globals__,'encoded':record},
                             sealer.__name__,sealer.__defaults__,sealer.__closure__)
    return clone(path,limits,ReadBudget()),result


def image_view(records,expected=False):
    result={}
    for path,item in records.items():
        value=dict(item)
        if value['kind']=='directory':value.pop('links')
        if path=='' and expected:value['mode']=0o755
        result[path]=value
    return result


def image_digest(records):
    h=hashlib.sha256(b'OUF-IMAGE-EQUIVALENCE\x00V1\x00')
    for path in sorted(records):
        raw=encoded(records[path]);h.update(len(raw).to_bytes(4,'big'));h.update(raw)
    return h.hexdigest()


def differences(expected,actual,oci,max_samples=40):
    destinations=[m['destination'].lstrip('/') for m in oci['mounts']]
    cwd=oci['process']['cwd'].lstrip('/')
    counts={};samples=[];total=structural=0
    for path in sorted(set(expected)|set(actual)):
        left=expected.get(path);right=actual.get(path)
        if left==right:continue
        total+=1
        if left is None:fields=['UNEXPECTED_ENTRY']
        elif right is None:fields=['MISSING_ENTRY']
        else:fields=[k for k in sorted(set(left)|set(right)) if k!='path' and left.get(k)!=right.get(k)]
        for field in fields:counts[field]=counts.get(field,0)+1
        relation=bool(path) and any(v==path or v.startswith(path+'/') for v in destinations+[cwd])
        if left is None and relation:structural+=1
        if len(samples)<max_samples:
            value={'imagePath':path[:512] or '.', 'differentFields':fields,
                   'declaredMountOrCwdPathOrAncestor':relation}
            for label,item in (('expected',left),('actual',right)):
                if item is not None:value[label]={k:item[k] for k in ('kind','mode','uid','gid','links','size') if k in item}
            samples.append(value)
    return {'differentEntryCount':total,'fieldCounts':counts,'samples':samples,
            'samplesTruncated':total>max_samples,'unexpectedDeclaredMountOrCwdEntries':structural,
            'fileContentsPrinted':False,'contentHashesPrinted':False,'xattrValuesPrinted':False,
            'symlinkTargetsPrinted':False,'acceptanceGranted':False}


def mount_rows(raw,root):
    require(len(raw)<=1048576,'MOUNTINFO_UNBOUNDED')
    root=Path(root);exact=[]
    def decode(value):return re.sub(r'\\([0-7]{3})',lambda m:chr(int(m.group(1),8)),value)
    for line in raw.decode().splitlines():
        before,after=line.split(' - ',1);fields=before.split();tail=after.split()
        mount=Path(decode(fields[4]))
        require(not (mount!=root and mount.is_relative_to(root)),'PRIVATE_SUBMOUNT_CONTENT_MUST_NOT_BE_READ')
        if mount==root:exact.append({'mountId':int(fields[0]),'filesystem':tail[0]})
    require(len(exact)<=1,'AMBIGUOUS_ROOTFS_MOUNT')
    if exact:require(exact[0]['filesystem']=='overlay','EXACT_OVERLAY_ROOTFS_REQUIRED')
    return exact


def current_mount(root):
    with open('/proc/self/mountinfo','rb') as stream:raw=stream.read(1048577)
    return mount_rows(raw,root)


@contextmanager
def stopped_view(docker,config,cid,root,report):
    initial=current_mount(root)
    if initial:
        yield root
        require(current_mount(root)==initial,'ROOTFS_MOUNT_CHANGED_DURING_READ')
        return
    # Docker export acquires/releases its rootfs mount; it never creates a task.
    # Discard the tar stream after the direct metadata/content seal has finished.
    process=subprocess.Popen([docker,'--host','unix:///var/run/docker.sock','--config',str(config),'export',cid],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    report['stoppedContainerExports']+=1
    selector=None
    try:
        end=time.monotonic()+20
        while not current_mount(root):
            require(process.poll() is None and time.monotonic()<end,'EXPORT_ROOTFS_NOT_OBSERVABLE')
            time.sleep(.05)
        mount=current_mount(root)
        yield root
        require(current_mount(root)==mount and process.poll() is None,'EXPORT_MOUNT_CHANGED_DURING_READ')
        selector=selectors.DefaultSelector();selector.register(process.stdout,selectors.EVENT_READ)
        total=0;end=time.monotonic()+60
        while True:
            require(time.monotonic()<end,'EXPORT_DRAIN_TIMEOUT')
            if not selector.select(.2):continue
            raw=os.read(process.stdout.fileno(),65536)
            if not raw:break
            total+=len(raw);require(total<=17179869184,'EXPORT_BYTES_UNBOUNDED')
        require(process.wait(timeout=10)==0,'STOPPED_EXPORT_FAILED')
    finally:
        if selector is not None:selector.close()
        process.stdout.close()
        if process.poll() is None:
            process.terminate()
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
        end=time.monotonic()+10
        while current_mount(root):
            require(time.monotonic()<end,'EXPORT_ROOTFS_MOUNT_RETAINED')
            time.sleep(.05)


def task_rows(raw):
    lines=raw.decode().splitlines();require(lines and lines[0].split()==['TASK','PID','STATUS'],'TASK_HEADER_UNPROVEN')
    result={}
    for line in lines[1:]:
        fields=line.split();require(len(fields)==3 and fields[1].isdigit(),'TASK_ROW_UNPROVEN')
        cid,pid,status=fields
        if cid in ROLE_IDS.values():
            require(cid not in result,'DUPLICATE_TASK_UNPROVEN')
            result[cid]={'taskPresent':True,'pid':int(pid),'status':status if status in ('STOPPED','CREATED','RUNNING','PAUSED','UNKNOWN') else 'UNPROVEN',
                         'taskPidPresent':Path('/proc',pid).exists() if int(pid)>0 else False}
    return {cid:result.get(cid,{'taskPresent':False,'pid':None,'status':None,'taskPidPresent':False}) for cid in ROLE_IDS.values()}


def process_metadata(read):
    endpoints=[];shims={cid:[] for cid in ROLE_IDS.values()}
    for proc in Path('/proc').iterdir():
        if not proc.name.isdecimal():continue
        try:
            exe=os.readlink(proc/'exe')
            if exe!='/usr/bin/dockerd' and not exe.endswith('/containerd-shim-runc-v2'):continue
            with open(proc/'cmdline','rb') as stream:raw=stream.read(16385)
            require(len(raw)<=16384,'PROCESS_ARGUMENTS_UNBOUNDED');argv=raw.split(b'\0')
            if exe=='/usr/bin/dockerd':
                for index,arg in enumerate(argv):
                    if arg.startswith(b'--containerd='):endpoints.append(arg.split(b'=',1)[1].decode())
                    elif arg==b'--containerd':endpoints.append(argv[index+1].decode())
                continue
            if b'-id' not in argv:continue
            cid=argv[argv.index(b'-id')+1].decode()
            if cid not in shims:continue
            cwd=os.readlink(proc/'cwd')
            require(cwd=='/run/containerd/io.containerd.runtime.v2.task/moby/'+cid,'EXACT_SHIM_BUNDLE_OWNER_UNPROVEN')
            require(b'-namespace' in argv and argv[argv.index(b'-namespace')+1]==b'moby','EXACT_SHIM_NAMESPACE_UNPROVEN')
            state=(proc/'stat').read_bytes();tail=state[state.rfind(b')')+2:].split()
            shims[cid].append({'pid':int(proc.name),'startTicks':int(tail[19]),'exactBundleOwner':True,'exactNamespace':True,
                'executableHash':sha(read(exe,True)),'argvHash':sha(raw),'bundlePathHash':sha(cwd.encode())})
        except (FileNotFoundError,ProcessLookupError):continue
    require(endpoints==['/run/containerd/containerd.sock'],'LIVE_DOCKER_EXPLICIT_ENDPOINT_DRIFT')
    require(all(len(rows)<=1 for rows in shims.values()),'MULTIPLE_EXACT_SHIMS_UNPROVEN')
    return shims


def main():
    global PHASE,DIAGNOSTIC
    report={'schema':'ouf.semantic-r7-rootfs-read-only.v1','privateKeysRead':0,'signaturesIssued':0,
        'containerLifecycleOperations':0,'dockerStartRequests':0,'stoppedContainerExports':0,
        'existingConfigurationWrites':0,'providerCalls':0,'brokerOperateInvoked':False,
        'privateValuesPrinted':False,'startAuthorized':False,'cleanupAuthorized':False,
        'notReleaseAcceptance':True,'historicalObservedRootfsSealRetained':False,'roles':{}}
    try:
        require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode and len(sys.argv)==1,'ISOLATED_FIXED_ROOT_READER_REQUIRED')
        os.umask(0o077)
        path=ORIGINAL/'provider_transaction_intake.py'
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:raw=os.read(fd,131073)
        finally:os.close(fd)
        require(sha(raw)==ORIGINAL_ENTRY,'ORIGINAL_PRIVATE_READER_DRIFT')
        entry={'__name__':'r7_read_only_entry','__file__':str(path)};exec(compile(raw,str(path),'exec'),entry)
        require(entry['read'](path)==raw,'ORIGINAL_READER_CUSTODY_DRIFT')
        read,parse,bound=entry['read'],entry['parse'],entry['bound'];retained={}
        def retain(path,wanted=None):
            raw=bound({'path':str(path),'sha256':wanted}) if wanted else read(path)
            retained[str(path)]=sha(raw);return parse(raw)
        approval=retain(CONTEXT/'human-approval-binding.json')
        require(approval['approvalRef']=='OUF_PROVIDER_AUDITED_RECOVERY_APPROVED_20261009T191942_CEST_R7'
            and approval['sourceClosureHash']==CLOSURE,'EXACT_CONSUMED_R7_BINDING_REQUIRED')
        denial=retain(CONTEXT/'operator-denial.json',OPERATOR_DENIAL)
        require(denial['doNotRerunApply'] is True and denial['evidenceDirectory']==str(OUTPUT),'EXACT_R7_DENIAL_REQUIRED')
        cfg=retain(CONTEXT/'execution-configuration.json',approval['configurationHash'])
        require(cfg['outputRoot']==str(OUTPUT),'EXACT_R7_OUTPUT_REQUIRED')
        package=Path(approval['sourcePackage'])
        require(package.parent==BASE and package.name.startswith('semantic-provider-v2-transaction-source-audited-'),'EXACT_R7_SOURCE_PACKAGE_REQUIRED')
        path=package/'provider_transaction_intake.py';raw=bound({'path':str(path),'sha256':R7_ENTRY})
        actual={'__name__':'r7_sealed_sources','__file__':str(path)};exec(compile(raw,str(path),'exec'),actual)
        sources,observer=actual['load'](package)
        require(sha(encoded({**{n:sha(v) for n,v in sources.items()},'frame-observer.py':sha(observer)}))==CLOSURE,'R7_SOURCE_CLOSURE_DRIFT')
        from tools.semantic_provider_node_observation import rootfs_seal
        from transaction_guard_observation import executable_binding,observe_locked
        from authenticate_provider_transaction import TARGETS
        switched=retain(OUTPUT/'runtime-switch-receipt.json');wrapper=read('/usr/local/sbin/ouf-semantic-admitted-v2',True)
        require(sha(wrapper)==switched['installedWrapperHash'],'CURRENT_R7_WRAPPER_DRIFT')
        report['installedWrapperHash']=sha(wrapper)
        for relative,item in denial['retainedPhaseDiagnostics'].items():
            role,name=relative.split('/',1);retain(OUTPUT/'registry'/ROLE_IDS[role]/name,item['sha256'])
        docker=cfg['commandBindings']['docker'];executable_binding(docker)
        def command(binding,args,limit=131072):
            identity=executable_binding(binding)
            with tempfile.TemporaryFile() as output:
                result=subprocess.run([binding['path'],*args],stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.DEVNULL,
                    timeout=15,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
                output.seek(0);raw=output.read(limit+1)
            require(result.returncode==0 and len(raw)<=limit,'BOUNDED_DIAGNOSTIC_COMMAND_FAILED')
            require(executable_binding(binding)==identity,'DIAGNOSTIC_EXECUTABLE_CHANGED');return raw
        def inspect(cid):
            fmt='{"id":{{json .Id}},"image":{{json .Image}},"runtime":{{json .HostConfig.Runtime}},"state":{{json .State}}}'
            raw=command(docker,['--host','unix:///var/run/docker.sock','--config',str(OUTPUT/'activation-docker-cli'),
                'inspect','--type','container','--format',fmt,cid],16384)
            value=parse(raw);s=value['state']
            expected=next(v for v in TARGETS.values() if v['containerId']==cid)
            require(value['id']==cid and value['image']==expected['imageManifestDigest']
                and value['runtime']=='ouf-semantic-admitted-v2' and s['Status']=='created'
                and s['Running'] is False and s['Pid']==0 and s['StartedAt'].startswith('0001-01-01'),
                'EXACT_NEVER_STARTED_CANDIDATE_REQUIRED')
            return value
        def guard():
            pointer=parse(bound(cfg['guardPointerBinding']));binding={'path':pointer['receiptFile'],'sha256':pointer['receiptHash']}
            owner=parse(bound({'path':str(Path(binding['path']).parent/'coordinated-configuration.json'),'sha256':OWNER}))
            fd=os.open(owner['commonLockFile'],os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
            try:
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                return observe_locked(fd,binding,OWNER,{t['containerId']:{'imageManifestDigest':t['imageManifestDigest'],
                    'runtimeName':'ouf-semantic-admitted-v2'} for t in TARGETS.values()},cfg['commandBindings'])
            finally:os.close(fd)
        PHASE='READ_R7_CURRENT_GUARD_AND_TERMINAL_TASKS'
        observed_guard=guard();report['nativeEmptyGuardObservation']=observed_guard
        require(observed_guard['candidateStateHashes']=={cid:v['stateHash'] for cid,v in denial['candidateObservations'].items()},'R7_CURRENT_STATE_DRIFT')
        ctr={'path':'/usr/bin/ctr','sha256':'8bb9bc5014e0f7623603d6a0dc1f7fedfe5b5a9ea5e265cc00dfbbae23ee984e'}
        shims=process_metadata(read)
        report['terminalTaskReview']={cid:{'shims':rows} for cid,rows in shims.items()}
        report['containerdEndpointSource']='LIVE_DOCKER_EXPLICIT_ARGV'
        prefix=['--address','/run/containerd/containerd.sock','--namespace','moby']
        tasks=task_rows(command(ctr,[*prefix,'tasks','list']));report['containerdRequestedTasks']=tasks
        report['allRecordedTaskPidsAbsent']=all(not t['taskPidPresent'] for t in tasks.values())
        require(all(not t['taskPidPresent'] and (not t['taskPresent'] or t['status']=='STOPPED') for t in tasks.values()),'TERMINAL_TASK_STATE_REQUIRED_FOR_ROOTFS_READ')
        before={cid:inspect(cid) for cid in ROLE_IDS.values()}
        DIAGNOSTIC=Path(tempfile.mkdtemp(prefix='semantic-r7-rootfs-read-',dir=BASE));DIAGNOSTIC.chmod(0o700)
        report['evidenceDirectory']=str(DIAGNOSTIC)
        print('OUF_R7_ROOTFS_DIAGNOSTIC_DIRECTORY='+str(DIAGNOSTIC),flush=True)
        roots=[]
        for role,cid in ROLE_IDS.items():
            PHASE='COMPARE_'+role.upper()+'_ROOTFS_WITH_RETAINED_IMAGE'
            print('OUF_R7_ROOTFS_READ_PHASE='+PHASE,flush=True)
            root=OUTPUT/'registry'/cid
            journal=retain(root/'adapter.json',denial['candidateObservations'][cid]['adapterJournalHash']);roots.append(journal['runtimeRoot'])
            for name in ('broker-state.json','deployment.json'):retain(root/name)
            bundle=retain(root/'bundle/config.json');policy=retain(Path(cfg['recordsByRole'][role]['framePolicy']['path']),cfg['recordsByRole'][role]['framePolicy']['sha256'])
            require(bundle==policy['expectedOci'],'R7_RETAINED_COMPLETE_OCI_DRIFT')
            node=retain(root/'attestation-producer.json');authorization=retain(Path(node['liveAcceptanceAuthorizationPath']))
            require(authorization['rootfsSeal']==TARGETS[role]['runtimeSeal'],'R7_ACCEPTED_ROOTFS_BINDING_DRIFT')
            metadata=command(ctr,[*prefix,'containers','info',cid]);meta=parse(metadata)
            require(meta['ID']==cid,'EXACT_CONTAINERD_METADATA_REQUIRED')
            tasks[cid]['containerMetadataHash']=sha(metadata)
            tasks[cid]['runtimeKind']=meta.get('Runtime',{}).get('Name')
            actual_root=Path(bundle['root']['path'])
            require(actual_root==Path('/var/lib/docker/rootfs/overlayfs')/cid,'EXACT_RETAINED_ROOTFS_PATH_REQUIRED')
            receipt=retain(OFFLINE/role/'expected-docker-rootfs.json')
            require(receipt['rootfsSeal']['sha256']==OFFLINE_SEALS[role]
                and receipt['manifestDigest']==TARGETS[role]['imageManifestDigest']
                and receipt['configDigest']==TARGETS[role]['imageConfigDigest'],'ORIGINAL_OFFLINE_IMAGE_BINDING_DRIFT')
            original,left=entries(rootfs_seal,OFFLINE/role/'bundle/rootfs',receipt['rootfsLimits'])
            require(original==receipt['rootfsSeal'],'ORIGINAL_OFFLINE_IMAGE_CHANGED')
            expected_image=image_view(left,True)
            require(image_digest(expected_image)==IMAGE_SEALS[role],'ORIGINAL_IMAGE_EQUIVALENCE_BASELINE_DRIFT')
            with stopped_view(docker['path'],OUTPUT/'activation-docker-cli',cid,actual_root,report) as view:
                observed,right=entries(rootfs_seal,view,receipt['rootfsLimits'])
            require(inspect(cid)==before[cid],'CANDIDATE_CHANGED_DURING_ROOTFS_READ')
            actual_image=image_view(right)
            value={'containerId':cid,'acceptedV1Seal':authorization['rootfsSeal'],'currentV1Seal':observed,
                'currentV1SealMatchesAccepted':observed==authorization['rootfsSeal'],
                'currentObservationIsHistoricalFailedObservation':False,
                'currentImageSeal':image_digest(actual_image),'priorExpectedImageSeal':IMAGE_SEALS[role],
                'imageSemanticsMatchRetainedBaseline':actual_image==expected_image,
                'strictOfflineDifferences':differences(left,right,bundle),
                'imageDifferences':differences(expected_image,actual_image,bundle),
                'originalV1SealsRetained':True,'acceptanceGranted':False}
            report['roles'][role]=value
            save(DIAGNOSTIC/(role+'-entry-comparison.json'),{'expectedOfflineEntries':left,'currentEntries':right,'summary':value})
        PHASE='VERIFY_PRESERVATION_AND_CURRENT_NATIVE_ABSENCE'
        require(len(set(roots))==1 and sha(roots[0].encode())==RUNTIME_ROOT_HASH,'RETAINED_RUNTIME_ROOT_DRIFT')
        report['runtimeRootHash']=RUNTIME_ROOT_HASH
        template=retain(Path(cfg['recordsByRole']['adapter']['preparerTemplate']['path']),cfg['recordsByRole']['adapter']['preparerTemplate']['sha256'])
        native=parse(command(template['candidate']['runtimeBinding'],['--root',roots[0],'list','--format','json']))
        if native is None:native=[]
        require(type(native) is list,'RUNC_INVENTORY_UNPROVEN')
        report['requestedNativeEntries']={cid:[{'status':v.get('status'),'pid':v.get('pid')} for v in native if v.get('id')==cid] for cid in ROLE_IDS.values()}
        after=task_rows(command(ctr,[*prefix,'tasks','list']))
        require(all(all(row[k]==after[cid][k] for k in after[cid]) for cid,row in tasks.items()),'TASKS_CHANGED_DURING_READ')
        for cid,row in tasks.items():require(sha(command(ctr,[*prefix,'containers','info',cid]))==row['containerMetadataHash'],'CONTAINER_METADATA_CHANGED_DURING_READ')
        require(process_metadata(read)==shims,'SHIM_GENERATIONS_CHANGED_DURING_READ')
        require(guard()==observed_guard,'NATIVE_GUARD_CHANGED_DURING_READ')
        require(read('/usr/local/sbin/ouf-semantic-admitted-v2',True)==wrapper,'WRAPPER_CHANGED_DURING_READ')
        require(all(sha(read(p))==h for p,h in retained.items()),'RETAINED_EVIDENCE_CHANGED_DURING_READ')
        report.update(status='R7_CURRENT_ROOTFS_DIFFERENCES_CAPTURED',phase=PHASE,retainedEvidencePreserved=True)
        save(DIAGNOSTIC/'retained-input-hashes.json',retained);save(DIAGNOSTIC/'diagnosis.json',report)
    except Exception as error:
        report.update(status='R7_ROOTFS_DIAGNOSIS_INCOMPLETE',phase=PHASE,reason=symbolic(error),errorType=type(error).__name__,
            exceptionPoints=[{'file':Path(t.filename).name,'function':t.name,'line':t.lineno} for t in traceback.extract_tb(error.__traceback__)[-4:]])
        if isinstance(error,OSError):report['errno']=error.errno
        if DIAGNOSTIC:
            try:save(DIAGNOSTIC/'diagnosis-incomplete.json',report)
            except Exception:report['diagnosisSaved']=False
    print('OUF_R7_ROOTFS_READ_ONLY='+json.dumps(report,sort_keys=True),flush=True)
    return 0 if report['status']=='R7_CURRENT_ROOTFS_DIFFERENCES_CAPTURED' else 1


if __name__=='__main__':sys.exit(main())
