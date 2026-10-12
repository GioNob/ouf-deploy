"""Exact original signed V11 image: pre-Java gate and same-PID Java release.
No real DB, provider, transport authority, target or CSV acceptance.
"""
import hashlib,importlib.util,json,os,shutil,stat,subprocess,sys,tempfile,time,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover')]
sys.path.insert(0,str(ROOT/'tools/semantic_cohort_admission/cohort-draft'))
from engine_creation import Engine
from creation_adapter import CreationAdapter
from gated_stage_adapter import GatedStageAdapter
from gated_release_adapter import GatedReleaseAdapter
from gated_process_observation import GatedProcessObservation
from gated_creation_plan import compile_gate,PROFILE
from native_evidence_store import NativeEvidenceStore
from executor_composition_fixture import compose
from cutover_executor import CutoverDenied
from transition_journal import digest
from paused_workload_binding import PausedWorkloadBinding
from tools.semantic_provider_node_observation import rootfs_seal
from tools.semantic_provider_deployment_authentication import VerificationBudget,decode
from tools.semantic_provider_preexec_native import NativeBackend
from tools.semantic_provider_deployment_admission import application_hash
import image_custody as custody
import image_manifest_identity as identity

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
verify=load('gated_v11_package','scripts/verify-durable-v11-package.py')

def command(args,timeout=120):
    p=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
    if p.returncode or len(p.stdout)>2097152:raise ValueError('GATED_V11_NATIVE_OPERATION_UNPROVEN')
    return p.stdout

def file_hash(path,limit=536870912):
    h=hashlib.sha256();size=0
    with Path(path).open('rb') as stream:
        while block:=stream.read(1048576):
            size+=len(block)
            if size>limit:raise ValueError('GATED_V11_FILE_UNBOUNDED')
            h.update(block)
    return h.hexdigest()

def paused_filesystem(e,engine,store,socket,request):
    """Native read-only seal; never construct an approval from observed OCI.

    No independent target policy is supplied by this fixture. This qualifies
    streaming/stability on original image bytes, not owner acceptance.
    """
    row=e.t.read()
    with e.t.invocation():
        e.t.begin('ATTEST_NEW_OCI_PEER',e.intent_hashes['ATTEST_NEW_OCI_PEER'],e.authority_hash,row['version'])
    binding=PausedWorkloadBinding(engine,e.t,request,store);before=binding.observe()
    cid=before['runtimeBinding']['containerId'];pid=before['runtimeBinding']['pid']
    binary=str(Path(shutil.which('runc')).resolve());state=None
    roots=(socket.parent/'exec/runtime-runc/moby',Path('/run/docker/runtime-runc/moby'),Path('/run/containerd/runc/moby'))
    for runtime_root in roots:
        result=subprocess.run([binary,'--root',str(runtime_root),'state',cid],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5)
        if result.returncode==0:
            state=decode(result.stdout,16384);break
    if state is None:raise ValueError('ORIGINAL_V11_PAUSED_RUNC_STATE_UNPROVEN')
    binding.verify_runc_state(state,before)
    bundle=Path(state['bundle'])
    # The isolated Engine may use the host containerd task parent. Never widen
    # to /run: only this exact random fixture CID under closed task parents.
    task_parents=(socket.parent/'exec/docker/containerd/daemon/io.containerd.runtime.v2.task/moby',
                  Path('/run/docker/containerd/daemon/io.containerd.runtime.v2.task/moby'),
                  Path('/run/containerd/io.containerd.runtime.v2.task/moby'))
    assert bundle.is_absolute() and bundle.name==cid and (bundle.is_relative_to(socket.parent) or bundle.parent in task_parents), 'EXACT_FIXTURE_CONTAINERD_BUNDLE_PARENT_REQUIRED'
    config=bundle/'config.json';raw=config.read_bytes();oci=decode(raw,131072)
    root=Path(oci['root']['path']);root=root if root.is_absolute() else bundle/root
    assert '..' not in root.parts and (root==bundle/'rootfs' or root.is_relative_to(socket.parent)), 'EXACT_FIXTURE_ROOTFS_PARENT_REQUIRED'
    generation=NativeBackend.generation(None,pid)
    limits={'maxEntries':100000,'maxBytes':8589934592,'maxDepth':64}
    first=rootfs_seal(root,limits,VerificationBudget(18))
    second=rootfs_seal(root,limits,VerificationBudget(18))
    assert first==second and first['entries']>100 and first['bytes']>1000000
    assert config.read_bytes()==raw and NativeBackend.generation(None,pid)==generation
    assert binding.observe()==before
    return {'rootfsSeal':first,'observedCompleteOciHash':application_hash(oci),'stableDoubleRootfsSeal':True,
            'actualPausedRuncContract':True,'independentOciPolicyAccepted':False,'reciprocalPeersVerified':False}

class Fixture:
    def __init__(self):self.cleanups=[]
    def addCleanup(self,fn):self.cleanups.append(fn)
    def close(self):
        for fn in reversed(self.cleanups):fn()

def main():
    assert os.geteuid()==0
    spec=verify.SPECS['semantic'];verified=verify.verify(ROOT/'semantic.zip','semantic');fixture=Fixture()
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory);root.chmod(0o700)
        with zipfile.ZipFile(ROOT/'semantic.zip') as archive:
            for name in ('image.docker.tar','source.tar','source-inventory.json','application.jar','package-record.json','migration-continuity.json','trivy-image.json','Dockerfile.resolved','provenance.json'):
                rows=[i for i in archive.infolist() if Path(i.filename).name==name];assert len(rows)==1
                with archive.open(rows[0]) as src,(root/name).open('xb') as dst:shutil.copyfileobj(src,dst,1048576)
        for name in ('image.docker.tar','source.tar','source-inventory.json','application.jar','package-record.json','migration-continuity.json','trivy-image.json','Dockerfile.resolved'):
            command(['gh','attestation','verify',str(root/name),'--repo','GioNob/ouf-semantic-registry','--signer-workflow','GioNob/ouf-semantic-registry/.github/workflows/discovery-durable-candidate.yml','--source-digest','3ec99277b8383e496913b9fd3bb05c877825abf5','--source-ref','refs/heads/codex/discovery-durable-resilience-20261011','--deny-self-hosted-runners','--bundle',str(root/'provenance.json'),'--format','json'])
        expected=verified['memberSha256']['image.docker.tar']
        with (root/'image.docker.tar').open('rb') as stream:audit=custody.archive(stream,expected,spec['image'],spec['source'])
        with tempfile.TemporaryFile() as envelope:
            with (root/'image.docker.tar').open('rb') as src:record=custody.tagless_archive(src,envelope,audit)
            envelope.seek(0);audit=custody.archive(envelope,record['derivedArchiveSha256'],spec['image'],spec['source']);descriptor=identity.descriptor(envelope,audit)
            assert descriptor['digest']=='sha256:bd48ab35db0441b1f4f48422e7190adaff176a61cddde5f981d93e496ad4b24a'
            envelope.seek(0);socket=Path(os.environ['OUF_CUSTODY_SOCKET']);s=socket.stat();engine=Engine(str(socket),(s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)))
            p=subprocess.run(['docker','--host','unix://'+str(socket),'image','load'],stdin=envelope,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120);assert p.returncode==0
        status,image=engine.request('GET','/v1.48/images/'+descriptor['digest']+'/json?manifests=true');assert status==200
        image_proof=identity.loaded(audit,descriptor,image)
        parent={'Image':descriptor['digest'],'User':'10001:10001','Env':list(audit['imageConfig'].get('Env') or [])+['OUF_SEM_DB_URL=jdbc:postgresql://127.0.0.1:1/fixture_only','OUF_SEM_DB_USER=fixture','OUF_SEM_DB_PASSWORD=fixture','OUF_DISCOVERY_WORKER_ENABLED=false','OUF_SCHEMA_GOV_ENABLED=false'],
                'HostConfig':{'Runtime':'runc','Privileged':False,'NetworkMode':'none','RestartPolicy':{'Name':'no','MaximumRetryCount':0},'Memory':2147483648,'MemorySwap':2147483648,'NanoCpus':2000000000,'PidsLimit':512}}
        request,proposal=compile_gate(parent,digest(parent),{'config':audit['imageConfig']});process=GatedProcessObservation(request)
        before=root/'before';before.mkdir(mode=0o700);before_store=NativeEvidenceStore(before)
        intent={'creationRequestHash':digest(request),'priorEvidencePhase':'STAGE_PAUSED_REPLACEMENT','preApplicationGateProfile':PROFILE}
        e,store=compose(fixture,'START_REPLACEMENT',intent,lambda t,s:GatedReleaseAdapter(engine,t,request,s,before_store,process,lambda point:None),additional={
            'CREATE_REPLACEMENT':(request,lambda t,s:CreationAdapter(engine,t,request,s)),
            'STAGE_PAUSED_REPLACEMENT':({'creationRequestHash':digest(request),'priorEvidencePhase':'CREATE_REPLACEMENT'},lambda t,s:GatedStageAdapter(engine,t,request,s,process,lambda point:None))},creation_request=request)
        cid=None
        try:
            e.run(6);native=engine.inspect(e.t);cid=native['Id'];pid=native['State']['Pid'];gate=process.observe(pid)
            assert gate['processKind']=='GATE_WAITING' and native['Image']==descriptor['digest']
            jar_before=file_hash('/proc/'+str(pid)+'/root/app/application.jar');assert jar_before==verified['memberSha256']['application.jar']
            java_before=file_hash('/proc/'+str(pid)+'/root/opt/java/openjdk/bin/java');assert process.observe(pid)==gate
            filesystem=paused_filesystem(e,engine,store,socket,request)
            deadline=time.monotonic()+5
            while True:
                try:e.run(11);break
                except CutoverDenied:
                    assert e.t.read()['state']=='IN_FLIGHT' and time.monotonic()<deadline
                    time.sleep(.05)
            java=process.observe(pid);assert java['processKind']=='APPLICATION_RUNNING' and java['generation']==gate['generation']
            assert file_hash('/proc/'+str(pid)+'/exe')==java_before
            receipt={'schema':'ouf.native-gated-original-v11-execution.v1','status':'ORIGINAL_V11_WAIT_GATE_AND_SAME_PID_JAVA_EXEC_OBSERVED','sourceCommit':spec['source'],'originalZipSha256':spec['zipSha256'],'nativeManifestImageId':descriptor['digest'],'signedSubjectsVerified':8,'layersVerified':len(audit['layers']),'actualApplicationJarMatchesPublishedBytes':True,'actualJavaLauncherUnchanged':True,'javaNotExecutedBeforeRelease':True,'actualSameGenerationJavaExec':True,'capabilitiesEmpty':True,'noNewPrivileges':True,'imageRebuilt':False,'fixtureImageImports':1,'targetImageImports':0,'authorityAndOtherPhasesSynthetic':True,'databaseMigrationTested':False,'completeOciRootfsPeerAcceptanceProven':False,'providerCalls':0,'applicationReadyProven':False,'targetApplied':False,'notReleaseAcceptance':True}
            receipt.update(filesystem)
            print('OUF_GATED_ORIGINAL_V11='+json.dumps(receipt,sort_keys=True));(ROOT/'native-gated-v11-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
        finally:
            if cid is not None:engine.request('DELETE','/v1.44/containers/'+cid+'?force=true')
            fixture.close()

if __name__=='__main__':main()
