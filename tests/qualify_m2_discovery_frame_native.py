"""Disposable Docker29 native frame/files/configtree test; no owner admission.

The runtime image and private inputs are synthetic. Java never executes. The
independent committed Engine baseline supplies expected OCI, not the live OCI.
"""
import hashlib,json,os,shutil,subprocess,sys,tempfile,time,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),
    str(ROOT/'tools/semantic_frame_compiler'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from test_m2_discovery_native_profile import fixture
from tools.m2_discovery_installation_profile.native_profile import DiscoveryProfile,FILE_ROLES,digest,ENTRY,JAVA
from tools.m2_discovery_installation_profile.frame_inputs import compile_inputs,ENGINE
from tools.m2_discovery_installation_profile.frame import compile_policy
from projected_frame_observation import ProjectedFrameObservation
from configtree_mount_observation import ConfigtreeMountObservation
from file_only_node_owner import ObservationBudget
from tools.semantic_provider_deployment_authentication import attributes

def run(*args):
    return subprocess.check_output(args,stderr=subprocess.PIPE,timeout=120).decode().strip()

def main():
    assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
    info=json.loads(run('docker','info','--format','{{json .}}'))
    assert info['ServerVersion']=='29.8.1' and info['Driver']=='overlayfs' and info['CgroupDriver']=='systemd'
    task=Path(tempfile.mkdtemp(prefix='discovery-native-',dir='/var/lib'));task.chmod(0o700)
    cid=None; network='ouf-disc-'+uuid.uuid4().hex[:12];tag='ouf-discovery-frame-fixture:'+uuid.uuid4().hex
    try:
        run('docker','pull','alpine:3.22');base=json.loads(run('docker','image','inspect','alpine:3.22'))[0]['RepoDigests']
        assert len(base)==1 and '@sha256:' in base[0]
        (task/'Dockerfile').write_text('FROM '+base[0]+'\nRUN addgroup -S -g 10001 ouf && adduser -S -D -H -u 10001 -G ouf ouf\nUSER 10001:10001\nWORKDIR /app\n')
        run('docker','build','-t',tag,str(task));image=json.loads(run('docker','image','inspect',tag))[0]['Id']
        network_id=run('docker','network','create',network)
        request,selection,*_=fixture();request['Image']=image
        request['HostConfig']['NetworkMode']=network
        request['NetworkingConfig']={'EndpointsConfig':{network:{'NetworkID':network_id}}}
        for role,f in selection['files'].items():
            p=task/role;p.write_bytes(('synthetic-'+role).encode());os.chown(p,f['uid'],f['gid']);p.chmod(f['mode'])
            f.update(source=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest(),metadataHash=digest(attributes(p.lstat())))
        tree=selection['configtree'];db=task/'database';db.mkdir(mode=0o500);os.chown(db,10001,10001)
        password=db/tree['fileName'];password.write_bytes(b'CI_SYNTHETIC_NOT_A_TARGET_PASSWORD');os.chown(password,10001,10001);password.chmod(0o400)
        tree.update(source=str(db),sha256=hashlib.sha256(password.read_bytes()).hexdigest())
        token=selection['renewable_token'];td=task/'policy';td.mkdir(mode=0o750);os.chown(td,0,10001)
        (td/token['fileName']).write_text('CI_NO_RUNTIME_AUTHORITY');os.chown(td/token['fileName'],0,10001);(td/token['fileName']).chmod(0o440)
        token.update(source=str(td),directoryDevice=td.stat().st_dev,directoryInode=td.stat().st_ino)
        binds=[{k:selection['files'][role][k] for k in ('source','target','readOnly')} for role in FILE_ROLES]
        binds += [{k:tree[k] for k in ('source','target','readOnly')},{'source':token['source'],'target':token['target'],'readOnly':True}]
        request['HostConfig']['Mounts']=[{'Type':'bind','Source':b['source'],'Target':b['target'],'ReadOnly':True} for b in binds]
        profile=DiscoveryProfile(request,**selection)
        args=['docker','create','--network',network,'--restart','no','--user','10001:10001','--cap-drop','ALL',
            '--security-opt','no-new-privileges:true','--memory','2147483648','--memory-swap','2147483648',
            '--cpus','2','--pids-limit','512','--workdir','/app','--entrypoint','/bin/sh']
        for value in request['Env']:args+=['--env',value]
        for b in binds:args+=['--mount','type=bind,source='+b['source']+',target='+b['target']+',readonly']
        cid=run(*args,image,*ENTRY[1:],*JAVA);run('docker','start',cid);run('docker','pause',cid)
        actual=json.loads(run('docker','inspect',cid))[0];pid=actual['State']['Pid']
        assert actual['State']['Paused'] and actual['RestartCount']==0 and actual['Image']==image
        cmdline=(Path('/proc')/str(pid)/'cmdline').read_bytes();assert cmdline==b'\0'.join(x.encode() for x in ENTRY+JAVA)+b'\0'
        state=json.loads(run('runc','--root','/run/docker/runtime-runc/moby','state',cid))
        parents=('/run/docker/containerd/daemon/io.containerd.runtime.v2.task/moby','/run/containerd/io.containerd.runtime.v2.task/moby')
        matches=[p for p in parents if state['bundle']==p+'/'+cid];assert len(matches)==1
        storage=info['DockerRootDir'];assert storage=='/var/lib/ouf-docker-29'
        context={'schema':'ouf.semantic-docker-frame-context.v1','containerId':cid,'bundleParent':matches[0],
            'metadataParent':storage+'/containers','networkNamespaceParent':'/run/docker/netns',
            'networkNamespaceName':None,'cgroupDriver':'systemd','storageParent':storage,'rootfsPath':storage+'/rootfs/overlayfs/'+cid}
        baseline=(ROOT/'tools/semantic_frame_compiler/containerd-overlayfs-southbound.json').read_bytes()
        template,launch=compile_inputs(baseline,request,execution_profile=profile,engine_profile=ENGINE)
        policy=compile_policy(template,launch,context,execution_profile=profile)
        owner=task/'owner.py';owner.write_bytes((ROOT/'tools/semantic_frame_compiler/frame-observer.py').read_bytes());owner.chmod(0o600)
        policy_path=task/'policy.json';policy_path.write_text(json.dumps(policy));policy_path.chmod(0o600)
        cfg={name:{'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for name,p in [('source',owner),('configuration',policy_path)]}
        cfg['bundleParents']=list(parents);budget=ObservationBudget(120);observer=ProjectedFrameObservation(cfg,budget)
        modules,schema=observer.owner(owner.read_bytes());bundle=json.loads(observer.bundle(Path(state['bundle'])/'config.json'))
        (task/'expected-oci.json').write_text(json.dumps(policy['expectedOci'],indent=2));(task/'actual-oci.json').write_text(json.dumps(bundle,indent=2))
        modules['review_semantic_oci_policy'].configured_profile(bundle,policy['expectedOci'],policy['manifest'],policy['startup'],policy['approvedHooks'],schema)
        current=modules['observe_semantic_mount_view'].generation(pid,budget)
        modules['observe_semantic_creation_frame'].source_mount_frame(pid,current,bundle,policy['sources'],budget)
        generation={'pid':pid,'startTicks':current['startTicks'],'namespaceInode':current['networkNamespaceInode']}
        ConfigtreeMountObservation(tree,budget).observe(generation)
        assert json.loads(run('docker','inspect',cid))[0]['State']==actual['State']
        assert (Path('/proc')/str(pid)/'cmdline').read_bytes()==cmdline
        result={'schema':'ouf.m2-discovery-native-frame-ci.v1','engine':ENGINE,'fullIndependentOciMatched':True,
            'fiveNativeReadonlyFilesObserved':True,'databaseConfigtreeNativeObserved':True,'javaStarted':False,
            'syntheticImageAndPrivateInputs':True,'tokenOwnerAdmissionProven':False,'providerTlsOrIamProven':False,
            'signaturesIssued':0,'targetAcceptance':False,'applicationE2EProven':False}
        (task/'result.json').write_text(json.dumps(result,indent=2));print(json.dumps(result))
    finally:
        if cid:subprocess.run(['docker','rm','--force',cid],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
        subprocess.run(['docker','network','rm',network],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
        print('CI_EVIDENCE_DIRECTORY='+str(task))

if __name__=='__main__':main()
